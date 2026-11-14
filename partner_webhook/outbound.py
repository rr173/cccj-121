"""下游 HTTP 发送工人（outbox → 合作方接收地址）。

与在线收件解耦：直接消费现有 ``outbox``，**不重新验证入站签名**，不读取
正文索引/档案加工库，也不转发入站签名或密钥。只使用 ``raw_bodies`` 的原始
字节与 ``accepted_events`` 业务列。

语义要点
--------
* 按合作方分别排队，队首 = 该合作方最小 ``outbox.id`` 且尚未送达的事件；
  队首在退避/被占用/永久失败时，后续事件不得超车，其他合作方不受影响。
* 每个合作方的接收地址一经登记不可原地更换。
* 领取 = 持久的一次性 lease（短事务落库，``BEGIN IMMEDIATE``），网络请求
  期间不留任何数据库写锁。占用到期后其他工人可接手；旧工人的迟到回执
  只追加 ``late_*`` 记录，绝不覆盖新工人的结果或重复完成。
* 仅 HTTP 2xx 且 UTF-8 JSON 对象回执的 ``delivery_key`` 与 ``body_sha256``
  完全匹配才算送达；此判定是唯一会写 ``outbox.delivered`` 的路径。
* 只承诺「至少一次」：过期请求无法撤回，接收方可能收到重复，用稳定的
  ``delivery_key`` 去重。跨网络不宣称恰好一次。
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from .storage import connect

# ---- 请求头 -------------------------------------------------------------
HEADER_PARTNER = "X-Partner-Id"
HEADER_EVENT_ID = "X-Event-Id"
HEADER_SOURCE_SEQ = "X-Source-Seq"
HEADER_BODY_SHA256 = "X-Body-Sha256"
HEADER_DELIVERY_KEY = "X-Delivery-Key"
DELIVERY_HEADERS = (
    HEADER_PARTNER, HEADER_EVENT_ID, HEADER_SOURCE_SEQ,
    HEADER_BODY_SHA256, HEADER_DELIVERY_KEY,
)

# ---- 状态 ---------------------------------------------------------------
STATUS_PENDING = "pending"
STATUS_IN_FLIGHT = "in_flight"
STATUS_RETRY_WAIT = "retry_wait"
STATUS_PERMANENT_FAILURE = "permanent_failure"
STATUS_DELIVERED = "delivered"

OUTCOME_SUCCESS = "success"
OUTCOME_RETRYABLE = "retryable_failure"
OUTCOME_PERMANENT = "permanent_failure"
OUTCOME_LOCAL_ERROR = "local_error"
OUTCOME_LEASE_EXPIRED = "lease_expired_takeover"

DEFAULT_LEASE_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_ATTEMPTS = 20
MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_BACKOFF_CAP = 60


class DeliveryError(Exception):
    """可预期、可向操作者展示的错误（配置/参数/未登记等）。"""


# ------------------------------------------------------------------------- #
# 纯函数：可独立测试的投递约定
# ------------------------------------------------------------------------- #
def delivery_key(partner_id: str, event_id: str, body_sha256: str) -> str:
    """稳定投递键：同合作方、同事件、同摘要恒等；跨合作方同号事件不同。

    用长度前缀避免拼接歧义（``a|b`` 与 ``a|b`` 等边界情况）。
    """
    parts = (partner_id, event_id, body_sha256.lower())
    material = "\x1f".join(f"{len(p)}:{p}" for p in parts)
    return "dk1_" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def header_value(value: str) -> str:
    """HTTP 头值净化：禁止 CR/LF/控制字符混入（单值只允许可打印 ASCII）。

    另外拒绝首尾空白：HTTP 解析器会裁掉它们，值将无法原样往返。
    """
    if not isinstance(value, str):
        raise DeliveryError("头值必须是字符串")
    if not value:
        raise DeliveryError("头值不能为空（身份字段必须可核对）")
    if "\r" in value or "\n" in value:
        raise DeliveryError("头值包含换行，拒绝拼入请求头")
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            raise DeliveryError(f"头值包含控制字符 0x{ord(ch):02x}")
    # 非 ASCII 会破坏等值往返：直接拒绝而不是静默改写
    for ch in value:
        if ord(ch) > 0x7e:
            raise DeliveryError("头值包含非 ASCII 字符，无法无歧义往返")
    if value != value.strip(" "):
        raise DeliveryError("头值首尾有空白，传输时会被裁剪，无法无歧义往返")
    return value


def build_headers(partner_id: str, event_id: str, source_seq: int,
                  body_sha256: str, key: str) -> dict[str, str]:
    """构造下游请求头。所有身份字段都经 :func:`header_value` 校验。"""
    return {
        HEADER_PARTNER: header_value(partner_id),
        HEADER_EVENT_ID: header_value(event_id),
        HEADER_SOURCE_SEQ: header_value(str(int(source_seq))),
        HEADER_BODY_SHA256: header_value(body_sha256.lower()),
        HEADER_DELIVERY_KEY: header_value(key),
        "Content-Type": "application/octet-stream",
        "Content-Length": "0",  # 实际发送时替换为真实长度
    }


def backoff_seconds(attempt_no: int, retry_after: str | None = None) -> int:
    """第 n 次失败后的等待秒数（n 从 1 计）：min(60, 2**(n-1))。

    Retry-After 只有「仅含十进制数字」才被采纳，并取较大值；其他形式忽略。
    """
    if attempt_no < 1:
        raise ValueError("attempt_no 从 1 计")
    if attempt_no > 64:  # 防守极端轮次，避免整数爆炸
        default = DEFAULT_BACKOFF_CAP
    else:
        default = min(DEFAULT_BACKOFF_CAP, 1 << (attempt_no - 1))
    if retry_after is not None and retry_after != "" and retry_after.isascii() \
            and retry_after.isdigit():
        # isdigit() 对部分 Unicode 数字为真；isascii 已排他
        return max(default, int(retry_after, 10))
    return default


def parse_receipt(body: bytes) -> dict[str, Any]:
    """严格解析回执：UTF-8、无 BOM、JSON 对象、无重复键。

    返回解析后的对象；任何不合规都抛 ValueError（调用方视为无效回执）。
    额外字段允许存在（调用方忽略）。
    """
    if body is None:
        raise ValueError("empty_response")
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("response_too_large")
    if not body:
        raise ValueError("empty_response")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"response_not_utf8: {exc}") from None

    def pairs_hook(items):
        seen = set()
        for name, value in items:
            if name in seen:
                raise ValueError(f"duplicate_receipt_field: {name}")
            seen.add(name)
        return dict(items)

    try:
        obj = json.loads(text, object_pairs_hook=pairs_hook)
    except json.JSONDecodeError as exc:
        raise ValueError("response_not_json") from None
    except ValueError:
        # 重复键等由 pairs_hook 抛出的 ValueError 原样上抛
        raise
    if not isinstance(obj, dict):
        raise ValueError("response_not_object")
    return obj


def validate_receipt(body: bytes, expected_key: str,
                     expected_sha: str) -> tuple[bool, str | None]:
    """检查回执是否确认本次投递。返回 (是否有效, 失败原因)。

    仅当 ``delivery_key`` 与 ``body_sha256`` 都恰好等于本次请求值时有效。
    """
    try:
        obj = parse_receipt(body)
    except ValueError as exc:
        return False, str(exc)
    for name, expected in (("delivery_key", expected_key),
                           ("body_sha256", expected_sha.lower())):
        if name not in obj:
            return False, f"receipt_field_missing: {name}"
        if not isinstance(obj[name], str):
            return False, f"receipt_field_not_string: {name}"
        if obj[name] != expected:
            return False, f"receipt_field_mismatch: {name}"
    return True, None


# ------------------------------------------------------------------------- #
# HTTP 发送（单次网络尝试）
# ------------------------------------------------------------------------- #
@dataclass
class SendOutcome:
    """一次网络尝试的结果，直接对应尝试表字段。"""

    outcome: str
    http_status: int | None = None
    failure_reason: str | None = None
    retry_after: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def send_once(url: str, headers: dict[str, str], body: bytes,
              timeout: float) -> SendOutcome:
    """向登记地址 POST 原始字节，按约定分类结果。

    - 连接/超时/断开声明的响应 → 可重试；
    - 3xx 不跟随，永久失败；其他 4xx 永久失败，429 可重试；
    - 5xx 可重试；
    - 仅 2xx 才解析回执，回执无效则按可重试处理。
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise DeliveryError(f"不支持的接收地址协议: {parts.scheme!r}")
    if not parts.hostname:
        raise DeliveryError("接收地址缺少主机")
    port = parts.port  # 端口非法时抛 ValueError
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    connection_cls = (http.client.HTTPSConnection if parts.scheme == "https"
                      else http.client.HTTPConnection)

    send_headers = dict(headers)
    send_headers["Content-Length"] = str(len(body))
    # 身份值在传输前按统一规则净化一次（换行/控制字符/非 ASCII 直接拒绝）
    for name in DELIVERY_HEADERS:
        send_headers[name] = header_value(send_headers[name])

    conn = connection_cls(parts.hostname, port, timeout=timeout)
    try:
        try:
            conn.request("POST", path, body=body, headers=send_headers)
            resp = conn.getresponse()
        except (socket.timeout, TimeoutError):
            return SendOutcome(OUTCOME_RETRYABLE, failure_reason="timeout")
        except ConnectionRefusedError:
            return SendOutcome(OUTCOME_RETRYABLE,
                               failure_reason="connection_refused")
        except (ConnectionResetError, BrokenPipeError,
                ConnectionAbortedError):
            return SendOutcome(OUTCOME_RETRYABLE,
                               failure_reason="connection_reset")
        except socket.gaierror as exc:
            return SendOutcome(OUTCOME_RETRYABLE,
                               failure_reason=f"dns_error: {exc}")
        except OSError as exc:
            return SendOutcome(OUTCOME_RETRYABLE,
                               failure_reason=f"network_error: {exc}")
        except http.client.HTTPException as exc:
            return SendOutcome(OUTCOME_RETRYABLE,
                               failure_reason=f"bad_response: {exc}")

        status = resp.status
        retry_after = resp.getheader("Retry-After")
        detail: dict[str, Any] = {}

        if 300 <= status < 400:
            # 不跟随跳转；立即关闭连接（不读正文），按永久失败处理
            conn.close()
            return SendOutcome(OUTCOME_PERMANENT, http_status=status,
                               failure_reason="http_redirect_not_followed",
                               detail={"location": resp.getheader("Location")})

        if not 200 <= status < 300:
            # 非 2xx：不读取可能无限长的正文，直接关闭连接（连接能结束）
            if status == 429:
                return SendOutcome(OUTCOME_RETRYABLE, http_status=status,
                                   failure_reason="http_429_rate_limited",
                                   retry_after=retry_after)
            kind = "http_4xx_client_error" if 400 <= status < 500 \
                else "http_5xx_server_error" if 500 <= status < 600 \
                else "http_unexpected_status"
            return SendOutcome(OUTCOME_PERMANENT, http_status=status,
                               failure_reason=kind)

        # ---- 2xx：必须有有效回执 --------------------------------------
        # 读取前先声明长度上限：超过 64KiB 立即判无效回执并关闭连接，
        # 不去读完一个可能无限长的响应体。
        declared = resp.getheader("Content-Length")
        if declared is not None and declared.isdigit() \
                and int(declared) > MAX_RESPONSE_BYTES:
            detail["declared_length"] = int(declared)
            return SendOutcome(OUTCOME_RETRYABLE, http_status=status,
                               failure_reason="invalid_receipt: "
                                              "response_too_large",
                               detail=detail)
        raw, read_error = _read_bounded(resp)
        if read_error:
            return SendOutcome(OUTCOME_RETRYABLE, http_status=status,
                               failure_reason=f"invalid_receipt: {read_error}")
        detail["response_bytes"] = len(raw)
        ok, reason = validate_receipt(raw, headers[HEADER_DELIVERY_KEY],
                                      headers[HEADER_BODY_SHA256])
        if not ok:
            return SendOutcome(OUTCOME_RETRYABLE, http_status=status,
                               failure_reason=f"invalid_receipt: {reason}",
                               detail=detail)
        detail["receipt"] = raw.decode("utf-8", errors="strict")
        return SendOutcome(OUTCOME_SUCCESS, http_status=status, detail=detail)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _read_bounded(resp) -> tuple[bytes, str | None]:
    """最多读取 64KiB；超限立即停止读取并报告错误（连接随后关闭）。"""
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = resp.read(min(8192, MAX_RESPONSE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                return b"", "response_too_large"
            chunks.append(chunk)
    except (socket.timeout, TimeoutError):
        return b"", "response_read_timeout"
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError,
            http.client.HTTPException) as exc:
        return b"", f"response_read_error: {exc}"
    except OSError as exc:
        return b"", f"response_read_error: {exc}"
    return b"".join(chunks), None


# ------------------------------------------------------------------------- #
# 持久层：登记、排队、领取、回写、人工重试
# ------------------------------------------------------------------------- #
def _row_dict(row) -> dict[str, Any] | None:
    return {k: row[k] for k in row.keys()} if row is not None else None


class DeliveryStore:
    """客户端投递状态存储。

    每个方法使用独立的短事务；领取用 ``BEGIN IMMEDIATE`` 拿到写锁，
    提交后立即释放，网络请求期间不持有任何 SQLite 锁。
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = connect(db_path)
        self.conn.isolation_level = None  # 显式事务
        # 多进程并发时，短暂等待写锁而不是立刻报 database is locked
        self.conn.execute("PRAGMA busy_timeout = 10000")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        tables = {
            r[0] for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "outbox_delivery" not in tables:
            # 本模块不应自行迁移；由 Storage/init-db 完成。这里给出明确指引。
            raise DeliveryError(
                "数据库缺少投递表；请先运行 init-db 或使用会执行迁移的 Storage"
            )

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 登记
    # ------------------------------------------------------------------ #
    def _txn(self, fn):
        """在 BEGIN IMMEDIATE 事务中执行 fn(conn)，提交或回滚。"""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            value = fn(self.conn)
            self.conn.execute("COMMIT")
            return value
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def _txn_read(self, fn):
        self.conn.execute("BEGIN")
        try:
            value = fn(self.conn)
            self.conn.execute("COMMIT")
            return value
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def endpoint(self, partner_id: str) -> dict[str, Any] | None:
        return self._txn_read(lambda c: _row_dict(c.execute(
            "SELECT * FROM delivery_endpoints WHERE partner_id = ?",
            (partner_id,),
        ).fetchone()))

    def register_endpoint(self, partner_id: str, url: str,
                          now: int) -> dict[str, Any]:
        """登记合作方接收地址；已登记则拒绝原地更换。"""
        url = validate_endpoint_url(url)

        def op(c):
            row = c.execute(
                "SELECT * FROM delivery_endpoints WHERE partner_id = ?",
                (partner_id,),
            ).fetchone()
            if row is not None:
                if row["url"] == url:
                    raise DeliveryError(
                        f"合作方 {partner_id} 已登记同一地址: {url}")
                raise DeliveryError(
                    f"合作方 {partner_id} 已登记地址 {row['url']}；"
                    "接收地址不可原地更换（请使用新合作方登记新地址）")
            c.execute(
                "INSERT INTO delivery_endpoints "
                "(partner_id, url, registered_at) VALUES (?, ?, ?)",
                (partner_id, url, now),
            )
            return {"partner_id": partner_id, "url": url,
                    "registered_at": now}

        return self._txn(op)

    # ------------------------------------------------------------------ #
    # 队列查询
    # ------------------------------------------------------------------ #
    def known_partners(self) -> list[str]:
        """有未送达 outbox 的合作方（按 id 升序）。"""
        return self._txn_read(lambda c: [
            row[0] for row in c.execute(
                "SELECT DISTINCT partner_id FROM outbox "
                "WHERE status != 'delivered' ORDER BY partner_id ASC"
            ).fetchall()
        ])

    def head_status(self, partner_id: str, now: int) -> dict[str, Any] | None:
        """队首的可发状态说明（不领取、不写库），用于本轮不等待时报告原因。"""
        def op(c):
            head = c.execute(
                "SELECT o.id, o.event_id, o.source_seq, o.status,"
                " d.status AS delivery_status, d.next_attempt_at,"
                " d.lease_expires_at, d.lease_owner, d.last_failure_reason"
                " FROM outbox o LEFT JOIN outbox_delivery d ON d.outbox_id = o.id"
                " WHERE o.partner_id = ? AND o.status != 'delivered'"
                " ORDER BY o.id ASC LIMIT 1",
                (partner_id,),
            ).fetchone()
            if head is None:
                return None
            item = _row_dict(head)
            status = item["delivery_status"]
            if status == STATUS_RETRY_WAIT and (item["next_attempt_at"] or 0) > now:
                item["ready"] = False
                item["blocked_by"] = "backoff"
                item["wait_seconds"] = item["next_attempt_at"] - now
            elif status == STATUS_IN_FLIGHT and (item["lease_expires_at"] or 0) > now:
                item["ready"] = False
                item["blocked_by"] = "leased"
                item["wait_seconds"] = item["lease_expires_at"] - now
            elif status == STATUS_PERMANENT_FAILURE:
                item["ready"] = False
                item["blocked_by"] = "permanent_failure"
                item["wait_seconds"] = None
            else:
                item["ready"] = True
                item["blocked_by"] = None
                item["wait_seconds"] = 0
            return item

        return self._txn_read(op)

    def partner_queue(self, partner_id: str,
                      limit: int = 100,
                      now: int | None = None) -> list[dict[str, Any]]:
        def op(c):
            rows = c.execute(
                """
                SELECT o.id, o.partner_id, o.event_id, o.source_seq,
                       o.body_sha256, o.created_at,
                       o.status AS outbox_status, o.delivered_at AS outbox_delivered_at,
                       d.status, d.attempt_no, d.total_attempts,
                       d.next_attempt_at, d.lease_owner, d.lease_token,
                       d.lease_expires_at, d.current_attempt_id,
                       d.last_http_status, d.last_failure_reason,
                       d.last_attempt_at, d.last_finished_at,
                       d.takeover_reason, d.delivered_at
                FROM outbox o
                LEFT JOIN outbox_delivery d ON d.outbox_id = o.id
                WHERE o.partner_id = ?
                ORDER BY o.id ASC
                LIMIT ?
                """,
                (partner_id, limit),
            ).fetchall()
            return [_row_dict(r) for r in rows]

        return self._txn_read(op)

    def event_attempts(self, partner_id: str, event_id: str) -> dict[str, Any]:
        def op(c):
            item = c.execute(
                "SELECT * FROM outbox WHERE partner_id = ? AND event_id = ?",
                (partner_id, event_id),
            ).fetchone()
            if item is None:
                raise DeliveryError(
                    f"未找到 outbox 事件: {partner_id}/{event_id}")
            state = _row_dict(c.execute(
                "SELECT * FROM outbox_delivery WHERE outbox_id = ?",
                (item["id"],),
            ).fetchone())
            attempts = [_row_dict(r) for r in c.execute(
                "SELECT * FROM delivery_attempts WHERE outbox_id = ? "
                "ORDER BY id ASC", (item["id"],)).fetchall()]
            actions = [_row_dict(r) for r in c.execute(
                "SELECT * FROM delivery_operator_actions WHERE outbox_id = ? "
                "ORDER BY id ASC", (item["id"],)).fetchall()]
            return {
                "outbox": _row_dict(item), "delivery": state,
                "attempts": attempts, "operator_actions": actions,
            }

        return self._txn_read(op)

    # ------------------------------------------------------------------ #
    # 领取：每个合作方最小 outbox.id 的队首
    # ------------------------------------------------------------------ #
    def claim_next(self, partner_id: str, worker_id: str, now: int,
                   lease_seconds: int = DEFAULT_LEASE_SECONDS,
                   ) -> dict[str, Any] | None:
        """领取某合作方的队首；没有可发项返回 None。

        队首规则：
        - 最小 ``outbox.id`` 且未 delivered 的就是队首；
        - 队首未有状态行/in_flight 但占用已过期 → 接手（旧尝试标 takeover）；
        - 队首 retry_wait 且 next_attempt_at 未到 → 返回 None（不等待、不越过）；
        - 队首 permanent_failure → 返回 None，必须人工重试；
        - 队首占用未到期 → 返回 None，不抢。
        """
        lease_expires = now + lease_seconds
        token = uuid.uuid4().hex

        def op(c):
            head = c.execute(
                """
                SELECT o.id FROM outbox o
                WHERE o.partner_id = ? AND o.status != 'delivered'
                ORDER BY o.id ASC LIMIT 1
                """,
                (partner_id,),
            ).fetchone()
            if head is None:
                return None
            outbox_id = head["id"]
            state = c.execute(
                "SELECT * FROM outbox_delivery WHERE outbox_id = ?",
                (outbox_id,),
            ).fetchone()

            takeover_reason = None
            previous = None
            prev_state = None
            if state is not None:
                if state["status"] == STATUS_IN_FLIGHT:
                    if state["lease_expires_at"] is not None \
                            and state["lease_expires_at"] <= now:
                        takeover_reason = "lease_expired"
                    else:
                        return None  # 其他工人持有，不抢
                elif state["status"] == STATUS_RETRY_WAIT:
                    if (state["next_attempt_at"] or 0) > now:
                        return None  # 未到期：本轮不等待，也不越过队首
                elif state["status"] == STATUS_PERMANENT_FAILURE:
                    return None  # 必须操作者明确重试
                elif state["status"] == STATUS_DELIVERED:
                    return None  # 防御：与 outbox 状态不一致
                # 过期 in_flight 或 pending/新状态 → 可以领取

                if takeover_reason:
                    previous = state["current_attempt_id"]
                    if previous is not None:
                        prev_state = c.execute(
                            "SELECT worker_id FROM delivery_attempts WHERE id = ?",
                            (previous,),
                        ).fetchone()
                    else:
                        prev_state = None
                    c.execute(
                        "UPDATE delivery_attempts SET outcome = ?, "
                        "finished_at = COALESCE(finished_at, ?), "
                        "takeover_reason = ? "
                        "WHERE id = ? AND outcome IS NULL",
                        (OUTCOME_LEASE_EXPIRED, now,
                         "previous lease expired", previous),
                    )
                else:
                    prev_state = None

            item = c.execute(
                "SELECT * FROM outbox WHERE id = ?", (outbox_id,)
            ).fetchone()
            # attempt_no 是本轮连续失败计数：仅人工重试会清零；
            # 普通顺序推进与过期接手都只看当前状态。
            if state is None or state["status"] in (STATUS_PENDING,
                                                    STATUS_RETRY_WAIT):
                attempt_no = 1 if state is None else (state["attempt_no"] or 0) + 1
            else:
                # in_flight（过期接手）：延续原轮次，接手本身也是一次尝试
                attempt_no = (state["attempt_no"] or 0) + 1
            # total_attempts 含所有网络/本地尝试
            total_attempts = (state["total_attempts"] + 1) if state is not None else 1

            key = delivery_key(item["partner_id"], item["event_id"],
                               item["body_sha256"])
            cur = c.execute(
                """
                INSERT INTO delivery_attempts
                (outbox_id, partner_id, event_id, source_seq, delivery_key,
                 body_sha256, attempt_no, worker_id, lease_token, claimed_at,
                 lease_expires_at, previous_attempt_id, previous_worker_id,
                 takeover_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (outbox_id, item["partner_id"], item["event_id"],
                 item["source_seq"], key, item["body_sha256"], attempt_no,
                 worker_id, token, now, lease_expires, previous,
                 prev_state["worker_id"] if prev_state else None,
                 takeover_reason),
            )
            attempt_id = int(cur.lastrowid)

            if state is None:
                c.execute(
                    """
                    INSERT INTO outbox_delivery
                    (outbox_id, partner_id, status, attempt_no, total_attempts,
                     next_attempt_at, lease_owner, lease_token, lease_expires_at,
                     current_attempt_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
                    """,
                    (outbox_id, partner_id, STATUS_IN_FLIGHT, attempt_no,
                     total_attempts, worker_id, token, lease_expires,
                     attempt_id, now),
                )
            else:
                c.execute(
                    """
                    UPDATE outbox_delivery SET
                        status = ?, attempt_no = ?, total_attempts = ?,
                        next_attempt_at = NULL, lease_owner = ?, lease_token = ?,
                        lease_expires_at = ?, current_attempt_id = ?,
                        takeover_reason = COALESCE(?, takeover_reason),
                        updated_at = ?
                    WHERE outbox_id = ?
                    """,
                    (STATUS_IN_FLIGHT, attempt_no, total_attempts, worker_id,
                     token, lease_expires, attempt_id, takeover_reason,
                     now, outbox_id),
                )

            # 领取事务只登记占用与尝试，不带大正文；正文在事务提交后另读
            return {
                "outbox_id": outbox_id,
                "partner_id": item["partner_id"],
                "event_id": item["event_id"],
                "source_seq": item["source_seq"],
                "body_sha256": item["body_sha256"],
                "delivery_key": key,
                "attempt_id": attempt_id,
                "attempt_no": attempt_no,
                "total_attempts": total_attempts,
                "lease_token": token,
                "lease_expires_at": lease_expires,
                "claimed_at": now,
                "takeover_reason": takeover_reason,
                "body": None,
                "stored_byte_length": None,
            }

        claim = self._txn(op)
        if claim is not None:
            # 事务（写锁）已释放；正文读取不在任何事务/写锁内
            raw = self.load_body(claim["body_sha256"])
            claim["body"] = raw[0] if raw else None
            claim["stored_byte_length"] = raw[1] if raw else None
        return claim

    def load_body(self, body_sha256: str) -> tuple[bytes | None, int | None]:
        def op(c):
            row = c.execute(
                "SELECT body_blob, byte_length FROM raw_bodies "
                "WHERE body_sha256 = ?", (body_sha256,),
            ).fetchone()
            if row is None:
                return None, None
            return bytes(row["body_blob"]), row["byte_length"]

        return self._txn_read(op)

    # ------------------------------------------------------------------ #
    # 本地坏数据：正文缺失/长度与摘要不符（通过 claim['body_problem'] 标记，
    # 由 finish() 写成 permanent_failure；绝不写 outbox.delivered）
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # 回写：只有凭据仍有效才生效
    # ------------------------------------------------------------------ #
    def finish(self, claim: dict[str, Any], send: SendOutcome, now: int,
               lease_seconds: int = DEFAULT_LEASE_SECONDS) -> dict[str, Any]:
        """根据网络结果回写。lease token 失效时只记迟到回执，不改状态。"""
        if claim.get("body_problem"):
            # 本地坏数据：绝不写 delivered
            return self._finish(claim, now, OUTCOME_LOCAL_ERROR,
                                http_status=None,
                                failure_reason=claim["body_problem"],
                                next_status=STATUS_PERMANENT_FAILURE,
                                retry_after=None,
                                detail={"local_error": True},
                                lease_seconds=lease_seconds)
        if send.outcome == OUTCOME_SUCCESS:
            return self._finish(claim, now, OUTCOME_SUCCESS,
                                http_status=send.http_status,
                                failure_reason=None,
                                next_status=STATUS_DELIVERED,
                                retry_after=send.retry_after,
                                detail=send.detail,
                                lease_seconds=lease_seconds)
        if send.outcome == OUTCOME_PERMANENT:
            return self._finish(claim, now, OUTCOME_PERMANENT,
                                http_status=send.http_status,
                                failure_reason=send.failure_reason,
                                next_status=STATUS_PERMANENT_FAILURE,
                                retry_after=send.retry_after,
                                detail=send.detail,
                                lease_seconds=lease_seconds)
        # retryable
        if send.failure_reason and send.failure_reason.startswith("invalid_receipt:"):
            category = "invalid_receipt"
        else:
            category = "network"
        detail = dict(send.detail)
        detail["category"] = category
        return self._finish(claim, now, OUTCOME_RETRYABLE,
                            http_status=send.http_status,
                            failure_reason=send.failure_reason,
                            next_status=STATUS_RETRY_WAIT,
                            retry_after=send.retry_after,
                            detail=detail,
                            lease_seconds=lease_seconds)

    def _finish(self, claim, now, outcome, *, http_status, failure_reason,
                next_status, retry_after, detail, lease_seconds) -> dict[str, Any]:
        def op(c):
            token = claim["lease_token"]
            attempt = c.execute(
                "SELECT * FROM delivery_attempts WHERE lease_token = ?",
                (token,),
            ).fetchone()
            if attempt is None:
                raise DeliveryError("尝试记录不存在（内部错误）")
            state = c.execute(
                "SELECT * FROM outbox_delivery WHERE outbox_id = ?",
                (claim["outbox_id"],),
            ).fetchone()

            if state is None or state["lease_token"] != token \
                    or state["current_attempt_id"] != attempt["id"]:
                # 迟到回执：凭据已失效。只追加 late_* 字段（同一尝试重复
                # 的迟到回执保留最早一次），绝不覆盖新工人的结果。
                c.execute(
                    """
                    UPDATE delivery_attempts SET
                        late_finished_at = ?, late_outcome = ?,
                        late_http_status = ?, late_failure_reason = ?
                    WHERE id = ? AND (late_finished_at IS NULL
                                      OR late_finished_at > ?)
                    """,
                    (now, outcome, http_status, failure_reason,
                     attempt["id"], now),
                )
                return {
                    "applied": False,
                    "reason": "lease_superseded",
                    "late_outcome": outcome,
                    "http_status": http_status,
                    "failure_reason": failure_reason,
                }

            detail_json = json.dumps(detail, ensure_ascii=False, sort_keys=True) \
                if detail else None
            c.execute(
                """
                UPDATE delivery_attempts SET
                    finished_at = ?, outcome = ?, http_status = ?,
                    failure_reason = ?, detail_json = ?,
                    body_bytes_sent = ?
                WHERE id = ?
                """,
                (now, outcome, http_status, failure_reason, detail_json,
                 claim.get("sent_bytes"), attempt["id"]),
            )

            next_attempt_at = None
            attempt_no = attempt["attempt_no"]
            applied_outcome = outcome
            if outcome == OUTCOME_SUCCESS:
                # 唯一合法地写 outbox.delivered 的路径
                c.execute(
                    "UPDATE outbox SET status = 'delivered', delivered_at = ? "
                    "WHERE id = ? AND status != 'delivered'",
                    (now, claim["outbox_id"]),
                )
                c.execute(
                    """
                    UPDATE outbox_delivery SET
                        status = ?, next_attempt_at = NULL,
                        lease_owner = NULL, lease_token = NULL,
                        lease_expires_at = NULL, current_attempt_id = NULL,
                        last_http_status = ?, last_failure_reason = NULL,
                        last_attempt_at = ?, last_finished_at = ?,
                        delivered_at = ?, updated_at = ?
                    WHERE outbox_id = ?
                    """,
                    (STATUS_DELIVERED, http_status, claim["claimed_at"],
                     now, now, now, claim["outbox_id"]),
                )
            else:
                if outcome == OUTCOME_RETRYABLE:
                    retry_after_str = retry_after
                    delay = backoff_seconds(attempt_no, retry_after_str)
                    next_attempt_at = now + delay
                    applied_outcome = OUTCOME_RETRYABLE
                else:
                    next_attempt_at = None
                c.execute(
                    """
                    UPDATE outbox_delivery SET
                        status = ?, next_attempt_at = ?,
                        lease_owner = NULL, lease_token = NULL,
                        lease_expires_at = NULL, current_attempt_id = NULL,
                        last_http_status = ?, last_failure_reason = ?,
                        last_attempt_at = ?, last_finished_at = ?,
                        updated_at = ?
                    WHERE outbox_id = ?
                    """,
                    (next_status, next_attempt_at, http_status,
                     failure_reason, claim["claimed_at"], now, now,
                     claim["outbox_id"]),
                )
            return {
                "applied": True,
                "outcome": applied_outcome,
                "http_status": http_status,
                "failure_reason": failure_reason,
                "next_status": next_status,
                "next_attempt_at": next_attempt_at,
                "delivered": outcome == OUTCOME_SUCCESS,
            }

        return self._txn(op)

    # ------------------------------------------------------------------ #
    # 人工重试永久失败
    # ------------------------------------------------------------------ #
    def retry_permanent(self, partner_id: str, event_id: str,
                        now: int, operator: str | None = None,
                        ) -> dict[str, Any]:
        def op(c):
            item = c.execute(
                "SELECT * FROM outbox WHERE partner_id = ? AND event_id = ?",
                (partner_id, event_id),
            ).fetchone()
            if item is None:
                raise DeliveryError(
                    f"未找到 outbox 事件: {partner_id}/{event_id}")
            state = c.execute(
                "SELECT * FROM outbox_delivery WHERE outbox_id = ?",
                (item["id"],),
            ).fetchone()
            if item["status"] == "delivered":
                raise DeliveryError("该事件已送达，不能重新发送")
            if state is None or state["status"] != STATUS_PERMANENT_FAILURE:
                raise DeliveryError(
                    "只有永久失败事件可人工重试；当前状态: "
                    + (state["status"] if state else "pending"))
            if state["status"] == STATUS_IN_FLIGHT:
                raise DeliveryError("该事件正被工人持有，不能人工重试")
            c.execute(
                """
                UPDATE outbox_delivery SET
                    status = ?, attempt_no = 0, next_attempt_at = NULL,
                    lease_owner = NULL, lease_token = NULL,
                    lease_expires_at = NULL, current_attempt_id = NULL,
                    updated_at = ?
                WHERE outbox_id = ?
                """,
                (STATUS_PENDING, now, item["id"]),
            )
            c.execute(
                "INSERT INTO delivery_operator_actions "
                "(outbox_id, partner_id, event_id, action, acted_at, detail_json) "
                "VALUES (?, ?, ?, 'retry_permanent', ?, ?)",
                (item["id"], partner_id, event_id, now,
                 json.dumps({"operator": operator, "previous_status":
                             state["status"]}, ensure_ascii=False)),
            )
            return {
                "outbox_id": item["id"], "partner_id": partner_id,
                "event_id": event_id, "status": STATUS_PENDING,
                "attempt_no": 0, "total_attempts_before":
                state["total_attempts"],
            }

        return self._txn(op)


def validate_endpoint_url(url: str) -> str:
    """只接受 http(s)，拒绝 URL 中的换行与控制字符。"""
    if not isinstance(url, str) or not url:
        raise DeliveryError("接收地址不能为空")
    if any(ch in url for ch in ("\r", "\n", "\t", "\x00")):
        raise DeliveryError("接收地址包含换行/控制字符")
    if any(not 0x20 <= ord(ch) <= 0x7e for ch in url):
        raise DeliveryError("接收地址只允许可打印 ASCII")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise DeliveryError("接收地址必须是 http:// 或 https://")
    if not parts.hostname:
        raise DeliveryError("接收地址缺少主机")
    if parts.fragment:
        raise DeliveryError("接收地址不能包含 fragment")
    try:
        parts.port  # noqa: B018 触发端口合法性检查
    except ValueError:
        raise DeliveryError("接收地址端口非法") from None
    return url


# ----------------------------------------------------------------- ------------------------------------------------------------------
# 工人：一轮运行
# ----------------------------------------------------------------- ------------------------------------------------------------------
@dataclass
class WorkerReport:
    partner_id: str
    worker_id: str
    attempts: int = 0
    delivered: list[str] = field(default_factory=list)
    retry_wait: list[dict[str, Any]] = field(default_factory=list)
    permanent_failure: list[dict[str, Any]] = field(default_factory=list)
    local_error: list[dict[str, Any]] = field(default_factory=list)
    deferred_head: dict[str, Any] | None = None
    late: list[dict[str, Any]] = field(default_factory=list)
    no_endpoint: bool = False
    stopped_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "partner_id": self.partner_id,
            "worker_id": self.worker_id,
            "attempts": self.attempts,
            "delivered": self.delivered,
            "retry_wait": self.retry_wait,
            "permanent_failure": self.permanent_failure,
            "local_error": self.local_error,
            "deferred_head": self.deferred_head,
            "late": self.late,
            "no_endpoint": self.no_endpoint,
            "stopped_reason": self.stopped_reason,
        }


class DeliveryWorker:
    """独立 HTTP 发送工人，可用任意进程并发运行（依赖 SQLite 持久占用）。"""

    def __init__(self, db_path: str, *, clock: Callable[[], float] | None = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 lease_seconds: int = DEFAULT_LEASE_SECONDS,
                 worker_id: str | None = None,
                 sender: Callable[[str, dict[str, str], bytes, float],
                                  SendOutcome] = send_once):
        self.store = DeliveryStore(db_path)
        self._clock = clock or time.time
        if not timeout > 0:
            raise DeliveryError("单请求超时必须为正数")
        if lease_seconds <= 0:
            raise DeliveryError("占用秒数必须为正数")
        self.timeout = timeout
        self.lease_seconds = lease_seconds
        self.worker_id = worker_id or f"{os.getpid()}-{uuid.uuid4().hex[:12]}"
        self._sender = sender

    def close(self) -> None:
        self.store.close()

    def now(self) -> int:
        return int(self._clock())

    def run_partner(self, partner_id: str,
                    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                    ) -> WorkerReport:
        """推进一个合作方：每步最多一次网络尝试，受 ``max_attempts`` 限制。

        将来才到期的队首不等待也不忙循环——立即返回 deferred_head。
        """
        report = WorkerReport(partner_id=partner_id, worker_id=self.worker_id)
        if max_attempts < 0:
            raise DeliveryError("max_attempts 不能为负数")
        endpoint = self.store.endpoint(partner_id)
        if endpoint is None:
            report.no_endpoint = True
            report.stopped_reason = "no_endpoint"
            return report
        url = endpoint["url"]

        while report.attempts < max_attempts:
            now = self.now()
            claim = self.store.claim_next(
                partner_id, self.worker_id, now,
                lease_seconds=self.lease_seconds,
            )
            if claim is None:
                # 不等待、不忙循环：报告队首为何不可发（退避/占用/永久失败）
                report.deferred_head = self.store.head_status(partner_id, now)
                report.stopped_reason = "head_not_ready"
                return report

            report.attempts += 1
            claim["sent_bytes"] = 0

            # ---- 发送前重算长度与摘要；坏数据绝不出网 ------------------
            body = claim["body"]
            problem = self._check_body(body, claim)
            if problem is not None:
                claim["body_problem"] = problem
                self.store.finish(claim, SendOutcome(OUTCOME_LOCAL_ERROR,
                                                     failure_reason=problem),
                                  now, lease_seconds=self.lease_seconds)
                report.local_error.append({
                    "event_id": claim["event_id"],
                    "outbox_id": claim["outbox_id"],
                    "reason": problem,
                })
                report.stopped_reason = "local_error"
                return report

            try:
                headers = build_headers(
                    claim["partner_id"], claim["event_id"],
                    claim["source_seq"], claim["body_sha256"],
                    claim["delivery_key"],
                )
            except DeliveryError as exc:
                claim["body_problem"] = f"header_build_error: {exc}"
                self.store.finish(claim, SendOutcome(OUTCOME_LOCAL_ERROR),
                                  now, lease_seconds=self.lease_seconds)
                report.local_error.append({
                    "event_id": claim["event_id"],
                    "outbox_id": claim["outbox_id"],
                    "reason": f"header_build_error: {exc}",
                })
                report.stopped_reason = "local_error"
                return report

            claim["sent_bytes"] = len(body)
            try:
                send = self._sender(url, headers, body, self.timeout)
            except Exception as exc:  # 发送器内部异常按可重试网络故障处理
                send = SendOutcome(OUTCOME_RETRYABLE,
                                   failure_reason=f"sender_error: {exc}")

            result = self.store.finish(claim, send, self.now(),
                                       lease_seconds=self.lease_seconds)
            if not result.get("applied"):
                report.late.append({
                    "event_id": claim["event_id"],
                    "attempt_id": claim["attempt_id"],
                    "late_outcome": result.get("late_outcome"),
                    "reason": result.get("reason"),
                })
                report.stopped_reason = "lease_superseded_before_writeback"
                return report

            if result["outcome"] == OUTCOME_SUCCESS:
                report.delivered.append(claim["event_id"])
                continue  # 队首推进到下一条
            if result["outcome"] == OUTCOME_PERMANENT:
                report.permanent_failure.append({
                    "event_id": claim["event_id"],
                    "http_status": result["http_status"],
                    "reason": result["failure_reason"],
                })
                report.stopped_reason = "head_permanent_failure"
                return report
            if result["outcome"] == OUTCOME_LOCAL_ERROR:
                report.local_error.append({
                    "event_id": claim["event_id"],
                    "reason": result["failure_reason"],
                })
                report.stopped_reason = "local_error"
                return report
            # retryable：队首进入退避，本轮结束（不越过、不忙循环）
            report.retry_wait.append({
                "event_id": claim["event_id"],
                "http_status": result["http_status"],
                "reason": result["failure_reason"],
                "next_attempt_at": result["next_attempt_at"],
            })
            report.stopped_reason = "head_retry_wait"
            return report

        report.stopped_reason = "max_attempts"
        return report

    @staticmethod
    def _check_body(body: bytes | None, claim: dict[str, Any]) -> str | None:
        if body is None:
            return "body_missing"
        if not isinstance(body, (bytes, bytearray)):
            return "body_not_bytes"
        body = bytes(body)
        stored_len = claim.get("stored_byte_length")
        if stored_len is not None and int(stored_len) != len(body):
            return ("body_length_mismatch: "
                    f"stored={stored_len} actual={len(body)}")
        digest = hashlib.sha256(body).hexdigest()
        if digest != str(claim["body_sha256"]).lower():
            return (f"body_sha256_mismatch: stored={claim['body_sha256']} "
                    f"actual={digest}")
        return None
