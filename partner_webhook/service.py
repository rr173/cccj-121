"""Webhook 接收验证服务（与传输层解耦，便于测试与重放）。

验证顺序严格按需求执行，任一步失败即记录拒绝流水并返回，绝不让
未通过验证的事件进入下游：

1. 协议版本与必填头；
2. 合作方与密钥版本（版本存在、且在请求声称的时间点仍生效）；
3. 时间窗（服务端当前时间与请求时间戳的偏差）；
4. 协议规范化 + HMAC 签名；
5. 事件 ID 去重 / 同 ID 异载荷冲突隔离；
6. 接受事件并写入下游 outbox（同一事务）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Mapping

from . import PROTOCOL_VERSION
from .canonical import (
    HEADER_EVENT_ID,
    HEADER_KEY_VERSION,
    HEADER_PARTNER,
    HEADER_PROTOCOL,
    HEADER_SEQUENCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_bytes,
    headers_lower,
)
from .config import AppConfig
from .crypto import decode_secret, verify
from .storage import Storage

# 接收结果
ACCEPTED = "accepted"
DUPLICATE = "duplicate"
CONFLICT = "conflict"
REJECTED = "rejected"

# 拒绝原因 -> HTTP 状态码
REJECTION_STATUS = {
    "missing_headers": 400,
    "bad_protocol": 400,
    "bad_timestamp": 400,
    "bad_sequence": 400,
    "unknown_partner": 404,
    "unknown_key_version": 401,
    "key_expired": 401,
    "timestamp_outside_window": 401,
    "bad_signature": 401,
    "conflicting_event_id": 409,
    "duplicate_event": 200,       # 幂等重投：返回成功但不再次入下游
}
STATUS_CONFLICT = 409
STATUS_OK = 200
STATUS_BAD_REQUEST = 400


@dataclass
class ReceiveResult:
    result: str
    reason: str | None
    http_status: int
    record_id: int | None = None
    event_id: str | None = None


class _LedgerEncodingError(Exception):
    """已安装账本的合作方提交了账本协议无法编码的事件。

    整个接收事务回滚（不落 ingest_records / accepted_events / outbox），
    由 HTTP 层映射为 400。
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


Clock = Callable[[], float]


class WebhookService:
    def __init__(self, config: AppConfig, storage: Storage, clock: Clock | None = None):
        self.config = config
        self.storage = storage
        self._clock = clock or time.time

    def now(self) -> int:
        return int(self._clock())

    # ------------------------------------------------------------------ #
    def receive(
        self,
        *,
        method: str,
        path: str,
        raw_headers: Mapping[str, str],
        body: bytes,
    ) -> ReceiveResult:
        """处理一次投递。所有分支（含拒绝）都会持久化流水。"""
        now = self.now()
        headers = headers_lower(raw_headers)
        storage = self.storage

        with storage.lock:
            try:
                # 先取数据库写锁：跨进程串行化，保证「首次接受」判定与账本
                # 叶序号一致。BEGIN IMMEDIATE 也覆盖随后的全部写入。
                storage.begin_write()
                body_sha256 = storage.store_raw_body(body, now)
                result = self._verify_and_persist(
                    method=method,
                    path=path,
                    headers=headers,
                    body=body,
                    body_sha256=body_sha256,
                    now=now,
                )
                storage.commit()
                return result
            except _LedgerEncodingError as exc:
                # 账本协议无法编码：整次拒绝，不留下任何接收或账本记录。
                storage.rollback()
                return ReceiveResult(
                    REJECTED, "ledger_encoding", STATUS_BAD_REQUEST, None,
                    headers.get(HEADER_EVENT_ID),
                )
            except Exception:
                storage.rollback()
                raise

    # ------------------------------------------------------------------ #
    def _verify_and_persist(
        self, *, method, path, headers, body, body_sha256, now
    ) -> ReceiveResult:
        # ---- 第 1 步：必填头与协议版本 ---------------------------------
        missing = [
            name for name in (
                HEADER_PROTOCOL, HEADER_PARTNER, HEADER_KEY_VERSION,
                HEADER_TIMESTAMP, HEADER_EVENT_ID, HEADER_SEQUENCE,
                HEADER_SIGNATURE,
            )
            if not headers.get(name)
        ]
        if missing:
            return self._reject(
                now=now, headers=headers, body_sha256=body_sha256,
                reason="missing_headers",
                detail={"missing": missing},
            )

        protocol = headers[HEADER_PROTOCOL]
        partner_id = headers[HEADER_PARTNER]
        key_version = headers[HEADER_KEY_VERSION]
        event_id = headers[HEADER_EVENT_ID]
        signature = headers[HEADER_SIGNATURE]

        if protocol != PROTOCOL_VERSION:
            return self._reject(
                now=now, headers=headers, body_sha256=body_sha256,
                reason="bad_protocol",
                common=dict(partner_id=partner_id, key_version=key_version,
                            event_id=event_id),
            )

        try:
            claimed_ts = int(headers[HEADER_TIMESTAMP])
        except ValueError:
            return self._reject(
                now=now, headers=headers, body_sha256=body_sha256,
                reason="bad_timestamp",
                common=dict(partner_id=partner_id, key_version=key_version,
                            event_id=event_id),
            )

        try:
            source_seq = int(headers[HEADER_SEQUENCE])
            if source_seq < 0:
                raise ValueError
        except ValueError:
            return self._reject(
                now=now, headers=headers, body_sha256=body_sha256,
                reason="bad_sequence",
                common=dict(partner_id=partner_id, key_version=key_version,
                            event_id=event_id, claimed_ts=claimed_ts),
            )

        common = dict(
            partner_id=partner_id, key_version=key_version,
            claimed_ts=claimed_ts, event_id=event_id, source_seq=source_seq,
        )

        # ---- 第 2 步：合作方与密钥版本（含密钥生效时间窗） -------------
        partner = self.config.partner(partner_id)
        if partner is None:
            return self._reject(now=now, headers=headers,
                                body_sha256=body_sha256,
                                reason="unknown_partner", common=common)

        key, key_err = partner.find_key(key_version, claimed_ts, now)
        if key_err is not None:
            # 密钥在声称时间或当前验证时间已失效 -> 过期签名不能重新进入
            return self._reject(now=now, headers=headers,
                                body_sha256=body_sha256,
                                reason=key_err, common=common)

        # ---- 第 3 步：服务端时间窗（防重放的第一道闸） ----------------
        skew = abs(now - claimed_ts)
        if skew > partner.max_skew_seconds:
            return self._reject(now=now, headers=headers,
                                body_sha256=body_sha256,
                                reason="timestamp_outside_window",
                                common=common,
                                detail={"skew_seconds": skew,
                                        "max_skew_seconds": partner.max_skew_seconds})

        # ---- 第 4 步：规范化 + HMAC 签名 ------------------------------
        canonical = canonical_bytes(
            method=method, path=path, partner_id=partner_id,
            key_version=key_version, timestamp=claimed_ts,
            event_id=event_id, sequence=source_seq, body=body,
        )
        if not verify(decode_secret(key.secret_b64), canonical, signature):
            return self._reject(now=now, headers=headers,
                                body_sha256=body_sha256,
                                reason="bad_signature", common=common)

        # ---- 第 5 步：事件 ID 去重 / 冲突隔离 -------------------------
        existing = self.storage.get_accepted_event(partner_id, event_id)
        if existing is not None:
            if existing["body_sha256"] == body_sha256:
                # 网络超时导致的幂等重投：确认成功，但不再次下发
                return self._finish(
                    now=now, headers=headers, body_sha256=body_sha256,
                    result=DUPLICATE, reason="duplicate_event",
                    http_status=REJECTION_STATUS["duplicate_event"],
                    common=common,
                )
            # 同 ID 但载荷不同：隔离为冲突，绝不覆盖原事件、不进下游
            return self._finish(
                now=now, headers=headers, body_sha256=body_sha256,
                result=CONFLICT, reason="conflicting_event_id",
                http_status=STATUS_CONFLICT, common=common,
                detail={"existing_body_sha256": existing["body_sha256"]},
            )

        # ---- 第 6 步：接受并同事务写入下游 outbox ---------------------
        record_id = self._insert_record(
            now=now, headers=headers, body_sha256=body_sha256,
            result=ACCEPTED, reason=None, http_status=STATUS_OK, common=common,
        )
        self.storage.insert_accepted_event({
            "event_id": event_id,
            "partner_id": partner_id,
            "source_seq": source_seq,
            "key_version": key_version,
            "body_sha256": body_sha256,
            "ingest_record_id": record_id,
            "claimed_timestamp": claimed_ts,
            "accepted_at": now,
        })
        # 保留源序号，乱序到达也按 source_seq 排序，绝不误判为重复
        self.storage.enqueue_outbox(
            partner_id=partner_id, event_id=event_id,
            source_seq=source_seq, body_sha256=body_sha256, now=now,
        )
        # ---- 第 7 步：同事务追加账本叶子（未安装的合作方跳过） ---------
        # 叶子序号来自 event_logs.tree_size（数据库写锁保护），与 source_seq
        # 无关；重复投递、同号冲突、拒收都在此之前返回，不会追加叶子。
        # 已安装的合作方在写叶前先把事件字段校验到可编码范围：超范围时整次
        # 接收回滚（accepted_events 与账本一同不落），而不是只记一半。
        installed = self.storage.event_log_installed(partner_id)
        if installed:
            from .eventlog import LedgerError, validate_encodable

            try:
                validate_encodable(partner_id, event_id, source_seq,
                                   body_sha256)
            except LedgerError as exc:
                # 已安装账本的合作方如果提交了账本无法编码的事件，明确拒绝
                # 整次接收（事件、正文、outbox 都不落），而不是只记一半。
                raise _LedgerEncodingError(exc.code, exc.message) from None
        self.storage.append_event_log_leaf(
            partner_id=partner_id, event_id=event_id,
            source_seq=source_seq, body_sha256=body_sha256, now=now,
        )
        return ReceiveResult(ACCEPTED, None, STATUS_OK, record_id, event_id)

    # ------------------------------------------------------------------ #
    def _reject(self, *, now, headers, body_sha256, reason,
                common=None, detail=None) -> ReceiveResult:
        record_id = self._insert_record(
            now=now, headers=headers, body_sha256=body_sha256,
            result=REJECTED, reason=reason,
            http_status=REJECTION_STATUS[reason],
            common=common or {}, detail=detail,
        )
        return ReceiveResult(REJECTED, reason,
                             REJECTION_STATUS[reason], record_id)

    def _finish(self, *, now, headers, body_sha256, result, reason,
                http_status, common, detail=None) -> ReceiveResult:
        record_id = self._insert_record(
            now=now, headers=headers, body_sha256=body_sha256,
            result=result, reason=reason, http_status=http_status,
            common=common, detail=detail,
        )
        return ReceiveResult(result, reason, http_status, record_id,
                             common.get("event_id"))

    def _insert_record(self, *, now, headers, body_sha256, result, reason,
                       http_status, common, detail=None) -> int:
        recorded_headers = dict(headers)
        if detail:
            recorded_headers["_detail"] = detail
        return self.storage.insert_ingest_record({
            "received_at": now,
            "partner_id": common.get("partner_id"),
            "key_version": common.get("key_version"),
            "claimed_timestamp": common.get("claimed_ts"),
            "event_id": common.get("event_id"),
            "source_seq": common.get("source_seq"),
            "body_sha256": body_sha256,
            "result": result,
            "reason": reason,
            "http_status": http_status,
            "headers": recorded_headers,
        })
