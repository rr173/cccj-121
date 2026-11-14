"""设备档案加工管线（独立 SQLite 加工库）。

从签名接收库的 ``accepted_events`` 读取 ``seed`` / ``patch`` 档案来件，按
RFC 6902 在独立数据库里持久维护「可解释的档案版本」。

设计要点
--------

* **源库只读**：只以 ``mode=ro`` + ``query_only`` 打开接收库，不借用也不
  标记原 outbox，不改变签名收件与坏库提取行为。
* **独立加工库**：加工状态全部保存在本模块自建的 SQLite 库，不使用正文
  搜索索引（``indexstore``）保存任何加工状态。
* **乱序与分支**：seed 与 patch 可以乱序到达，缺前版先等待；同一坐标出现
  多个源事件即分支，没有人工选择时只公布从唯一 seed 出发、每一跳均无分支
  且执行成功的最长前缀；选择持久化后按选择重算。
* **原子同步**：每次同步在源库一个只读读事务里取来件快照，加工侧的导入
  登记、当前档案与处置结论在同一个写事务里共同提交；当前内容的读取不可能
  看到「版本已升而内容还没改」的中间状态。未提交进程退出后重开仍是旧结果。
* **原子 patch**：:mod:`partner_webhook.jsonpatch` 深拷贝后应用，失败不留下
  半改对象；失败修订阻断其后续，不会被跳过。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .jsonpatch import MISSING, UNBORN, PatchError, apply_patch
from .strictjson import (
    JsonBodyError,
    JsonObject,
    RawNumber,
    parse_strict_json,
)

# 加工规则版本：信封/补丁规则变化时提升。
PROCESSOR_VERSION = 1

# 处置（disposition）稳定机器码。
DISP_ADOPTED = "adopted"                 # 已采用：进入当前公布链
DISP_WAITING = "waiting_predecessor"     # 等待前版：seed 或前一修订尚未齐
DISP_BRANCH_UNRESOLVED = "branch_unresolved"  # 分支未选：该修订有多个候选
DISP_NOT_SELECTED = "not_selected"       # 未被选中：人工选择了同坐标另一事件
DISP_OP_FAILED = "operation_failed"      # 操作失败：本事件 patch 执行不成立
DISP_BLOCKED = "blocked_by_predecessor"  # 被前方阻断：前序修订未进链
DISP_NON_ARCHIVE = "non_archive"         # 非档案来件：已接受但不是两类正文
DISP_INVALID = "invalid_contract"        # 约定字段缺失/多余/重复键/类型错误

# 中文解释（与机器码一一对应，便于 CLI 直接展示）。
DISPOSITION_TEXT = {
    DISP_ADOPTED: "已采用",
    DISP_WAITING: "等待前版",
    DISP_BRANCH_UNRESOLVED: "分支未选",
    DISP_NOT_SELECTED: "未被选中",
    DISP_OP_FAILED: "操作失败",
    DISP_BLOCKED: "被前方阻断",
    DISP_NON_ARCHIVE: "非档案来件",
    DISP_INVALID: "约定不符",
}


class ArchiveError(Exception):
    """加工库操作失败（选择坐标不存在等可预期错误也走这里）。"""


# --------------------------------------------------------------------- #
# 精确 JSON 序列化（保留 RawNumber 原文，不用 float / 不碰 NaN）
# --------------------------------------------------------------------- #
def dumps_exact(value: Any) -> str:
    """把严格解析值模型序列化为 JSON 文本，数字保留原始十进制写法。"""
    parts: list[str] = []

    def emit(node: Any) -> None:
        if node is None:
            parts.append("null")
        elif node is True:
            parts.append("true")
        elif node is False:
            parts.append("false")
        elif isinstance(node, RawNumber):
            parts.append(node.text)
        elif isinstance(node, str):
            parts.append(_json_string(node))
        elif isinstance(node, dict):
            parts.append("{")
            first = True
            for key, item in node.items():
                if not first:
                    parts.append(",")
                first = False
                parts.append(_json_string(key))
                parts.append(":")
                emit(item)
            parts.append("}")
        elif isinstance(node, list):
            parts.append("[")
            for index, item in enumerate(node):
                if index:
                    parts.append(",")
                emit(item)
            parts.append("]")
        else:  # pragma: no cover - 加工链只产生上面这些类型
            raise ArchiveError(f"无法序列化的值类型: {type(node)!r}")

    emit(value)
    return "".join(parts)


def _json_string(text: str) -> str:
    out = ['"']
    for ch in text:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def body_preview(blob: bytes, limit: int = 160) -> str:
    """正文摘要：UTF-8 解码后截断的文本预览（不是全文，也不是搜索索引）。"""
    text = blob.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + "…"
    return text


# --------------------------------------------------------------------- #
# 信封校验（不强制转型；一切错误指明事件）
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class ParsedEnvelope:
    kind: str                     # seed / patch
    document_id: str
    revision: int
    document: Any = None          # seed 才有
    base_revision: int | None = None
    operations: tuple = ()


@dataclass
class EnvelopeFailure:
    code: str                     # invalid_contract / non_archive
    reason: str


def _is_plain_object(value: Any) -> bool:
    return isinstance(value, JsonObject)


def _is_canonical_nonneg_int(value: Any) -> bool:
    # 布尔不是整数；严格解析器只产出 RawNumber 数字，这里只接受写法规范的
    # 非负整数字面量（拒绝 1.0、1e0、01、负数），不做任何强制转型。
    if isinstance(value, bool):
        return False
    if not isinstance(value, RawNumber):
        return False
    text = value.text
    if not text.isdigit():
        return False
    if len(text) > 1 and text[0] == "0":  # 拒绝 01 之类
        return False
    return True


def _as_int(value: Any) -> int:
    return int(value.text)


def validate_envelope(root: Any) -> ParsedEnvelope | EnvelopeFailure:
    """校验一份已接受正文是否符合档案来件约定。

    缺失/多余/重复键/类型错误一律返回 :class:`EnvelopeFailure`，不做任何
    强制转型；调用方负责把事件身份与原因一起登记。
    """
    if not isinstance(root, JsonObject):
        return EnvelopeFailure(
            DISP_NON_ARCHIVE,
            f"正文根不是 JSON 对象（实际 {type(root).__name__}），非档案来件",
        )
    obj = root.values
    kind = obj.get("kind")
    if not isinstance(kind, str):
        return EnvelopeFailure(DISP_INVALID,
                               "缺少字符串字段 kind 或其类型不是字符串")
    if kind not in ("seed", "patch"):
        return EnvelopeFailure(DISP_NON_ARCHIVE,
                               f"kind={kind!r} 不是 seed/patch，非档案来件")

    document_id = obj.get("document_id")
    if not isinstance(document_id, str):
        return EnvelopeFailure(DISP_INVALID,
                               "缺少字符串字段 document_id 或其类型不是字符串")
    revision_raw = obj.get("revision")
    if not _is_canonical_nonneg_int(revision_raw):
        return EnvelopeFailure(
            DISP_INVALID,
            "revision 必须是写法规范的非负整数字面量且不是布尔值"
            f"（实际 {_type_name(revision_raw)}）",
        )
    revision = _as_int(revision_raw)

    if kind == "seed":
        extra = set(obj) - {"kind", "document_id", "revision", "document"}
        if extra:
            return EnvelopeFailure(
                DISP_INVALID,
                f"seed 正文含多余字段: {sorted(extra)}（约定字段外不接受）",
            )
        if "document" not in obj:
            return EnvelopeFailure(DISP_INVALID, "seed 缺少 document 字段")
        if revision != 0:
            return EnvelopeFailure(DISP_INVALID,
                                   f"seed 的 revision 必须为 0（实际 {revision}）")
        return ParsedEnvelope(
            kind="seed", document_id=document_id, revision=0,
            document=obj["document"],
        )

    # kind == "patch"
    extra = set(obj) - {"kind", "document_id", "base_revision", "revision",
                        "operations"}
    if extra:
        return EnvelopeFailure(
            DISP_INVALID,
            f"patch 正文含多余字段: {sorted(extra)}（约定字段外不接受）",
        )
    base_raw = obj.get("base_revision")
    if not _is_canonical_nonneg_int(base_raw):
        return EnvelopeFailure(
            DISP_INVALID,
            "base_revision 必须是写法规范的非负整数字面量且不是布尔值"
            f"（实际 {_type_name(base_raw)}）",
        )
    base_revision = _as_int(base_raw)
    if revision != base_revision + 1:
        return EnvelopeFailure(
            DISP_INVALID,
            f"patch 的 revision({revision}) 必须等于 base_revision+1"
            f"({base_revision + 1})",
        )
    operations = obj.get("operations")
    if not isinstance(operations, list):
        return EnvelopeFailure(DISP_INVALID,
                               "operations 必须是 JSON Patch 操作数组")
    for index, op in enumerate(operations):
        failure = _validate_operation(op, index)
        if failure is not None:
            return failure
    return ParsedEnvelope(
        kind="patch", document_id=document_id, revision=revision,
        base_revision=base_revision, operations=tuple(operations),
    )


def _validate_operation(op: Any, index: int) -> EnvelopeFailure | None:
    where = f"第 {index + 1} 个操作"
    if not isinstance(op, JsonObject):
        return EnvelopeFailure(DISP_INVALID,
                               f"{where}必须是 JSON 对象（实际 {_type_name(op)}）")
    values = op.values
    name = values.get("op")
    if not isinstance(name, str):
        return EnvelopeFailure(DISP_INVALID, f"{where}缺少字符串字段 op")
    if name not in ("add", "remove", "replace", "move", "copy", "test"):
        return EnvelopeFailure(
            DISP_INVALID,
            f"{where}的 op={name!r} 不是 RFC 6902 六种操作之一",
        )
    path = values.get("path")
    if not isinstance(path, str):
        return EnvelopeFailure(DISP_INVALID, f"{where}缺少字符串字段 path")
    try:
        from .jsonpatch import parse_pointer
        parse_pointer(path)
    except ValueError as exc:
        return EnvelopeFailure(DISP_INVALID, f"{where}的 path 非法: {exc}")

    if name in ("move", "copy"):
        from_pointer = values.get("from")
        if not isinstance(from_pointer, str):
            return EnvelopeFailure(DISP_INVALID,
                                   f"{where}({name}) 缺少字符串字段 from")
        try:
            from .jsonpatch import parse_pointer
            parse_pointer(from_pointer)
        except ValueError as exc:
            return EnvelopeFailure(DISP_INVALID,
                                   f"{where}的 from 非法: {exc}")
        expected = {"op", "path", "from"}
    elif name in ("add", "replace", "test"):
        if "value" not in values:
            return EnvelopeFailure(DISP_INVALID,
                                   f"{where}({name}) 缺少 value 字段")
        expected = {"op", "path", "value"}
    else:  # remove
        expected = {"op", "path"}
    extra = set(values) - expected
    if extra:
        return EnvelopeFailure(
            DISP_INVALID,
            f"{where}含多余字段 {sorted(extra)}（{name} 只允许 {sorted(expected)}）",
        )
    return None


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "number"
    if isinstance(value, RawNumber):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, JsonObject):
        return "object"
    return type(value).__name__


# --------------------------------------------------------------------- #
# 加工库 schema 与连接
# --------------------------------------------------------------------- #
ARCHIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS archive_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 已导入事件的登记（来源只读保留：合作方、事件ID、正文摘要/长度/预览）。
CREATE TABLE IF NOT EXISTS archive_events (
    partner_id       TEXT NOT NULL,
    event_id         TEXT NOT NULL,
    document_id      TEXT NOT NULL,
    source_seq       INTEGER NOT NULL,
    body_sha256      TEXT NOT NULL,
    byte_length      INTEGER NOT NULL,
    body_preview     TEXT NOT NULL,
    kind             TEXT,                       -- seed / patch；非档案为 NULL
    revision         INTEGER,
    base_revision    INTEGER,
    disposition      TEXT NOT NULL,
    reason_code      TEXT,
    reason           TEXT,
    failed_op        INTEGER,                    -- 1 基操作序号
    failed_pointer   TEXT,
    imported_at      INTEGER NOT NULL,
    PRIMARY KEY (partner_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_archive_doc
    ON archive_events (partner_id, document_id, revision);

-- 档案类正文全文缓存：让加工库自包含（重算不依赖源库在线）；
-- 这不是搜索索引，只按 SHA-256 去重保存原始字节，供重新解释 seed/patch。
CREATE TABLE IF NOT EXISTS archive_bodies (
    body_sha256  TEXT PRIMARY KEY,
    body_blob    BLOB NOT NULL,
    byte_length  INTEGER NOT NULL
);

-- 每份档案当前公布状态；内容用精确 JSON 文本持久化。
CREATE TABLE IF NOT EXISTS documents (
    partner_id      TEXT NOT NULL,
    document_id     TEXT NOT NULL,
    current_revision INTEGER,                    -- 未公布任何内容时为 NULL
    state           TEXT NOT NULL,               -- present / absent
    content_json    TEXT,                        -- state=present 时的档案内容
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (partner_id, document_id)
);

-- 人工选择（含 seed 选择）。
CREATE TABLE IF NOT EXISTS revisions_selected (
    partner_id   TEXT NOT NULL,
    document_id  TEXT NOT NULL,
    revision     INTEGER NOT NULL,
    event_id     TEXT NOT NULL,
    selected_at  INTEGER NOT NULL,
    PRIMARY KEY (partner_id, document_id, revision)
);

-- 每次同步的流水（便于审计重复同步为无操作）。
CREATE TABLE IF NOT EXISTS sync_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      INTEGER NOT NULL,
    committed_at    INTEGER,
    source_events   INTEGER NOT NULL,
    imported        INTEGER NOT NULL,
    adopted         INTEGER NOT NULL,
    non_archive     INTEGER NOT NULL,
    invalid         INTEGER NOT NULL
);
"""


def _quote_uri_path(path: str) -> str:
    from urllib.parse import quote

    return "file:" + quote(str(Path(path).resolve()), safe="/")


def connect_archive(path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        uri = _quote_uri_path(path) + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    else:
        conn = sqlite3.connect(path, isolation_level=None)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA foreign_keys = OFF")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def connect_source_readonly(path: str) -> sqlite3.Connection:
    """只读打开签名接收库（``mode=ro`` + ``query_only``），绝不写源库。"""
    uri = _quote_uri_path(path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(ARCHIVE_SCHEMA)
    row = conn.execute(
        "SELECT value FROM archive_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO archive_meta(key, value) VALUES"
            " ('schema_version', '1'), ('processor_version', ?)",
            (str(PROCESSOR_VERSION),),
        )


# --------------------------------------------------------------------- #
# 同步
# --------------------------------------------------------------------- #
_SOURCE_EVENTS_SQL = """
SELECT ae.partner_id, ae.event_id, ae.source_seq, ae.body_sha256,
       rb.body_blob, rb.byte_length AS registered_length
FROM accepted_events ae
JOIN raw_bodies rb ON rb.body_sha256 = ae.body_sha256
ORDER BY ae.partner_id ASC, ae.source_seq ASC, ae.event_id ASC
"""


@dataclass
class ArchiveSyncReport:
    source_events: int = 0
    imported: int = 0
    recomputed_documents: int = 0
    adopted: int = 0
    waiting: int = 0
    branch_unresolved: int = 0
    not_selected: int = 0
    operation_failed: int = 0
    blocked: int = 0
    non_archive: int = 0
    invalid: int = 0
    documents: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "source_events": self.source_events,
            "imported": self.imported,
            "recomputed_documents": self.recomputed_documents,
            "disposition_counts": {
                DISP_ADOPTED: self.adopted,
                DISP_WAITING: self.waiting,
                DISP_BRANCH_UNRESOLVED: self.branch_unresolved,
                DISP_NOT_SELECTED: self.not_selected,
                DISP_OP_FAILED: self.operation_failed,
                DISP_BLOCKED: self.blocked,
                DISP_NON_ARCHIVE: self.non_archive,
                DISP_INVALID: self.invalid,
            },
            "documents": self.documents,
        }


def sync_archive(*, source_db: str, archive_db: str,
                 simulate_crash_before_commit: bool = False,
                 clock=time.time) -> ArchiveSyncReport:
    """从接收库导入新来件并重算全部受影响档案（单事务共同提交）。"""
    report = ArchiveSyncReport()
    archive_conn = connect_archive(archive_db)
    if simulate_crash_before_commit:
        # 让脏页尽早落 WAL，崩溃演示更有说服力；不影响事务原子性。
        archive_conn.execute("PRAGMA cache_size = -32")
        archive_conn.execute("PRAGMA wal_autocheckpoint = 0")
    try:
        ensure_schema(archive_conn)
        archive_conn.execute("BEGIN IMMEDIATE")
        try:
            _sync_in_transaction(
                archive_conn, source_db, report,
                simulate_crash_before_commit=simulate_crash_before_commit,
                clock=clock,
            )
            archive_conn.execute("COMMIT")
        except BaseException:
            try:
                archive_conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
    finally:
        archive_conn.close()
    return report


def _sync_in_transaction(archive_conn: sqlite3.Connection, source_db: str,
                         report: ArchiveSyncReport, *,
                         simulate_crash_before_commit: bool,
                         clock) -> None:
    now = int(clock())
    cur = archive_conn.execute(
        "INSERT INTO sync_runs (started_at, source_events, imported, adopted,"
        " non_archive, invalid) VALUES (?, 0, 0, 0, 0, 0)",
        (now,),
    )
    run_id = int(cur.lastrowid)

    # 源库：一个只读读事务里取快照。
    source_conn = connect_source_readonly(source_db)
    affected: set[tuple[str, str]] = set()
    try:
        source_conn.execute("BEGIN")
        try:
            rows = source_conn.execute(_SOURCE_EVENTS_SQL).fetchall()
        finally:
            source_conn.execute("COMMIT")
        for row in rows:
            report.source_events += 1
            partner_id = row["partner_id"]
            event_id = row["event_id"]
            already = archive_conn.execute(
                "SELECT 1 FROM archive_events WHERE partner_id = ? AND event_id = ?",
                (partner_id, event_id),
            ).fetchone()
            if already is not None:
                continue  # 重复同步是无操作，不重复登记。
            report.imported += 1
            blob = bytes(row["body_blob"])
            digest = row["body_sha256"]
            actual_digest = hashlib.sha256(blob).hexdigest()
            if actual_digest != digest:
                _insert_event(
                    archive_conn, row, blob, now,
                    document_id="", kind=None, revision=None,
                    base_revision=None, disposition=DISP_INVALID,
                    reason_code="digest_mismatch",
                    reason="正文与接收库登记的 SHA-256 摘要不符，拒绝加工",
                )
                report.invalid += 1
                continue
            try:
                root = parse_strict_json(blob)
            except JsonBodyError as exc:
                # 解析失败（含重复键）：指明事件，按约定不符/非档案登记。
                code = DISP_INVALID if exc.code == "duplicate_key" else DISP_NON_ARCHIVE
                reason_code = exc.code
                _insert_event(
                    archive_conn, row, blob, now,
                    document_id="", kind=None, revision=None,
                    base_revision=None, disposition=code,
                    reason_code=reason_code, reason=exc.message,
                )
                _count(report, code)
                continue
            parsed = validate_envelope(root)
            if isinstance(parsed, EnvelopeFailure):
                doc_id = root.values.get("document_id")
                _insert_event(
                    archive_conn, row, blob, now,
                    document_id=doc_id if isinstance(doc_id, str) else "",
                    kind=None, revision=None, base_revision=None,
                    disposition=parsed.code, reason_code="envelope",
                    reason=parsed.reason,
                )
                _count(report, parsed.code)
                if isinstance(doc_id, str):
                    affected.add((partner_id, doc_id))
                continue
            # 档案类正文：全文进入加工库自有缓存（重算不再依赖源库在线）。
            archive_conn.execute(
                "INSERT OR IGNORE INTO archive_bodies (body_sha256, body_blob,"
                " byte_length) VALUES (?, ?, ?)",
                (digest, blob, len(blob)),
            )
            _insert_event(
                archive_conn, row, blob, now,
                document_id=parsed.document_id, kind=parsed.kind,
                revision=parsed.revision,
                base_revision=parsed.base_revision,
                disposition=DISP_WAITING, reason_code=None,
                reason="新导入，待重算",
            )
            affected.add((partner_id, parsed.document_id))
    finally:
        source_conn.close()

    # 重算所有受影响档案（含新分支影响到的旧档案）。
    counts: dict[str, int] = {}
    for partner_id, document_id in sorted(affected):
        result = recompute_document(archive_conn, partner_id, document_id, now=now)
        report.recomputed_documents += 1
        for code, n in result.counts.items():
            counts[code] = counts.get(code, 0) + n
        report.documents[f"{partner_id}/{document_id}"] = {
            "current_revision": result.current_revision,
            "state": result.state,
            "chain": result.chain,
        }
    for code, n in counts.items():
        setattr(report, _report_attr(code),
                getattr(report, _report_attr(code)) + n)

    if simulate_crash_before_commit:
        import sys

        staged = archive_conn.execute(
            "SELECT COUNT(*) FROM archive_events"
        ).fetchone()[0]
        sys.stderr.write(
            f"[simulate-crash] run={run_id} 已登记 {staged} 条、档案内容已更新但"
            "尚未提交，进程强制退出\n"
        )
        sys.stderr.flush()
        os._exit(97)

    archive_conn.execute(
        "UPDATE sync_runs SET committed_at = ?, source_events = ?, imported = ?,"
        " adopted = ?, non_archive = ?, invalid = ? WHERE id = ?",
        (now, report.source_events, report.imported, report.adopted,
         report.non_archive, report.invalid, run_id),
    )


def _report_attr(code: str) -> str:
    return {
        DISP_ADOPTED: "adopted",
        DISP_WAITING: "waiting",
        DISP_BRANCH_UNRESOLVED: "branch_unresolved",
        DISP_NOT_SELECTED: "not_selected",
        DISP_OP_FAILED: "operation_failed",
        DISP_BLOCKED: "blocked",
    }[code]


_REPORT_ATTRS = {
    DISP_ADOPTED: "adopted",
    DISP_WAITING: "waiting",
    DISP_BRANCH_UNRESOLVED: "branch_unresolved",
    DISP_NOT_SELECTED: "not_selected",
    DISP_OP_FAILED: "operation_failed",
    DISP_BLOCKED: "blocked",
    DISP_NON_ARCHIVE: "non_archive",
    DISP_INVALID: "invalid",
}


def _count(report: ArchiveSyncReport, code: str) -> None:
    attr = _REPORT_ATTRS[code]
    setattr(report, attr, getattr(report, attr) + 1)


def _insert_event(archive_conn: sqlite3.Connection, row: sqlite3.Row,
                  blob: bytes, now: int, *, document_id: str, kind,
                  revision, base_revision, disposition: str,
                  reason_code, reason: str, failed_op=None,
                  failed_pointer=None) -> None:
    archive_conn.execute(
        "INSERT INTO archive_events (partner_id, event_id, document_id,"
        " source_seq, body_sha256, byte_length, body_preview, kind, revision,"
        " base_revision, disposition, reason_code, reason, failed_op,"
        " failed_pointer, imported_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (row["partner_id"], row["event_id"], document_id,
         int(row["source_seq"]), row["body_sha256"], len(blob),
         body_preview(blob), kind, revision, base_revision, disposition,
         reason_code, reason, failed_op, failed_pointer, now),
    )


# --------------------------------------------------------------------- #
# 单档案重算：分支判定 + 沿修订链接执行
# --------------------------------------------------------------------- #
@dataclass
class RecomputeResult:
    current_revision: int | None
    state: str                    # present / absent / none
    chain: list
    counts: dict


def _load_candidates(archive_conn: sqlite3.Connection, partner_id: str,
                     document_id: str) -> dict[int, list[sqlite3.Row]]:
    rows = archive_conn.execute(
        "SELECT * FROM archive_events WHERE partner_id = ? AND document_id = ?"
        " AND kind IS NOT NULL ORDER BY source_seq ASC, event_id ASC",
        (partner_id, document_id),
    ).fetchall()
    candidates: dict[int, list[sqlite3.Row]] = {}
    for row in rows:
        candidates.setdefault(int(row["revision"]), []).append(row)
    return candidates


def recompute_document(archive_conn: sqlite3.Connection, partner_id: str,
                       document_id: str, *, now: int | None = None) -> RecomputeResult:
    """按当前候选事件与人工选择，重算一份档案的处置与公布内容。

    只公布从唯一（或已选择）seed 出发、每一跳均无分支且执行成功的最长前缀。
    所有处置写回 ``archive_events``，当前内容写入 ``documents``；调用方负责
    事务边界。处置结论同时保存在内存 ``states`` 里——``sqlite3.Row`` 是加载
    时的快照，读不到同事务内刚 UPDATE 的值，不能用它判断最新状态。
    """
    if now is None:
        now = int(time.time())
    candidates = _load_candidates(archive_conn, partner_id, document_id)
    selections = {
        int(row["revision"]): row["event_id"]
        for row in archive_conn.execute(
            "SELECT revision, event_id FROM revisions_selected"
            " WHERE partner_id = ? AND document_id = ?",
            (partner_id, document_id),
        )
    }

    # event_id -> 最新处置结论（内存真值；先全部置等待）。
    states: dict[str, dict] = {}
    for rows in candidates.values():
        for row in rows:
            states[row["event_id"]] = {
                "disposition": DISP_WAITING, "reason_code": None,
                "reason": "重算中", "failed_op": None,
                "failed_pointer": None,
            }

    def mark(row: sqlite3.Row, disposition: str, *, reason_code: str | None,
             reason: str, failed_op=None, failed_pointer=None) -> None:
        archive_conn.execute(
            "UPDATE archive_events SET disposition = ?, reason_code = ?,"
            " reason = ?, failed_op = ?, failed_pointer = ?"
            " WHERE partner_id = ? AND event_id = ?",
            (disposition, reason_code, reason, failed_op, failed_pointer,
             partner_id, row["event_id"]),
        )
        states[row["event_id"]] = {
            "disposition": disposition, "reason_code": reason_code,
            "reason": reason, "failed_op": failed_op,
            "failed_pointer": failed_pointer,
        }

    counts: dict[str, int] = {}

    def tally(code: str) -> None:
        counts[code] = counts.get(code, 0) + 1

    # 没有任何 seed：全部等待（patch 永远等不到，也保持等待前版）。
    if 0 not in candidates:
        for revision in sorted(candidates):
            if revision == 0:
                continue
            for row in candidates[revision]:
                mark(row, DISP_WAITING, reason_code="missing_seed",
                     reason="尚未收到 seed（revision=0），等待建档")
                tally(DISP_WAITING)
        return _publish(archive_conn, partner_id, document_id, None, "none",
                        [], counts, now)

    # 选定每个修订的「有效候选」：人工选择优先，否则唯一候选，否则分支。
    chosen: dict[int, sqlite3.Row] = {}
    for revision, rows in candidates.items():
        selected_id = selections.get(revision)
        if selected_id is not None:
            match = next((r for r in rows if r["event_id"] == selected_id), None)
            if match is None:
                # 选择对应的事件已不在候选（正常不会发生：事件不删除）；
                # 保守按分支处理，不改任何其他状态。
                for row in rows:
                    mark(row, DISP_BRANCH_UNRESOLVED,
                         reason_code="stale_selection",
                         reason=f"已选事件 {selected_id} 不在当前候选中")
                    tally(DISP_BRANCH_UNRESOLVED)
                continue
            chosen[revision] = match
            for row in rows:
                if row["event_id"] == selected_id:
                    continue
                mark(row, DISP_NOT_SELECTED, reason_code="other_selected",
                     reason=f"修订 {revision} 已人工选择事件 {selected_id}")
                tally(DISP_NOT_SELECTED)
        elif len(rows) == 1:
            chosen[revision] = rows[0]
        else:
            for row in rows:
                mark(row, DISP_BRANCH_UNRESOLVED,
                     reason_code="multiple_candidates",
                     reason=f"修订 {revision} 存在 {len(rows)} 个竞争源事件，"
                            "需人工选择")
                tally(DISP_BRANCH_UNRESOLVED)

    # 沿修订链从 0 开始行走；任一非干净节点终止公布。
    chain: list[dict] = []
    current = UNBORN
    current_revision: int | None = None
    revision = 0
    halt: str | None = None  # "waiting"（缺事件）/ "blocked"（分支或失败）
    while True:
        row = chosen.get(revision)
        if row is None:
            # 该修订没有有效候选：有候选即分支未选（阻断），否则是等待来件。
            halt = "blocked" if revision in candidates else "waiting"
            break
        if revision == 0:
            if row["kind"] != "seed":
                mark(row, DISP_INVALID, reason_code="not_a_seed",
                     reason="revision=0 的事件不是 seed")
                tally(DISP_INVALID)
                _block_successors(chosen, revision, mark, tally, states)
                halt = "blocked"
                break
            current = _seed_document(row, archive_conn)
        else:
            if row["kind"] != "patch":
                mark(row, DISP_INVALID, reason_code="not_a_patch",
                     reason=f"修订 {revision} 的事件不是 patch")
                tally(DISP_INVALID)
                _block_successors(chosen, revision, mark, tally, states)
                halt = "blocked"
                break
            operations = _load_operations(row, archive_conn)
            try:
                current = apply_patch(current, operations)
            except PatchError as exc:
                mark(row, DISP_OP_FAILED,
                     reason_code=exc.code,
                     reason=f"第 {exc.op_number()} 个操作失败（位置 "
                            f"{exc.pointer or '<根>'}）：{exc.message}",
                     failed_op=exc.op_number(), failed_pointer=exc.pointer)
                tally(DISP_OP_FAILED)
                _block_successors(chosen, revision, mark, tally, states)
                halt = "blocked"
                break
        mark(row, DISP_ADOPTED, reason_code=None,
             reason=f"已采用为修订 {revision}")
        tally(DISP_ADOPTED)
        chain.append({
            "revision": revision,
            "event_id": row["event_id"],
            "kind": row["kind"],
        })
        current_revision = revision
        revision += 1

    # 链上未走到、且还没有分支/失败类结论的候选：按停止原因给等待或阻断。
    tip = current_revision if current_revision is not None else -1
    for later_revision in sorted(chosen):
        if later_revision <= tip:
            continue
        row = chosen[later_revision]
        if states[row["event_id"]]["disposition"] in (
                DISP_NOT_SELECTED, DISP_BRANCH_UNRESOLVED, DISP_OP_FAILED,
                DISP_BLOCKED, DISP_INVALID):
            continue
        if halt == "waiting":
            mark(row, DISP_WAITING, reason_code="missing_predecessor",
                 reason=f"修订 {later_revision} 的前一修订尚未到齐，等待前版")
            tally(DISP_WAITING)
        else:
            mark(row, DISP_BLOCKED, reason_code="chain_break",
                 reason=f"修订 {later_revision} 之前存在未解决分支或失败，"
                        "被前方阻断")
            tally(DISP_BLOCKED)

    if current is UNBORN:
        return _publish(archive_conn, partner_id, document_id, None, "none",
                        chain, counts, now)
    if current is MISSING:
        return _publish(archive_conn, partner_id, document_id,
                        current_revision, "absent", chain, counts, now)
    return _publish(archive_conn, partner_id, document_id, current_revision,
                    "present", chain, counts, now, content=current)


def _block_successors(chosen, failed_revision, mark, tally,
                      states: dict[str, dict]) -> None:
    """失败/无效修订之后的已选候选一律标为被前方阻断（不能跳过接下一版）。"""
    for later in sorted(chosen):
        if later <= failed_revision:
            continue
        row = chosen[later]
        if states[row["event_id"]]["disposition"] in (
                DISP_NOT_SELECTED, DISP_BRANCH_UNRESOLVED):
            continue
        mark(row, DISP_BLOCKED, reason_code="predecessor_failed",
             reason=f"前驱修订 {failed_revision} 未进入公布链，本修订被阻断")
        tally(DISP_BLOCKED)


def _publish(archive_conn, partner_id, document_id, current_revision, state,
             chain, counts, now, *, content=None) -> RecomputeResult:
    content_json = None
    if state == "present":
        content_json = dumps_exact(content)
    archive_conn.execute(
        "INSERT INTO documents (partner_id, document_id, current_revision,"
        " state, content_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(partner_id, document_id) DO UPDATE SET"
        " current_revision = excluded.current_revision,"
        " state = excluded.state, content_json = excluded.content_json,"
        " updated_at = excluded.updated_at",
        (partner_id, document_id, current_revision, state, content_json, now),
    )
    return RecomputeResult(current_revision=current_revision, state=state,
                           chain=chain, counts=counts)


def _to_mutable(value: Any) -> Any:
    """把严格值模型转成补丁引擎使用的普通可变容器（dict/list）。

    ``RawNumber`` 与标量不可变，原样保留；这样 jsonpatch 只面对 dict/list，
    深拷贝与 ``isinstance(..., dict)`` 判断都成立。
    """
    if isinstance(value, JsonObject):
        return {key: _to_mutable(item) for key, item in value.values.items()}
    if isinstance(value, list):
        return [_to_mutable(item) for item in value]
    return value


def _seed_document(row: sqlite3.Row,
                   archive_conn: sqlite3.Connection):
    """从已登记正文重新解析 seed 的 document（精确值模型，转普通容器）。"""
    blob = _read_blob(archive_conn, row["body_sha256"])
    root = parse_strict_json(blob)
    return _to_mutable(root.values["document"])


def _load_operations(row: sqlite3.Row, archive_conn: sqlite3.Connection):
    blob = _read_blob(archive_conn, row["body_sha256"])
    root = parse_strict_json(blob)
    return _to_mutable(list(root.values["operations"]))


def _read_blob(archive_conn: sqlite3.Connection, body_sha256: str) -> bytes:
    # 加工库不保存正文全文（只保存摘要/预览）；需要重放时从源库正文缓存表
    # 取——为保持加工库自包含，同步时把档案类正文另存到 archive_bodies。
    row = archive_conn.execute(
        "SELECT body_blob FROM archive_bodies WHERE body_sha256 = ?",
        (body_sha256,),
    ).fetchone()
    if row is None:  # pragma: no cover - 同步路径保证写入
        raise ArchiveError(f"加工库缺少正文缓存 {body_sha256}")
    return bytes(row["body_blob"])


# --------------------------------------------------------------------- #
# 人工选择 / 撤销
# --------------------------------------------------------------------- #
def select_revision(*, archive_db: str, partner_id: str, document_id: str,
                    revision: int, event_id: str,
                    clock=time.time) -> dict:
    """按坐标选择要采用的源事件 ID；选择必须存在且属于该坐标。

    错误选择不改任何状态（抛 :class:`ArchiveError`）。选择持久化后立即重算
    该档案；选择、撤销与新来件都只能影响本合作方的对应档案。
    """
    conn = connect_archive(archive_db)
    try:
        ensure_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = _select_in_transaction(
                conn, partner_id, document_id, revision, event_id,
                now=int(clock()),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return result


def _select_in_transaction(conn, partner_id, document_id, revision, event_id,
                           *, now) -> dict:
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise ArchiveError("revision 必须是非负整数且不是布尔值")
    row = conn.execute(
        "SELECT * FROM archive_events WHERE partner_id = ? AND event_id = ?",
        (partner_id, event_id),
    ).fetchone()
    if row is None:
        raise ArchiveError(
            f"合作方 {partner_id!r} 下不存在事件 {event_id!r}；选择未登记，"
            "不改变任何状态")
    if row["document_id"] != document_id or row["revision"] != revision \
            or row["kind"] is None:
        raise ArchiveError(
            f"事件 {event_id!r} 不属于坐标 ({partner_id!r}, {document_id!r},"
            f" 修订 {revision})；选择无效，不改变任何状态")
    conn.execute(
        "INSERT INTO revisions_selected (partner_id, document_id, revision,"
        " event_id, selected_at) VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(partner_id, document_id, revision) DO UPDATE SET"
        " event_id = excluded.event_id, selected_at = excluded.selected_at",
        (partner_id, document_id, revision, event_id, now),
    )
    result = recompute_document(conn, partner_id, document_id, now=now)
    return {
        "partner_id": partner_id, "document_id": document_id,
        "revision": revision, "selected_event_id": event_id,
        "current_revision": result.current_revision, "state": result.state,
        "chain": result.chain,
    }


def deselect_revision(*, archive_db: str, partner_id: str, document_id: str,
                      revision: int) -> dict:
    """撤销某修订的人工选择，使其恢复无偏好的分支判定。

    坐标上没有选择时不改任何状态；撤销后立即重算。
    """
    conn = connect_archive(archive_db)
    try:
        ensure_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        try:
            if not isinstance(revision, int) or isinstance(revision, bool) \
                    or revision < 0:
                raise ArchiveError("revision 必须是非负整数且不是布尔值")
            row = conn.execute(
                "SELECT 1 FROM revisions_selected WHERE partner_id = ?"
                " AND document_id = ? AND revision = ?",
                (partner_id, document_id, revision),
            ).fetchone()
            if row is None:
                raise ArchiveError(
                    f"坐标 ({partner_id!r}, {document_id!r}, 修订 {revision}) "
                    "没有人工选择可撤销；不改变任何状态")
            conn.execute(
                "DELETE FROM revisions_selected WHERE partner_id = ?"
                " AND document_id = ? AND revision = ?",
                (partner_id, document_id, revision),
            )
            now = int(time.time())
            result = recompute_document(conn, partner_id, document_id, now=now)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return {
        "partner_id": partner_id, "document_id": document_id,
        "revision": revision, "deselected": True,
        "current_revision": result.current_revision, "state": result.state,
        "chain": result.chain,
    }


# --------------------------------------------------------------------- #
# 读取接口
# --------------------------------------------------------------------- #
def get_current_document(archive_db: str, partner_id: str,
                         document_id: str) -> dict:
    """查看当前公布档案；从未建立或无公布内容时明确区分状态。"""
    conn = connect_archive(archive_db, read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM documents WHERE partner_id = ? AND document_id = ?",
            (partner_id, document_id),
        ).fetchone()
        if row is None:
            return {
                "partner_id": partner_id, "document_id": document_id,
                "published": False, "state": "none",
                "current_revision": None, "document": None, "chain": [],
            }
        chain = [
            {"revision": r["revision"], "event_id": r["event_id"],
             "kind": r["kind"]}
            for r in conn.execute(
                "SELECT revision, event_id, kind FROM archive_events"
                " WHERE partner_id = ? AND document_id = ?"
                " AND disposition = ? ORDER BY revision",
                (partner_id, document_id, DISP_ADOPTED),
            )
        ]
        document = None
        if row["state"] == "present":
            document = parse_strict_json(row["content_json"])
            document = _to_plain(document)
        return {
            "partner_id": partner_id, "document_id": document_id,
            "published": True, "state": row["state"],
            "current_revision": row["current_revision"],
            "document": document, "chain": chain,
        }
    finally:
        conn.close()


def list_dispositions(archive_db: str, partner_id: str | None = None,
                      document_id: str | None = None) -> list[dict]:
    """查看来件处置（可按合作方/档案过滤），含失败操作与指针。"""
    sql = ("SELECT partner_id, event_id, document_id, source_seq, kind,"
           " revision, base_revision, disposition, reason_code, reason,"
           " failed_op, failed_pointer, body_sha256, byte_length,"
           " body_preview, imported_at FROM archive_events WHERE 1=1")
    params: list = []
    if partner_id is not None:
        sql += " AND partner_id = ?"
        params.append(partner_id)
    if document_id is not None:
        sql += " AND document_id = ?"
        params.append(document_id)
    sql += " ORDER BY partner_id, document_id, revision, source_seq, event_id"
    conn = connect_archive(archive_db, read_only=True)
    try:
        rows = conn.execute(sql, params).fetchall()
        return [_disposition_dict(r) for r in rows]
    finally:
        conn.close()


def list_revisions(archive_db: str, partner_id: str,
                   document_id: str) -> dict:
    """查看一份档案的修订处置、分支候选与人工选择（修订视角）。"""
    conn = connect_archive(archive_db, read_only=True)
    try:
        events = [
            _disposition_dict(r) for r in conn.execute(
                "SELECT * FROM archive_events WHERE partner_id = ?"
                " AND document_id = ? AND kind IS NOT NULL"
                " ORDER BY revision, source_seq, event_id",
                (partner_id, document_id),
            )
        ]
        selections = {
            int(r["revision"]): r["event_id"]
            for r in conn.execute(
                "SELECT revision, event_id FROM revisions_selected"
                " WHERE partner_id = ? AND document_id = ?",
                (partner_id, document_id),
            )
        }
        doc = conn.execute(
            "SELECT * FROM documents WHERE partner_id = ? AND document_id = ?",
            (partner_id, document_id),
        ).fetchone()
        return {
            "partner_id": partner_id, "document_id": document_id,
            "selections": selections,
            "current_revision": doc["current_revision"] if doc else None,
            "state": doc["state"] if doc else "none",
            "events": events,
        }
    finally:
        conn.close()


def _disposition_dict(row: sqlite3.Row) -> dict:
    code = row["disposition"]
    return {
        "partner_id": row["partner_id"], "event_id": row["event_id"],
        "document_id": row["document_id"], "source_seq": row["source_seq"],
        "kind": row["kind"], "revision": row["revision"],
        "base_revision": row["base_revision"],
        "disposition": code,
        "disposition_text": DISPOSITION_TEXT.get(code, code),
        "reason_code": row["reason_code"], "reason": row["reason"],
        "failed_op": row["failed_op"], "failed_pointer": row["failed_pointer"],
        "body_sha256": row["body_sha256"], "byte_length": row["byte_length"],
        "body_preview": row["body_preview"], "imported_at": row["imported_at"],
    }


class ExactNumber:
    """CLI 输出用：包一层让数字以原始十进制文本落盘，不经过 float。"""

    def __init__(self, text: str):
        self.text = text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ExactNumber) and other.text == self.text

    def __hash__(self) -> int:
        return hash(("ExactNumber", self.text))

    def __repr__(self) -> str:
        return f"ExactNumber({self.text!r})"


def _to_plain(value: Any) -> Any:
    """把严格值模型转成普通 Python 值供 CLI JSON 输出（数字保持精确文本）。"""
    if isinstance(value, JsonObject):
        return {key: _to_plain(item) for key, item in value.values.items()}
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    if isinstance(value, RawNumber):
        return ExactNumber(value.text)
    return value


def dumps_plain(value: Any, *, indent: int = 2) -> str:
    """序列化 :func:`_to_plain` 的结果，:class:`ExactNumber` 输出原文数字。"""
    level = 0

    def emit(node: Any, depth: int) -> str:
        pad = "\n" + " " * (indent * (depth + 1))
        end_pad = "\n" + " " * (indent * depth)
        if isinstance(node, ExactNumber):
            return node.text
        if node is None:
            return "null"
        if node is True:
            return "true"
        if node is False:
            return "false"
        if isinstance(node, str):
            return _json_string(node)
        if isinstance(node, dict):
            if not node:
                return "{}"
            items = [
                f"{pad}{_json_string(key)}: {emit(item, depth + 1)}"
                for key, item in node.items()
            ]
            return "{" + ",".join(items) + end_pad + "}"
        if isinstance(node, list):
            if not node:
                return "[]"
            items = [f"{pad}{emit(item, depth + 1)}" for item in node]
            return "[" + ",".join(items) + end_pad + "]"
        # 普通 int/float 兜底（加工链本身不产生 float）。
        return json.dumps(node, ensure_ascii=False)

    return emit(value, level)


__all__ = [
    "ArchiveError", "ArchiveSyncReport", "DISP_ADOPTED", "DISP_WAITING",
    "DISP_BRANCH_UNRESOLVED", "DISP_NOT_SELECTED", "DISP_OP_FAILED",
    "DISP_BLOCKED", "DISP_NON_ARCHIVE", "DISP_INVALID",
    "DISPOSITION_TEXT", "ExactNumber", "ParsedEnvelope", "EnvelopeFailure",
    "connect_archive", "connect_source_readonly", "deselect_revision",
    "dumps_exact", "dumps_plain", "ensure_schema", "get_current_document",
    "list_dispositions", "list_revisions", "recompute_document",
    "select_revision", "sync_archive", "validate_envelope",
]
