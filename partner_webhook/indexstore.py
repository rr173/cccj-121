"""持久 JSON 正文索引（本地分析用）。

索引数据库与在线接收数据库**完全分离**：接收库只以只读连接打开，索引库由本
模块建立。这样查询不依赖源库，也不会因索引维护写坏在线接收库。

数据模型
--------

``index_generations`` 每次同步产生一代；只有 ``status='published'`` 且被
``index_meta.current_generation`` 指向的一代对查询可见。新一代在**同一个
索引事务**里完成「节点写入 → 事件登记 → 发布」，事务提交前旧一代始终完整
可查；进程在任意时刻退出，未提交的新一代整体回滚。

``parsed_bodies`` 以 ``(body_sha256, parser_version)`` 缓存正文解释结果（含
跳过原因），并记下核验时的正文长度；复用时要求长度仍与本轮登记一致。同摘要
被多个事件引用时只解析一次；重复同步不会重复解析未变化的正文，也不会产生
重复节点。

``events`` 记录每个合作方的事件及其正文摘要与可查询状态；``nodes`` 保存
「路径、类型、数组实例关系」。数组元素的 ``parent_id`` 指向数组节点，
``field_name`` 为 NULL，因此路径中的任何字符串段都不会跨过数组。
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from .strictjson import (
    PARSER_VERSION,
    JsonBodyError,
    Node,
    collect_nodes,
    read_json_body,
)

INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS index_generations (
    generation     INTEGER PRIMARY KEY,
    status         TEXT NOT NULL,              -- staging / published
    parser_version INTEGER NOT NULL,
    created_at     INTEGER NOT NULL,
    published_at   INTEGER,
    source_events  INTEGER,
    indexed_events INTEGER,
    skipped_events INTEGER,
    source_identity TEXT
);

CREATE TABLE IF NOT EXISTS parsed_bodies (
    body_sha256    TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    byte_length    INTEGER NOT NULL,
    status         TEXT NOT NULL,              -- indexed / skipped
    reason_code    TEXT,
    reason         TEXT,
    node_count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (body_sha256, parser_version)
);

CREATE TABLE IF NOT EXISTS events (
    generation     INTEGER NOT NULL,
    partner_id     TEXT NOT NULL,
    event_id       TEXT NOT NULL,
    source_seq     INTEGER NOT NULL,
    body_sha256    TEXT NOT NULL,
    byte_length    INTEGER NOT NULL,
    parser_version INTEGER NOT NULL,
    status         TEXT NOT NULL,              -- indexed / skipped
    reason_code    TEXT,
    reason         TEXT,
    node_count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (generation, partner_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_index_events_partner
    ON events (generation, partner_id, status);
CREATE INDEX IF NOT EXISTS idx_index_events_body
    ON events (body_sha256, parser_version);

-- 节点按 (正文摘要, 解析器版本) 共享；同摘要的多个事件引用同一批节点。
CREATE TABLE IF NOT EXISTS nodes (
    body_sha256    TEXT NOT NULL,
    parser_version INTEGER NOT NULL,
    node_id        INTEGER NOT NULL,
    parent_id      INTEGER,
    field_name     TEXT,                       -- 数组元素为 NULL
    path           TEXT NOT NULL,              -- 长度前缀编码，仅供核对
    json_type      TEXT NOT NULL,
    array_instance INTEGER,                    -- 直接包含该值的数组节点 ID
    num_neg        INTEGER,
    num_digits     TEXT,
    num_exp        TEXT,                       -- 十进制文本，1e400 不丢精度
    str_value      TEXT,
    bool_value     INTEGER,
    PRIMARY KEY (body_sha256, parser_version, node_id)
);

CREATE INDEX IF NOT EXISTS idx_nodes_parent
    ON nodes (body_sha256, parser_version, parent_id);
CREATE INDEX IF NOT EXISTS idx_nodes_field
    ON nodes (body_sha256, parser_version, field_name);
CREATE INDEX IF NOT EXISTS idx_nodes_path
    ON nodes (body_sha256, parser_version, path);
"""


class IndexError_(Exception):
    """索引维护失败（整体回滚，不产生半代索引）。"""


# --------------------------------------------------------------------- #
# 连接
# --------------------------------------------------------------------- #
def _quote_uri_path(path: str) -> str:
    from urllib.parse import quote

    return "file:" + quote(str(Path(path).resolve()), safe="/")


def connect_index(path: str, *, read_only: bool = False) -> sqlite3.Connection:
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
    """只读打开在线接收库（``mode=ro`` + ``query_only``）。"""
    uri = _quote_uri_path(path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(INDEX_SCHEMA)
    row = conn.execute(
        "SELECT value FROM index_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO index_meta(key, value) VALUES ('schema_version', '1')"
        )


# --------------------------------------------------------------------- #
# 同步
# --------------------------------------------------------------------- #
@dataclass
class SyncReport:
    generation: int
    previous_generation: int | None
    parser_version: int
    source_events: int = 0
    indexed_events: int = 0
    skipped_events: int = 0
    added: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: int = 0
    parsed_bodies: int = 0
    reused_bodies: int = 0
    skipped: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "generation": self.generation,
            "previous_generation": self.previous_generation,
            "parser_version": self.parser_version,
            "source_events": self.source_events,
            "indexed_events": self.indexed_events,
            "skipped_events": self.skipped_events,
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "unchanged": self.unchanged,
            "parsed_bodies": self.parsed_bodies,
            "reused_bodies": self.reused_bodies,
            "skipped": self.skipped,
        }


_SOURCE_EVENTS_SQL = """
SELECT ae.partner_id, ae.event_id, ae.source_seq, ae.body_sha256,
       rb.body_blob, rb.byte_length AS registered_length,
       length(rb.body_blob) AS stored_length
FROM accepted_events ae
LEFT JOIN raw_bodies rb ON rb.body_sha256 = ae.body_sha256
ORDER BY ae.partner_id ASC, ae.event_id ASC
"""


def _event_key(partner_id: str, event_id: str) -> str:
    return f"{partner_id}/{event_id}"


def sync_index(*, source_db: str, index_db: str,
               simulate_crash_after_nodes: bool = False,
               clock=time.time) -> SyncReport:
    """全量扫描源事件集合并发布新一代索引。

    源库在一个只读读事务内取快照；索引侧写入全部在**同一个写事务**中，
    最后一步才是发布。任何异常（包括进程中途退出）都不会留下可查询的半代
    索引，也不会触碰源库。
    """
    report: SyncReport
    index_conn = connect_index(index_db)
    if simulate_crash_after_nodes:
        # 让脏页更早落到 WAL，崩溃演示更有说服力；不影响事务原子性。
        index_conn.execute("PRAGMA cache_size = -32")
        index_conn.execute("PRAGMA wal_autocheckpoint = 0")
    try:
        ensure_schema(index_conn)
        index_conn.execute("BEGIN IMMEDIATE")
        try:
            report = _sync_in_transaction(
                index_conn, source_db,
                simulate_crash_after_nodes=simulate_crash_after_nodes,
                clock=clock,
            )
            index_conn.execute("COMMIT")
        except BaseException:
            try:
                index_conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
    finally:
        index_conn.close()
    return report


def _sync_in_transaction(index_conn: sqlite3.Connection, source_db: str, *,
                         simulate_crash_after_nodes: bool,
                         clock) -> SyncReport:
    now = int(clock())
    meta = index_conn.execute(
        "SELECT value FROM index_meta WHERE key = 'current_generation'"
    ).fetchone()
    previous_generation = int(meta["value"]) if meta else None
    max_row = index_conn.execute(
        "SELECT COALESCE(MAX(generation), 0) AS g FROM index_generations"
    ).fetchone()
    generation = int(max_row["g"]) + 1

    previous_events: dict[str, tuple[str, str]] = {}
    if previous_generation is not None:
        for row in index_conn.execute(
            "SELECT partner_id, event_id, body_sha256, status FROM events "
            "WHERE generation = ?",
            (previous_generation,),
        ):
            previous_events[_event_key(row["partner_id"], row["event_id"])] = (
                row["body_sha256"], row["status"],
            )

    report = SyncReport(generation=generation,
                        previous_generation=previous_generation,
                        parser_version=PARSER_VERSION)
    index_conn.execute(
        "INSERT INTO index_generations "
        "(generation, status, parser_version, created_at)"
        " VALUES (?, 'staging', ?, ?)",
        (generation, PARSER_VERSION, now),
    )

    source_conn: sqlite3.Connection | None = None
    identity_hash = hashlib.sha256()
    cache: dict[tuple[str, int], tuple[str, str | None, str | None, int]] = {}
    current_keys: set[str] = set()
    try:
        source_conn = connect_source_readonly(source_db)
        source_conn.execute("BEGIN")
        cursor = source_conn.execute(_SOURCE_EVENTS_SQL)
        for row in cursor:
            partner_id = row["partner_id"]
            event_id = row["event_id"]
            digest = row["body_sha256"]
            key = _event_key(partner_id, event_id)
            current_keys.add(key)
            identity_hash.update(
                f"{partner_id}\x00{event_id}\x00{digest}\x00"
                f"{row['registered_length']}\x00".encode("utf-8")
            )
            report.source_events += 1

            prior = previous_events.get(key)
            if prior is None:
                report.added.append(key)
            elif prior[0] != digest:
                report.changed.append(key)

            blob = row["body_blob"]
            registered_length = row["registered_length"]
            if blob is None:
                status, code, reason, node_count = (
                    "skipped", "missing_body", "accepted_events 找不到对应正文", 0,
                )
            else:
                blob = bytes(blob)
                stored_length = int(row["stored_length"])
                length_ok = (registered_length is None
                             or int(registered_length) == stored_length)
                cache_key = (digest, registered_length)
                cached = cache.get(cache_key) if length_ok else None
                if cached is None and length_ok and registered_length is not None:
                    db_row = index_conn.execute(
                        "SELECT status, reason_code, reason, node_count,"
                        " byte_length FROM parsed_bodies"
                        " WHERE body_sha256 = ? AND parser_version = ?",
                        (digest, PARSER_VERSION),
                    ).fetchone()
                    # 只有长度也与本轮登记一致时才复用缓存；否则重新核对解析
                    if db_row is not None and \
                            int(db_row["byte_length"]) == int(registered_length):
                        cached = (db_row["status"], db_row["reason_code"],
                                  db_row["reason"], int(db_row["node_count"]))
                        cache[cache_key] = cached
                if cached is not None:
                    status, code, reason, node_count = cached
                    report.reused_bodies += 1
                elif not length_ok:
                    # 登记长度与存储字节数不一致：有正文却不满足核对条件，
                    # 逐条跳过，绝不用宽松解释顶上。
                    status, code, reason, node_count = (
                        "skipped", "length_mismatch",
                        f"存储正文 {stored_length} 字节与登记长度 "
                        f"{registered_length} 不符", 0,
                    )
                else:
                    status, code, reason, node_count = _parse_and_store(
                        index_conn, digest, blob,
                        registered_length=None if registered_length is None
                        else int(registered_length),
                        stored_length=stored_length,
                    )
                    cache[cache_key] = (status, code, reason, node_count)
                    report.parsed_bodies += 1

            if status == "indexed":
                report.indexed_events += 1
            else:
                report.skipped_events += 1
                report.skipped.append({
                    "partner_id": partner_id, "event_id": event_id,
                    "body_sha256": digest, "reason_code": code,
                    "reason": reason,
                })

            index_conn.execute(
                "INSERT INTO events (generation, partner_id, event_id,"
                " source_seq, body_sha256, byte_length, parser_version,"
                " status, reason_code, reason, node_count)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (generation, partner_id, event_id, int(row["source_seq"]),
                 digest, int(registered_length or 0), PARSER_VERSION,
                 status, code, reason, node_count),
            )
        source_conn.execute("COMMIT")
    except BaseException:
        if source_conn is not None:
            try:
                source_conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    finally:
        if source_conn is not None:
            source_conn.close()

    report.removed = sorted(set(previous_events) - current_keys)
    # 未变化的统计：仍在源表、摘要未变的事件数
    report.unchanged = report.source_events - len(report.added) - len(report.changed)

    if simulate_crash_after_nodes:
        # 演示/测试专用：此时节点与事件行都已写入当前事务但尚未提交。直接
        # 结束进程（不复位连接、不提交），SQLite 会丢弃未提交内容。
        staged_nodes = index_conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE body_sha256 IN "
            "(SELECT body_sha256 FROM events WHERE generation = ?)",
            (generation,),
        ).fetchone()[0]
        staged_events = index_conn.execute(
            "SELECT COUNT(*) FROM events WHERE generation = ?", (generation,)
        ).fetchone()[0]
        import sys

        sys.stderr.write(
            "[simulate-crash] generation=%d staged_events=%d staged_nodes=%d"
            " 尚未提交，进程强制退出\n"
            % (generation, staged_events, staged_nodes)
        )
        sys.stderr.flush()
        os._exit(97)

    # ---- 发布：更新状态与当前代，清理旧代（同一事务） ----------------
    source_identity = identity_hash.hexdigest()
    index_conn.execute(
        "UPDATE index_generations SET status = 'published', published_at = ?,"
        " source_events = ?, indexed_events = ?, skipped_events = ?,"
        " source_identity = ? WHERE generation = ?",
        (now, report.source_events, report.indexed_events,
         report.skipped_events, source_identity, generation),
    )
    index_conn.execute(
        "INSERT INTO index_meta(key, value) VALUES"
        " ('current_generation', ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(generation),),
    )
    index_conn.execute("DELETE FROM events WHERE generation <> ?", (generation,))
    index_conn.execute(
        "DELETE FROM index_generations WHERE generation <> ?", (generation,)
    )
    # 发布前清理：node/parsed_bodies 只保留本代事件实际引用的摘要。被移除
    # 或本次跳过的摘要不再有事件引用，其节点随发布一起消失；同摘要仍被其他
    # 事件引用时保持原样（共享、只读）。
    index_conn.execute(
        "DELETE FROM parsed_bodies WHERE NOT EXISTS ("
        " SELECT 1 FROM events e WHERE e.generation = ?"
        " AND e.body_sha256 = parsed_bodies.body_sha256"
        " AND e.parser_version = parsed_bodies.parser_version)",
        (generation,),
    )
    index_conn.execute(
        "DELETE FROM nodes WHERE NOT EXISTS ("
        " SELECT 1 FROM events e WHERE e.generation = ?"
        " AND e.body_sha256 = nodes.body_sha256"
        " AND e.parser_version = nodes.parser_version)",
        (generation,),
    )
    return report


def _parse_and_store(index_conn: sqlite3.Connection, digest: str, blob: bytes,
                     *, registered_length: int | None,
                     stored_length: int) -> tuple[str, str | None, str | None, int]:
    """核对摘要/长度、严格解释正文并写入节点。

    返回 ``(status, reason_code, reason, node_count)``。只有 ``JsonBodyError``
    是逐条跳过；其他异常向上抛，整代同步回滚。
    """
    try:
        root = read_json_body(
            blob, expected_sha256=digest,
            expected_length=registered_length
            if registered_length is not None else stored_length,
        )
        nodes = collect_nodes(root)
    except JsonBodyError as exc:
        # 逐条跳过。已发布的旧一代可能仍引用该摘要的节点；这里不改写节点，
        # 由发布时的引用清理决定去留，保证旧代查询在提交前不受影响。
        index_conn.execute(
            "INSERT OR REPLACE INTO parsed_bodies"
            " (body_sha256, parser_version, byte_length, status, reason_code,"
            "  reason, node_count) VALUES (?, ?, ?, 'skipped', ?, ?, 0)",
            (digest, PARSER_VERSION,
             registered_length if registered_length is not None else stored_length,
             exc.code, exc.message),
        )
        return "skipped", exc.code, exc.message, 0

    # 同一摘要的解析结果是确定的，节点 ID 也稳定；用 OR REPLACE 重放一遍
    # 是幂等的，不会产生重复节点，也不会让旧一代查询读到不同结构。
    rows = [
        (
            digest, PARSER_VERSION, node.node_id, node.parent_id,
            node.field_name, _encode_node_path(node), node.json_type,
            node.array_instance, node.num_neg, node.num_digits, node.num_exp,
            node.str_value, node.bool_value,
        )
        for node in nodes
    ]
    index_conn.executemany(
        "INSERT OR REPLACE INTO nodes"
        " (body_sha256, parser_version, node_id, parent_id,"
        " field_name, path, json_type, array_instance, num_neg, num_digits,"
        " num_exp, str_value, bool_value)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    index_conn.execute(
        "INSERT OR REPLACE INTO parsed_bodies"
        " (body_sha256, parser_version, byte_length, status, reason_code,"
        "  reason, node_count) VALUES (?, ?, ?, 'indexed', NULL, NULL, ?)",
        (digest, PARSER_VERSION,
         registered_length if registered_length is not None else stored_length,
         len(nodes)),
    )
    return "indexed", None, None, len(nodes)


def _encode_node_path(node: Node) -> str:
    from .strictjson import encode_path

    return encode_path(node.path)


# --------------------------------------------------------------------- #
# 状态 / 诊断
# --------------------------------------------------------------------- #
def index_status(index_db: str) -> dict:
    conn = connect_index(index_db, read_only=True)
    try:
        meta = {row["key"]: row["value"]
                for row in conn.execute("SELECT key, value FROM index_meta")}
        if "current_generation" not in meta:
            raise IndexError_("索引尚未发布任何一代")
        generation = int(meta["current_generation"])
        gen = conn.execute(
            "SELECT * FROM index_generations WHERE generation = ?",
            (generation,),
        ).fetchone()
        if gen is None:
            raise IndexError_("当前代元数据缺失")
        counts = {
            row["status"]: row["n"]
            for row in conn.execute(
                "SELECT status, COUNT(*) AS n FROM events"
                " WHERE generation = ? GROUP BY status",
                (generation,),
            )
        }
        skipped = [
            dict(row) for row in conn.execute(
                "SELECT partner_id, event_id, body_sha256, reason_code, reason"
                " FROM events WHERE generation = ? AND status = 'skipped'"
                " ORDER BY partner_id, event_id",
                (generation,),
            )
        ]
        bodies = conn.execute(
            "SELECT COUNT(*) FROM parsed_bodies"
        ).fetchone()[0]
        nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        return {
            "index_db": str(index_db),
            "generation": generation,
            "status": gen["status"],
            "parser_version": gen["parser_version"],
            "published_at": gen["published_at"],
            "source_events": gen["source_events"],
            "indexed_events": gen["indexed_events"],
            "skipped_events": gen["skipped_events"],
            "event_status_counts": counts,
            "skipped": skipped,
            "cached_bodies": bodies,
            "node_rows": nodes,
        }
    finally:
        conn.close()


__all__ = [
    "IndexError_", "SyncReport", "connect_index", "connect_source_readonly",
    "ensure_schema", "index_status", "sync_index",
]
