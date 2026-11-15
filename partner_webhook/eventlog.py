"""按合作方可验证追加账本（SQLite 持久节点 + 证明生成）。

承诺范围
--------
本账本只记录**接收端**的承诺：某个合作方的某条事件在某个前缀树长下确实
被本服务首次接受。它不证明下游已经收到数据，也不证明正文的业务真实性。

持久化模型
----------
* ``event_logs``：每个合作方一行。``log_id`` 在首次安装时随机生成并固定；
  ``tree_size`` 与 ``root_hash`` 为当前前缀的根。
* ``log_leaves``：叶位置、事件 ID、source_seq、正文摘要与叶哈希；叶位置从
  0 连续增长，与 source_seq 稀疏/倒序无关。
* ``log_nodes``：已形成的完整子树节点（``level`` = 子树高度，
  ``node_index`` = 起始叶位置 / 2^level）。追加一片新叶只插入受影响的
  O(log n) 个节点，旧节点从不改写。

并发与事务
----------
安装、追加叶子与接收事件同一写事务；两者都以 ``BEGIN IMMEDIATE`` 取得
SQLite 写锁，因此两个独立进程不能同时分配同一个叶序号，也不依赖进程内
线程锁。接收事务回滚时叶子与节点一并回滚，不会出现 accepted_events 已提交
而账本未记的分离状态。
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from . import merkle
from .merkle import (
    Checkpoint,
    ConsistencyProof,
    InclusionProof,
    MerkleError,
    PROTOCOL,
    hex32,
)

READ_ONLY_HINT = (
    "证明生成只读取 event_logs / log_nodes / log_leaves 的单行主键查询；"
    "不读取 accepted_events、ingest_records、raw_bodies，也不扫描任何表。"
)


class LedgerError(Exception):
    """账本操作被明确拒绝（安装校验失败、证明越界等）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class NotInstalled(LedgerError):
    def __init__(self, partner_id: str):
        super().__init__("not_installed",
                         f"合作方 {partner_id!r} 尚未安装事件账本")


# --------------------------------------------------------------------- #
# 连接与只读快照
# --------------------------------------------------------------------- #
def _quote_uri_path(path: str) -> str:
    return "file:" + quote(str(Path(path).resolve()), safe="/")


def connect_readonly(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(_quote_uri_path(db_path) + "?mode=ro", uri=True,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def connect_write(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


# --------------------------------------------------------------------- #
# 读计数（证明节点访问证据）
# --------------------------------------------------------------------- #
@dataclass
class ReadTrace:
    """一次操作对账本表的读取计量。

    计量范围：``log_nodes`` 与 ``log_leaves`` 的点查次数及返回行数、
    ``event_logs`` 元数据点查次数。每次点查都带 (partner_id, level,
    node_index) / (partner_id, leaf_index) 主键条件，不使用全表扫描。
    不含 SQLite 内部页读取、文件系统缓存与检查点/证明文件本身的读取。
    """

    meta_reads: int = 0
    node_queries: int = 0
    node_rows: int = 0
    leaf_queries: int = 0
    leaf_rows: int = 0
    statements: list[str] = field(default_factory=list)

    @property
    def node_reads(self) -> int:
        return self.node_queries + self.leaf_queries

    def as_dict(self) -> dict[str, Any]:
        return {
            "meta_reads": self.meta_reads,
            "node_queries": self.node_queries,
            "node_rows": self.node_rows,
            "leaf_queries": self.leaf_queries,
            "leaf_rows": self.leaf_rows,
            "node_reads": self.node_reads,
            "scope": READ_ONLY_HINT,
        }


class NodeReader:
    """按主键读取已持久化的节点与叶；所有读取都计入 trace。"""

    def __init__(self, conn: sqlite3.Connection, partner_id: str,
                 trace: ReadTrace):
        self.conn = conn
        self.partner_id = partner_id
        self.trace = trace

    def leaf(self, index: int) -> bytes:
        trace = self.trace
        trace.leaf_queries += 1
        trace.statements.append(
            "SELECT leaf_hash FROM log_leaves WHERE partner_id=? AND leaf_index=?")
        row = self.conn.execute(
            "SELECT leaf_hash FROM log_leaves WHERE partner_id = ?"
            " AND leaf_index = ?", (self.partner_id, index)).fetchone()
        if row is None:
            raise LedgerError("missing_leaf",
                              f"账本缺少叶位置 {index}；节点存储不完整")
        trace.leaf_rows += 1
        return merkle.parse_hex32(row["leaf_hash"], f"leaf[{index}].leaf_hash")

    def node(self, level: int, node_index: int) -> bytes:
        trace = self.trace
        trace.node_queries += 1
        trace.statements.append(
            "SELECT node_hash FROM log_nodes WHERE partner_id=? AND level=?"
            " AND node_index=?")
        row = self.conn.execute(
            "SELECT node_hash FROM log_nodes WHERE partner_id = ? AND level = ?"
            " AND node_index = ?",
            (self.partner_id, level, node_index)).fetchone()
        if row is None:
            raise LedgerError(
                "missing_node",
                f"账本缺少子树节点 level={level} index={node_index}；"
                "节点存储不完整")
        trace.node_rows += 1
        return merkle.parse_hex32(row["node_hash"],
                                  f"node[{level},{node_index}].node_hash")

    # -- 组合 ------------------------------------------------------- #
    def range_root(self, start: int, length: int) -> bytes:
        """区间 [start, start+length) 的规范树根。

        完全对齐的 2 次幂区间直接取持久节点（O(1)）；否则按同一递归切分，
        非完美一侧继续下降。对任意区间为 O(log length)。
        """
        if length == 0:
            return merkle.empty_root()
        if length == 1:
            return self.leaf(start)
        if length & (length - 1) == 0 and start % length == 0:
            level = length.bit_length() - 1
            return self.node(level, start >> level)
        k = merkle.split_size(length)
        return merkle.node_hash(self.range_root(start, k),
                                self.range_root(start + k, length - k))

    def prefix_root(self, size: int) -> bytes:
        """前缀 [0,size) 的根：按二进制块右结合折叠。"""
        if size == 0:
            return merkle.empty_root()
        blocks: list[tuple[int, int]] = []
        start = 0
        remaining = size
        while remaining:
            level = remaining.bit_length() - 1
            blocks.append((level, start >> level))
            start += 1 << level
            remaining -= 1 << level

        def fold(position: int) -> bytes:
            level, node_index = blocks[position]
            value = self.node(level, node_index)
            if position + 1 == len(blocks):
                return value
            return merkle.node_hash(value, fold(position + 1))

        return fold(0)

    def inclusion_path(self, size: int, index: int) -> list[bytes]:
        if index < 0 or index >= size:
            raise LedgerError("index_out_of_range",
                              f"叶位置 {index} 不在树长 {size} 内")
        path: list[bytes] = []

        def walk(start: int, length: int, offset: int) -> None:
            if length == 1:
                return
            k = merkle.split_size(length)
            if offset < k:
                walk(start, k, offset)
                path.append(self.range_root(start + k, length - k))
            else:
                walk(start + k, length - k, offset - k)
                path.append(self.range_root(start, k))

        walk(0, size, index)
        return path

    def consistency_path(self, old_size: int,
                         new_size: int) -> list[bytes]:
        if old_size < 0 or new_size < old_size:
            raise LedgerError("size_regression",
                              f"树长非法或倒退: {old_size} -> {new_size}")
        if old_size == 0 or old_size == new_size:
            return []
        path: list[bytes] = []

        def walk(start: int, length: int, m_old: int, b: bool) -> None:
            if m_old == length:
                if not b:
                    path.append(self.range_root(start, length))
                return
            k = merkle.split_size(length)
            if m_old <= k:
                walk(start, k, m_old, b)
                path.append(self.range_root(start + k, length - k))
            else:
                walk(start + k, length - k, m_old - k, False)
                path.append(self.range_root(start, k))

        walk(0, new_size, old_size, True)
        return path


# --------------------------------------------------------------------- #
# 元数据读取
# --------------------------------------------------------------------- #
def _meta(conn: sqlite3.Connection, partner_id: str,
          trace: ReadTrace) -> sqlite3.Row:
    trace.meta_reads += 1
    trace.statements.append(
        "SELECT log_id, protocol, tree_size, root_hash FROM event_logs"
        " WHERE partner_id=?")
    row = conn.execute(
        "SELECT log_id, protocol, tree_size, root_hash FROM event_logs"
        " WHERE partner_id = ?", (partner_id,)).fetchone()
    if row is None:
        raise NotInstalled(partner_id)
    return row


def event_log_exists(conn: sqlite3.Connection, partner_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM event_logs WHERE partner_id = ?",
        (partner_id,)).fetchone()
    return row is not None


def ledger_partners(conn: sqlite3.Connection) -> list[str]:
    return [row[0] for row in conn.execute(
        "SELECT partner_id FROM event_logs ORDER BY partner_id")]


# --------------------------------------------------------------------- #
# 叶编码校验
# --------------------------------------------------------------------- #
def leaf_fields(partner_id: str, event_id: str, source_seq: int,
                body_sha256: str) -> tuple[bytes, str]:
    """校验可编码性并返回 (叶原文, 规范化摘要小写)。"""
    try:
        preimage = merkle.leaf_preimage(partner_id, event_id,
                                        source_seq, body_sha256)
    except MerkleError as exc:
        raise LedgerError(exc.code, exc.message) from None
    return preimage, body_sha256.lower()


def validate_encodable(partner_id: str, event_id: str, source_seq: int,
                       body_sha256: str) -> None:
    """只校验、不产生任何数据。超范围时抛 LedgerError。"""
    leaf_fields(partner_id, event_id, source_seq, body_sha256)


# --------------------------------------------------------------------- #
# 追加一片叶子（在调用方的接收事务内）
# --------------------------------------------------------------------- #
def append_leaf(conn: sqlite3.Connection, *, partner_id: str, event_id: str,
                source_seq: int, body_sha256: str, now: int,
                trace: ReadTrace | None = None) -> dict[str, Any] | None:
    """首次接受事件时在**现有事务内**追加叶子。

    合作方未安装账本时返回 ``None``（安装时再统一纳入历史）。任何失败都
    抛异常，由调用方回滚整个接收事务。
    """
    row = conn.execute(
        "SELECT tree_size FROM event_logs WHERE partner_id = ?",
        (partner_id,)).fetchone()
    if row is None:
        return None
    if trace is not None:
        trace.meta_reads += 1
    tree_size = int(row["tree_size"])
    preimage, digest = leaf_fields(partner_id, event_id, source_seq,
                                   body_sha256)
    value = hashlib.sha256(b"\x00" + preimage).digest()

    if conn.execute(
            "SELECT 1 FROM log_leaves WHERE partner_id = ? AND event_id = ?",
            (partner_id, event_id)).fetchone() is not None:
        raise LedgerError("duplicate_leaf",
                          f"事件 {event_id!r} 已经存在于该合作方账本")
    if trace is not None:
        trace.statements.append(
            "INSERT log_leaves / log_nodes (唯一一次，受接收事务保护)")

    conn.execute(
        "INSERT INTO log_leaves (partner_id, leaf_index, event_id, source_seq,"
        " body_sha256, leaf_hash, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (partner_id, tree_size, event_id, int(source_seq), digest,
         hex32(value), now),
    )
    # 只合并受新叶影响的完整子树；旧节点从不改写。
    affected = _append_node(conn, partner_id, tree_size, value)
    reader = NodeReader(conn, partner_id, trace if trace is not None
                        else _NO_TRACE)
    root = reader.prefix_root(tree_size + 1)
    conn.execute(
        "UPDATE event_logs SET tree_size = ?, root_hash = ?, updated_at = ?"
        " WHERE partner_id = ?",
        (tree_size + 1, hex32(root), now, partner_id),
    )
    return {
        "partner_id": partner_id,
        "leaf_index": tree_size,
        "leaf_hash": hex32(value),
        "tree_size": tree_size + 1,
        "root_hash": hex32(root),
        "merged_nodes": affected,
    }


_NO_TRACE = ReadTrace()


def _append_node(conn: sqlite3.Connection, partner_id: str, cursor: int,
                 leaf_value: bytes) -> list[str]:
    """写入叶层节点并向上合并恰好闭合的完整子树节点。"""
    conn.execute(
        "INSERT INTO log_nodes (partner_id, level, node_index, node_hash)"
        " VALUES (?, 0, ?, ?)",
        (partner_id, cursor, hex32(leaf_value)),
    )
    return _merge_parents(conn, partner_id, cursor)


def _merge_parents(conn: sqlite3.Connection, partner_id: str,
                   cursor: int) -> list[str]:
    """叶 ``cursor`` 插入后，向上合并恰好闭合的完整子树节点。"""
    affected: list[str] = []
    level = 0
    while True:
        span = 1 << (level + 1)
        if (cursor + 1) % span != 0:
            break
        start = cursor + 1 - span
        left = _node_direct(conn, partner_id, level, start >> level)
        right = _node_direct(conn, partner_id, level, (start >> level) + 1)
        parent = merkle.node_hash(left, right)
        conn.execute(
            "INSERT INTO log_nodes (partner_id, level, node_index, node_hash)"
            " VALUES (?, ?, ?, ?)",
            (partner_id, level + 1, start >> (level + 1), hex32(parent)),
        )
        affected.append(f"{level + 1}:{start >> (level + 1)}")
        level += 1
    return affected


def _node_direct(conn, partner_id: str, level: int, node_index: int) -> bytes:
    row = conn.execute(
        "SELECT node_hash FROM log_nodes WHERE partner_id = ? AND level = ?"
        " AND node_index = ?", (partner_id, level, node_index)).fetchone()
    if row is None:
        raise LedgerError("missing_node",
                          f"账本缺少子树节点 level={level} index={node_index}")
    return bytes.fromhex(row["node_hash"])


# --------------------------------------------------------------------- #
# 安装（一次写事务，纳入已有 accepted_events）
# --------------------------------------------------------------------- #
_ACCEPTED_SQL = (
    "SELECT event_id, source_seq, body_sha256, ingest_record_id"
    " FROM accepted_events WHERE partner_id = ?"
    " ORDER BY ingest_record_id ASC, event_id ASC"
)

_BODY_SQL = (
    "SELECT body_blob, byte_length FROM raw_bodies WHERE body_sha256 = ?"
)


def _read_verified_body(conn: sqlite3.Connection, digest: str,
                        event_id: str) -> bytes:
    if not isinstance(digest, str) or len(digest) != 64:
        raise LedgerError("bad_body_digest",
                          f"事件 {event_id!r} 的正文摘要不是 64 位十六进制")
    try:
        bytes.fromhex(digest)
    except ValueError:
        raise LedgerError("bad_body_digest",
                          f"事件 {event_id!r} 的正文摘要不是十六进制") from None
    row = conn.execute(_BODY_SQL, (digest,)).fetchone()
    if row is None:
        raise LedgerError("body_missing",
                          f"事件 {event_id!r} 的正文（摘要 {digest}）不存在，"
                          "拒绝安装；不产生任何账本记录")
    blob = bytes(row["body_blob"])
    if len(blob) != int(row["byte_length"]):
        raise LedgerError(
            "body_length_mismatch",
            f"事件 {event_id!r} 的正文实际 {len(blob)} 字节，登记为"
            f" {row['byte_length']} 字节，拒绝安装")
    actual = hashlib.sha256(blob).hexdigest()
    if actual != digest.lower():
        raise LedgerError(
            "body_digest_mismatch",
            f"事件 {event_id!r} 的正文实际摘要 {actual} 与登记 {digest} 不符，"
            "拒绝安装")
    return blob


def install(*, db_path: str, partner_id: str,
            clock: Callable[[], float] = time.time) -> dict[str, Any]:
    """安装/复核某合作方账本。

    首次安装：随机生成 log_id，按 accepted_events 的 ingest_record_id 递增
    纳入全部历史叶子。重复安装：只复核，不换号、不重排、不追加。
    整个过程持有写锁；并发收件等待写锁后在新的叶位置追加，不会漏掉交界处
    的事件。
    """
    if not partner_id:
        raise LedgerError("bad_partner", "合作方标识不能为空")
    conn = connect_write(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            report = _install_in_transaction(conn, partner_id,
                                             now=int(clock()))
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
    finally:
        conn.close()
    return report


def _install_in_transaction(conn: sqlite3.Connection, partner_id: str,
                            *, now: int) -> dict[str, Any]:
    existing = conn.execute(
        "SELECT log_id, protocol, tree_size, root_hash, created_at"
        " FROM event_logs WHERE partner_id = ?", (partner_id,)).fetchone()
    accepted = list(conn.execute(_ACCEPTED_SQL, (partner_id,)))
    # 先逐条核对正文存在、长度与摘要吻合；任何一条失败都不写账本。
    verified: list[tuple[str, int, str, bytes]] = []
    for row in accepted:
        event_id = row["event_id"]
        digest = str(row["body_sha256"]).lower()
        seq = row["source_seq"]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise LedgerError("bad_sequence",
                              f"事件 {event_id!r} 的 source_seq 不是整数")
        # 既核对正文存在/长度/摘要，也核对事件字段能按协议编码（超范围拒绝）。
        try:
            merkle.leaf_preimage(partner_id, event_id, int(seq), digest)
        except MerkleError as exc:
            raise LedgerError(exc.code,
                              f"事件 {event_id!r} 无法按协议编码: "
                              f"{exc.message}") from None
        blob = _read_verified_body(conn, digest, event_id)
        verified.append((event_id, int(seq), digest, blob))

    if existing is not None:
        _verify_existing(conn, partner_id, existing, verified)
        return {
            "partner_id": partner_id,
            "log_id": existing["log_id"],
            "protocol": existing["protocol"],
            "tree_size": int(existing["tree_size"]),
            "root_hash": existing["root_hash"],
            "created_at": int(existing["created_at"]),
            "already_installed": True,
            "leaves": len(verified),
        }

    log_id = secrets.token_hex(16)
    conn.execute(
        "INSERT INTO event_logs (partner_id, log_id, protocol, tree_size,"
        " root_hash, created_at, updated_at)"
        " VALUES (?, ?, ?, 0, ?, ?, ?)",
        (partner_id, log_id, PROTOCOL, hex32(merkle.empty_root()),
         now, now),
    )
    reader = NodeReader(conn, partner_id, ReadTrace())
    for position, (event_id, seq, digest, _blob) in enumerate(verified):
        # 安装阶段的正文/摘要/长度校验已在 _read_verified_body 完成。
        value = merkle.leaf_hash(partner_id, event_id, seq, digest)
        conn.execute(
            "INSERT INTO log_leaves (partner_id, leaf_index, event_id,"
            " source_seq, body_sha256, leaf_hash, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (partner_id, position, event_id, seq, digest, hex32(value), now),
        )
        # 节点合并与在线追加走同一函数，保证两条构建路径同构。
        _append_node(conn, partner_id, position, value)
    size = len(verified)
    root = reader.prefix_root(size)
    conn.execute(
        "UPDATE event_logs SET tree_size = ?, root_hash = ?, updated_at = ?"
        " WHERE partner_id = ?", (size, hex32(root), now, partner_id))
    return {
        "partner_id": partner_id, "log_id": log_id, "protocol": PROTOCOL,
        "tree_size": size, "root_hash": hex32(root), "created_at": now,
        "already_installed": False, "leaves": size,
    }


def _verify_existing(conn: sqlite3.Connection, partner_id: str,
                     existing: sqlite3.Row,
                     verified: list[tuple[str, int, str, bytes]]) -> None:
    if existing["protocol"] != PROTOCOL:
        raise LedgerError("bad_protocol",
                          "已安装账本的协议版本与本实现不一致；拒绝重复安装")
    rows = list(conn.execute(
        "SELECT leaf_index, event_id, source_seq, body_sha256, leaf_hash"
        " FROM log_leaves WHERE partner_id = ? ORDER BY leaf_index ASC",
        (partner_id,)))
    if len(rows) != len(verified):
        raise LedgerError(
            "reinstall_mismatch",
            f"已安装账本有 {len(rows)} 片叶子，但 accepted_events 有"
            f" {len(verified)} 条；拒绝换号或重排")
    if int(existing["tree_size"]) != len(rows):
        raise LedgerError("reinstall_mismatch",
                          "已安装账本的 tree_size 与叶行数不一致")
    reader = NodeReader(conn, partner_id, ReadTrace())
    for index, (row, expected) in enumerate(zip(rows, verified)):
        if int(row["leaf_index"]) != index:
            raise LedgerError("reinstall_mismatch",
                              f"叶位置不连续：期望 {index}，实际 {row['leaf_index']}")
        event_id, seq, digest, _blob = expected
        if (row["event_id"], int(row["source_seq"]),
                str(row["body_sha256"]).lower()) != (event_id, seq, digest):
            raise LedgerError(
                "reinstall_mismatch",
                f"叶 {index} 与 accepted_events 顺序不一致；拒绝重排")
        value = merkle.leaf_hash(partner_id, event_id, seq, digest)
        if bytes.fromhex(row["leaf_hash"]) != value:
            raise LedgerError("reinstall_mismatch",
                              f"叶 {index} 的哈希与字段不符")
    root = hex32(reader.prefix_root(len(rows)))
    if root != existing["root_hash"]:
        raise LedgerError("reinstall_mismatch",
                          "已安装账本的根与由节点重建的根不一致")


# --------------------------------------------------------------------- #
# 检查点与证明
# --------------------------------------------------------------------- #
def _with_read_snapshot(db_path: str, fn):
    conn = connect_readonly(db_path)
    try:
        conn.execute("BEGIN")
        try:
            value = fn(conn)
        finally:
            conn.execute("COMMIT")
    finally:
        conn.close()
    return value


def read_checkpoint(db_path: str, partner_id: str, *,
                    tree_size: int | None = None,
                    trace: ReadTrace | None = None) -> Checkpoint:
    """读取检查点。

    ``tree_size=None`` 时返回当前检查点（单行一致读取）；传入 ``tree_size``
    时从持久节点重建该旧前缀的根（不重扫叶事件）。已经发出的旧检查点保存
    在调用方手里，不因新收件而改变。
    """
    trace = trace or ReadTrace()

    def run(conn):
        meta = _meta(conn, partner_id, trace)
        current = int(meta["tree_size"])
        size = current if tree_size is None else merkle_strict_size(tree_size)
        if size > current:
            raise LedgerError("size_out_of_range",
                              f"请求树长 {size} 超过当前树长 {current}")
        if size == current:
            root_hex = meta["root_hash"]
        else:
            root_hex = hex32(NodeReader(conn, partner_id, trace).prefix_root(size))
        return Checkpoint(meta["log_id"], partner_id, size,
                          merkle.parse_hex32(root_hex, "root_hash"),
                          meta["protocol"])

    return _with_read_snapshot(db_path, run)


def merkle_strict_size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerError("bad_size", "树长必须是整数（布尔值不算整数）")
    if value < 0:
        raise LedgerError("bad_size", "树长不能为负数")
    return value


def _verify_checkpoint_identity(checkpoint: Checkpoint, meta: sqlite3.Row,
                                partner_id: str) -> None:
    if checkpoint.partner_id != partner_id:
        raise LedgerError("cross_partner",
                          f"检查点合作方 {checkpoint.partner_id!r} 与账本"
                          f" {partner_id!r} 不符")
    if checkpoint.log_id != meta["log_id"]:
        raise LedgerError("cross_log_id",
                          f"检查点 log_id 与本地账本不符")
    if checkpoint.protocol != meta["protocol"]:
        raise LedgerError("bad_protocol", "检查点协议与本地账本不符")
    if checkpoint.version != merkle.FORMAT_VERSION:
        raise LedgerError("bad_version", "检查点格式版本不受支持")


def prove_inclusion(db_path: str, partner_id: str, checkpoint: Checkpoint,
                    event_id: str, *,
                    trace: ReadTrace | None = None) -> InclusionProof:
    """在指定旧 tree_size 下为一条事件生成在账证明。

    检查点必须与本地相应前缀的根一致；事件必须已经进入该前缀。
    """
    trace = trace or ReadTrace()

    def run(conn):
        meta = _meta(conn, partner_id, trace)
        _verify_checkpoint_identity(checkpoint, meta, partner_id)
        size = merkle_strict_size(checkpoint.tree_size)
        if size > int(meta["tree_size"]):
            raise LedgerError("size_out_of_range",
                              f"检查点树长 {size} 超过本地当前树长"
                              f" {meta['tree_size']}")
        if size == 0:
            raise LedgerError("empty_tree", "空树没有可证明的叶")
        reader = NodeReader(conn, partner_id, trace)
        local_root = reader.prefix_root(size)
        if local_root != checkpoint.root_hash:
            raise LedgerError("checkpoint_root_mismatch",
                              "检查点根与本地相应前缀的根不符，拒绝生成证明")
        row = conn.execute(
            "SELECT leaf_index, event_id, source_seq, body_sha256, leaf_hash"
            " FROM log_leaves WHERE partner_id = ? AND event_id = ?",
            (partner_id, event_id)).fetchone()
        if trace is not None:
            trace.leaf_queries += 1
            trace.statements.append(
                "SELECT leaf_index ... FROM log_leaves WHERE partner_id=?"
                " AND event_id=?")
        if row is None:
            raise LedgerError("event_not_in_log",
                              f"事件 {event_id!r} 不在该合作方账本中")
        if trace is not None:
            trace.leaf_rows += 1
        index = int(row["leaf_index"])
        if index >= size:
            raise LedgerError(
                "not_in_prefix",
                f"事件 {event_id!r} 位于叶 {index}，尚未进入树长 {size} 的前缀")
        value = merkle.leaf_hash(partner_id, row["event_id"],
                                 int(row["source_seq"]),
                                 str(row["body_sha256"]).lower())
        if value != bytes.fromhex(row["leaf_hash"]):
            raise LedgerError("leaf_hash_mismatch",
                              "持久叶哈希与字段重算结果不符")
        path = reader.inclusion_path(size, index)
        rebuilt = merkle.build_inclusion_root(value, index, size, path)
        if rebuilt != checkpoint.root_hash:
            raise LedgerError("internal_path_mismatch",
                              "生成的路径无法重建检查点根（内部错误）")
        return InclusionProof(
            checkpoint.log_id, partner_id, size, index, row["event_id"],
            int(row["source_seq"]), str(row["body_sha256"]).lower(),
            tuple(path))

    return _with_read_snapshot(db_path, run)


def prove_consistency(db_path: str, partner_id: str,
                      old_checkpoint: Checkpoint,
                      new_checkpoint: Checkpoint, *,
                      trace: ReadTrace | None = None) -> ConsistencyProof:
    """以旧、新两个可信检查点生成一致性路径。

    生成前分别核对两个检查点与本地相应前缀的根；两端的大小不能倒退。
    """
    trace = trace or ReadTrace()

    def run(conn):
        meta = _meta(conn, partner_id, trace)
        for label, checkpoint in (("旧", old_checkpoint),
                                  ("新", new_checkpoint)):
            _verify_checkpoint_identity(checkpoint, meta, partner_id)
            if checkpoint.tree_size > int(meta["tree_size"]):
                raise LedgerError(
                    "size_out_of_range",
                    f"{label}检查点树长 {checkpoint.tree_size} 超过本地当前树长"
                    f" {meta['tree_size']}")
        old_size = merkle_strict_size(old_checkpoint.tree_size)
        new_size = merkle_strict_size(new_checkpoint.tree_size)
        if new_size < old_size:
            raise LedgerError("size_regression",
                              f"新检查点树长 {new_size} 小于旧树长 {old_size}")
        reader = NodeReader(conn, partner_id, trace)
        old_root = reader.prefix_root(old_size)
        new_root = reader.prefix_root(new_size)
        if old_root != old_checkpoint.root_hash:
            raise LedgerError("checkpoint_root_mismatch",
                              "旧检查点根与本地相应前缀不符，拒绝生成证明")
        if new_root != new_checkpoint.root_hash:
            raise LedgerError("checkpoint_root_mismatch",
                              "新检查点根与本地相应前缀不符，拒绝生成证明")
        path = reader.consistency_path(old_size, new_size)
        try:
            checked = merkle.reconstruct_consistency(
                old_root, new_root, old_size, new_size, path)
        except MerkleError as exc:
            raise LedgerError("internal_path_mismatch",
                              f"生成的一致性路径无法重建两端根: {exc.message}")
        if checked.old_root != old_root or checked.new_root != new_root:
            raise LedgerError("internal_path_mismatch",
                              "生成的一致性路径重建结果不一致")
        return ConsistencyProof(old_checkpoint.log_id, partner_id,
                                old_size, new_size, tuple(path))

    return _with_read_snapshot(db_path, run)


# --------------------------------------------------------------------- #
# 状态
# --------------------------------------------------------------------- #
def log_status(db_path: str, partner_id: str | None = None) -> dict[str, Any]:
    conn = connect_readonly(db_path)
    try:
        conn.execute("BEGIN")
        try:
            if partner_id is not None:
                row = conn.execute(
                    "SELECT * FROM event_logs WHERE partner_id = ?",
                    (partner_id,)).fetchone()
                if row is None:
                    raise NotInstalled(partner_id)
                partners = [row]
            else:
                partners = list(conn.execute(
                    "SELECT * FROM event_logs ORDER BY partner_id"))
            result = []
            for row in partners:
                leaves = conn.execute(
                    "SELECT COUNT(*) FROM log_leaves WHERE partner_id = ?",
                    (row["partner_id"],)).fetchone()[0]
                accepted = conn.execute(
                    "SELECT COUNT(*) FROM accepted_events WHERE partner_id = ?",
                    (row["partner_id"],)).fetchone()[0]
                result.append({
                    "partner_id": row["partner_id"],
                    "log_id": row["log_id"],
                    "protocol": row["protocol"],
                    "tree_size": int(row["tree_size"]),
                    "root_hash": row["root_hash"],
                    "leaves": int(leaves),
                    "accepted_events": int(accepted),
                    "created_at": int(row["created_at"]),
                    "updated_at": int(row["updated_at"]),
                })
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    if partner_id is not None:
        return result[0]
    return {"logs": result}
