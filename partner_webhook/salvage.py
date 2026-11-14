"""离线接收库提取器（损坏镜像抢救）。

备份介质出现坏页时，SQLite 查询读到损坏位置会整次失败。本工具**直接解释
SQLite 文件页**（不经过 SQL 引擎、不调用 sqlite3 或任何现成恢复工具），
从主库镜像中抢救 ``accepted_events`` 与 ``raw_bodies`` 两张表里仍能确认的
事件及原始请求体，并把无法确认的部分逐条登记，供人工核对后重新导入。

边界（务必阅读）：

- 只读打开源文件，绝不修改、修复或清空源库；
- 结果仅供人工核对，**不回写在线接收或 outbox**；
- 不扫描全文件猜测字节：目录（sqlite_schema）无法完整解释时整体拒绝；
- 索引、outbox、ingest_records 与 freelist 不参与抢救；
- 不猜测遗失行的内容或数量。

退出码：0 完整提取；2 部分结果（存在损坏/歧义/失配/资源上限）；
1 整体拒绝（格式不受支持、目录不能解释、旁文件未归并等）。

用法：

    python3 -I partner_webhook/salvage.py --db 镜像.db --out 输出目录 \
        [--max-payload-bytes N] [--max-pages N] [--max-diagnostics N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_PARTIAL = 2

SQLITE_MAGIC = b"SQLite format 3\x00"
SUPPORTED_PAGE_SIZES = (512, 4096, 65536)

PAGE_INTERIOR_TABLE = 5
PAGE_LEAF_TABLE = 13

# 本仓库 migrations/0001_init.sql 中两张目标表的固定布局（按列顺序）。
TARGET_TABLES = ("accepted_events", "raw_bodies")
TABLE_COLUMNS = {
    "accepted_events": [
        "event_id", "partner_id", "source_seq", "key_version",
        "body_sha256", "ingest_record_id", "claimed_timestamp", "accepted_at",
    ],
    "raw_bodies": ["body_sha256", "body_blob", "byte_length", "first_seen_at"],
}
TABLE_KINDS = {
    "accepted_events": ["text", "text", "int", "text", "text", "int", "int", "int"],
    "raw_bodies": ["text", "blob", "int", "int"],
}

EVIDENCE_BOUNDARY = (
    "本输出仅表示本次从数据库镜像中按 SQLite 文件结构解码得到的内容；"
    "正文的 SHA-256 校验仅证明提取字节与 raw_bodies 登记的摘要一致，"
    "不证明原始投递签名有效，也不证明当时的接收判定正确；"
    "全部结果需人工核对后方可重新导入。本工具只读源文件，"
    "不修复、不清空源库，也不回写在线接收或 outbox。"
)

DEFAULT_MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_PAGES = 2_000_000
DEFAULT_MAX_DIAGNOSTICS = 20_000


class FatalRejection(Exception):
    """整体拒绝（退出码 1）：输入无法确定解释方式。"""


class ParseError(Exception):
    """单点解析失败（页/cell/记录级），隔离对应部分即可。"""


class PayloadTooLarge(ParseError):
    """单条载荷超过配置上限。"""


class PageLimitReached(Exception):
    """访问页数达到上限：停止遍历，保留已得结果。"""


# --------------------------------------------------------------------------- #
# 基础解析：varint / serial type / record
# --------------------------------------------------------------------------- #
def read_varint(buf: bytes, pos: int, end: int) -> tuple[int, int]:
    """读取 SQLite varint（1-9 字节，大端 7 位组，第 9 字节取全部 8 位）。

    返回 (无符号 64 位值, 新位置)；越界抛 ParseError。
    """
    value = 0
    for i in range(9):
        if pos >= end:
            raise ParseError(f"varint 在偏移 {pos} 处越出边界 {end}")
        byte = buf[pos]
        pos += 1
        if i == 8:  # 第 9 个字节贡献全部 8 位
            value = (value << 8) | byte
            return value, pos
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, pos
    return value, pos  # 防御：循环必然在 i == 8 处返回


def as_signed64(value: int) -> int:
    """把 64 位无符号解释为有符号整数（rowid、大整数列）。"""
    return value - (1 << 64) if value >= (1 << 63) else value


def serial_kind_size(serial: int) -> tuple[str, int]:
    """serial type -> (种类, 字节数)。保留值 10/11 视为非法。"""
    if serial == 0:
        return "null", 0
    if serial in (1, 2, 3, 4):
        return "int", serial
    if serial == 5:
        return "int", 6
    if serial == 6:
        return "int", 8
    if serial == 7:
        return "float", 8
    if serial in (8, 9):
        return "int", 0
    if serial in (10, 11):
        raise ParseError(f"非法 serial type {serial}（SQLite 保留值）")
    if serial >= 12:
        if serial % 2 == 0:
            return "blob", (serial - 12) // 2
        return "text", (serial - 13) // 2
    raise ParseError(f"非法 serial type {serial}")


def _decode_value(kind: str, raw: bytes, serial: int):
    if kind == "null":
        return None
    if kind == "int":
        if serial == 8:
            return 0
        if serial == 9:
            return 1
        return int.from_bytes(raw, "big", signed=True)
    if kind == "float":
        return struct.unpack(">d", raw)[0]
    if kind == "text":
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw  # 非 UTF-8 文本：保留原始字节，由调用方按 text_invalid 处理
    return raw  # blob


def parse_record(payload: bytes) -> list[tuple[str, object, int, int]]:
    """解析一条 record。

    返回 [(kind, value, 起始, 结束)]，偏移相对载荷起点；kind 为
    null/int/float/text/blob/text_invalid 之一。载荷必须被恰好消费完，
    否则视为不自洽（隔离该记录）。
    """
    header_len, pos = read_varint(payload, 0, len(payload))
    if header_len < pos or header_len > len(payload):
        raise ParseError(
            f"record 头长 {header_len} 与载荷长度 {len(payload)} 不自洽"
        )
    serials = []
    while pos < header_len:
        serial, pos = read_varint(payload, pos, header_len)
        serials.append(serial)
    if pos != header_len:
        raise ParseError("record 头边界不对齐")
    values = []
    vpos = header_len
    for serial in serials:
        kind, size = serial_kind_size(serial)
        if vpos + size > len(payload):
            raise ParseError(
                f"列值越出载荷：需要 {size} 字节，仅剩 {len(payload) - vpos}"
            )
        raw = payload[vpos:vpos + size]
        value = _decode_value(kind, raw, serial)
        if kind == "text" and isinstance(value, bytes):
            kind = "text_invalid"
        values.append((kind, value, vpos, vpos + size))
        vpos += size
    if vpos != len(payload):
        raise ParseError(
            f"record 未恰好消费载荷：{vpos} != {len(payload)}"
        )
    return values


# --------------------------------------------------------------------------- #
# 源镜像（只读）
# --------------------------------------------------------------------------- #
class ImageFile:
    """只读 SQLite 主库镜像：解析文件头、按页读取。绝不写入。"""

    def __init__(self, path: str):
        self.path = str(path)
        try:
            self.fd = os.open(self.path, os.O_RDONLY)
        except OSError as exc:
            raise FatalRejection(f"无法只读打开源文件 {self.path}: {exc}") from exc
        try:
            self.size = os.fstat(self.fd).st_size
            self._parse_header()
        except Exception:
            os.close(self.fd)
            raise

    def close(self) -> None:
        os.close(self.fd)

    def _parse_header(self) -> None:
        if self.size < 100:
            raise FatalRejection("文件不足 100 字节，不是 SQLite 3 主库镜像")
        header = os.pread(self.fd, 100, 0)
        if len(header) != 100 or header[:16] != SQLITE_MAGIC:
            raise FatalRejection("文件头魔数不符，不是 SQLite 3 主库镜像")
        raw_page_size = int.from_bytes(header[16:18], "big")
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        if page_size not in SUPPORTED_PAGE_SIZES:
            raise FatalRejection(
                f"页长 {page_size} 不在支持范围（512/4096/65536），拒绝解释"
            )
        write_version, read_version = header[18], header[19]
        if write_version not in (1, 2) or read_version not in (1, 2):
            raise FatalRejection(
                f"文件格式版本号无效（write={write_version}, read={read_version}）"
            )
        if header[21] != 64 or header[22] != 32 or header[23] != 32:
            raise FatalRejection("载荷比例字段不是 64/32/32，主库头无效")
        self.reserved_bytes = header[20]
        self.page_size = page_size
        self.usable_size = page_size - self.reserved_bytes
        if self.usable_size < 480:
            raise FatalRejection(f"可用页长 {self.usable_size} 小于 480，主库头无效")
        encoding = int.from_bytes(header[56:60], "big")
        if encoding != 1:
            raise FatalRejection(f"文本编码 {encoding} 不是 UTF-8，拒绝解释")
        if self.size < page_size:
            raise FatalRejection("文件不足一个完整页，主库头无效或文件被截短")
        self.page_count = self.size // page_size
        self.trailing_bytes = self.size % page_size
        # 头内登记的库页数仅在 change counter 与 version-valid-for 一致时可信
        self.header_page_count = int.from_bytes(header[28:32], "big")
        self.header_size_valid = (
            int.from_bytes(header[24:28], "big")
            == int.from_bytes(header[92:96], "big")
            and self.header_page_count > 0
        )

    def read_page(self, page_no: int) -> bytes:
        """读取一个完整页；越界或短缺抛 ParseError。"""
        if page_no < 1 or page_no > self.page_count:
            raise ParseError(
                f"页号 {page_no} 越界（镜像共 {self.page_count} 页）"
            )
        data = os.pread(
            self.fd, self.page_size, (page_no - 1) * self.page_size
        )
        if len(data) != self.page_size:
            raise ParseError(
                f"页 {page_no} 读取短缺：{len(data)}/{self.page_size} 字节"
            )
        return data

    def sha256(self) -> str:
        """流式计算源文件摘要（只读）。"""
        digest = hashlib.sha256()
        offset = 0
        while offset < self.size:
            chunk = os.pread(self.fd, min(1 << 20, self.size - offset), offset)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()


def check_side_files(db_path: str) -> None:
    """旁边存在非空 -wal / -journal 时拒绝：尚有未归并的状态。"""
    for suffix in ("-wal", "-journal"):
        side = db_path + suffix
        if os.path.exists(side) and os.path.getsize(side) > 0:
            raise FatalRejection(
                f"存在非空旁文件 {side}（{os.path.getsize(side)} 字节）："
                "WAL/回滚日志尚未归并，镜像状态不确定，拒绝提取"
            )


# --------------------------------------------------------------------------- #
# 诊断
# --------------------------------------------------------------------------- #
class Diagnostics:
    """诊断条目收集器；达到上限后丢弃后续条目并记录丢弃数。"""

    def __init__(self, limit: int):
        self.limit = limit
        self.entries: list[dict] = []
        self.dropped = 0
        self.limit_hit = False
        self.by_severity = {"info": 0, "warning": 0, "error": 0}

    def add(self, severity: str, code: str, *, tree=None, page=None,
            path=None, detail=None) -> None:
        if self.limit_hit:
            self.dropped += 1
            return
        if len(self.entries) >= self.limit:
            self.limit_hit = True
            self.by_severity["error"] += 1
            self.entries.append({
                "seq": len(self.entries) + 1,
                "severity": "error",
                "code": "diagnostics_limit_reached",
                "detail": {"limit": self.limit,
                           "note": "诊断条数达到上限，后续诊断被丢弃"},
            })
            return
        self.by_severity[severity] += 1
        entry = {"seq": len(self.entries) + 1, "severity": severity, "code": code}
        if tree is not None:
            entry["tree"] = tree
        if page is not None:
            entry["page"] = page
        if path is not None:
            entry["path"] = [str(p) for p in path]
        if detail:
            entry["detail"] = detail
        self.entries.append(entry)


# --------------------------------------------------------------------------- #
# 提取器：直接解释 B-tree 页
# --------------------------------------------------------------------------- #
class Extractor:
    """遍历表 B-tree、拼接溢出链、解析 record。不做任何写操作。"""

    def __init__(self, image: ImageFile, diags: Diagnostics, *,
                 max_payload_bytes: int, max_pages: int):
        self.image = image
        self.diags = diags
        self.max_payload_bytes = max_payload_bytes
        self.max_pages = max_pages
        self.usable = image.usable_size
        self.owners: dict[int, str] = {}   # 页号 -> 占用者标签
        self.contested: set[int] = set()   # 被重复占用的页（歧义）
        self.pages_visited = 0
        self.unfinished: list[str] = []    # 未完成原因
        self.strict = False                # 目录解析阶段：任何非 info 诊断都致命

    # ------------------------------------------------------------------ #
    def diag(self, severity: str, code: str, **kw) -> None:
        if self.strict and severity != "info":
            raise FatalRejection(f"目录无法完整解释（{code}）：{kw}")
        self.diags.add(severity, code, **kw)

    def note_unfinished(self, reason: str) -> None:
        if reason not in self.unfinished:
            self.unfinished.append(reason)

    # ------------------------------------------------------------------ #
    def _claim_page(self, page_no: int, owner: str, *, tree: str, path) -> bool:
        """登记页占用；发现重复占用时登记冲突并返回 False。"""
        existing = self.owners.get(page_no)
        if existing is None:
            self.owners[page_no] = owner
            return True
        if existing == owner:
            return True
        self.contested.add(page_no)
        self.diag("error", "page_ownership_conflict", tree=tree, page=page_no,
                  path=path, detail={"first_owner": existing,
                                     "second_owner": owner,
                                     "note": "同一页被重复占用，相关记录均不算已确认"})
        return False

    def _visit_page(self, page_no: int, owner: str, *, tree: str, path):
        """页数上限检查 + 占用登记 + 读取。冲突返回 None，越界抛 ParseError。"""
        if self.pages_visited >= self.max_pages:
            self.note_unfinished("page_limit")
            self.diag("error", "page_limit_reached", tree=tree, page=page_no,
                      path=path, detail={"limit": self.max_pages})
            raise PageLimitReached
        if not self._claim_page(page_no, owner, tree=tree, path=path):
            return None
        self.pages_visited += 1
        return self.image.read_page(page_no)

    # ------------------------------------------------------------------ #
    def walk_table_tree(self, name: str, root_page: int, sink) -> None:
        """遍历表 B-tree；叶记录交给 sink(rowid, payload, chunks, prov)。

        chunks: [(文件偏移, 长度)]，按载荷顺序覆盖整条记录的字节来源。
        prov:   {"leaf_page", "cell_index", "cell_offset"}。
        """
        visited: set[int] = set()
        stack = [(root_page, (root_page,))]
        owner = f"tree:{name}"
        while stack:
            page_no, path = stack.pop()
            if page_no in visited:
                self.diag("error", "tree_cycle", tree=name, page=page_no,
                          path=path, detail={"note": "同一棵树内页面被重复引用"})
                continue
            visited.add(page_no)
            if page_no < 1 or page_no > self.image.page_count:
                self.diag("error", "page_out_of_bounds", tree=name, page=page_no,
                          path=path,
                          detail={"page_count": self.image.page_count})
                continue
            page = self._visit_page(page_no, owner, tree=name, path=path)
            if page is None:
                continue  # 占用冲突已登记，跳过该子树
            base = 100 if page_no == 1 else 0
            ptype = page[base]
            if ptype == PAGE_INTERIOR_TABLE:
                for child in reversed(
                        self._parse_interior(page, page_no, base, name, path)):
                    stack.append((child, path + (child,)))
            elif ptype == PAGE_LEAF_TABLE:
                self._parse_leaf(page, page_no, base, name, path, sink)
            else:
                self.diag("error", "bad_page_type", tree=name, page=page_no,
                          path=path,
                          detail={"type_byte": ptype, "expected": "5(内部)/13(叶子)"})

    # ------------------------------------------------------------------ #
    def _read_page_header(self, page: bytes, page_no: int, base: int,
                          header_size: int, tree: str, path):
        """校验页头与 cell 指针数组边界；失败登记并返回 None。"""
        usable = self.usable
        hdr_end = base + header_size
        cell_count = int.from_bytes(page[base + 3:base + 5], "big")
        content_start = int.from_bytes(page[base + 5:base + 7], "big") or 65536
        problems = []
        if hdr_end + 2 * cell_count > usable:
            problems.append(
                f"cell 指针数组越界（{cell_count} 个 cell，可用页长 {usable}）")
        if content_start > usable:
            problems.append(f"内容区起点 {content_start} 超出可用页长 {usable}")
        elif cell_count and content_start < hdr_end:
            problems.append(
                f"内容区起点 {content_start} 与页头 {hdr_end} 重叠")
        if problems:
            self.diag("error", "bad_page_header", tree=tree, page=page_no,
                      path=path, detail={"problems": problems,
                                         "note": "页边界无法确定，跳过整页"})
            return None
        return cell_count, content_start

    def _parse_interior(self, page: bytes, page_no: int, base: int,
                        tree: str, path) -> list[int]:
        """解析表内部页，返回可信子页号列表（坏 cell 单独隔离）。"""
        usable = self.usable
        parsed = self._read_page_header(page, page_no, base, 12, tree, path)
        if parsed is None:
            return []
        cell_count, content_start = parsed
        children = []
        for i in range(cell_count):
            ptr = int.from_bytes(page[base + 12 + 2 * i: base + 14 + 2 * i], "big")
            if ptr < content_start or ptr + 5 > usable:
                self.diag("error", "bad_cell_pointer", tree=tree, page=page_no,
                          path=path, detail={"cell_index": i, "pointer": ptr,
                                             "content_start": content_start})
                continue
            child = int.from_bytes(page[ptr:ptr + 4], "big")
            try:
                read_varint(page, ptr + 4, usable)  # key varint 必须完整可读
            except ParseError as exc:
                self.diag("error", "bad_cell", tree=tree, page=page_no,
                          path=path, detail={"cell_index": i, "error": str(exc)})
                continue
            if child < 1 or child > self.image.page_count:
                self.diag("error", "child_out_of_bounds", tree=tree,
                          page=page_no, path=path,
                          detail={"cell_index": i, "child": child,
                                  "page_count": self.image.page_count})
                continue
            children.append(child)
        rightmost = int.from_bytes(page[base + 8:base + 12], "big")
        if rightmost < 1 or rightmost > self.image.page_count:
            self.diag("error", "child_out_of_bounds", tree=tree, page=page_no,
                      path=path, detail={"cell_index": "rightmost",
                                         "child": rightmost,
                                         "page_count": self.image.page_count})
        else:
            children.append(rightmost)
        return children

    def _parse_leaf(self, page: bytes, page_no: int, base: int,
                    tree: str, path, sink) -> None:
        """解析表叶页：页头可信时逐 cell 解析，单个 cell 损坏只隔离该记录。"""
        parsed = self._read_page_header(page, page_no, base, 8, tree, path)
        if parsed is None:
            return
        cell_count, content_start = parsed
        for i in range(cell_count):
            ptr = int.from_bytes(page[base + 8 + 2 * i: base + 10 + 2 * i], "big")
            prov = {"leaf_page": page_no, "cell_index": i, "cell_offset": ptr}
            if ptr < content_start or ptr >= self.usable:
                self.diag("error", "bad_cell_pointer", tree=tree, page=page_no,
                          path=path,
                          detail={"cell_index": i, "pointer": ptr,
                                  "content_start": content_start})
                continue
            try:
                rowid, payload, chunks = self._read_leaf_payload(
                    page, ptr, tree, page_no, i)
            except PayloadTooLarge as exc:
                self.diag("error", "payload_exceeds_limit", tree=tree,
                          page=page_no, path=path,
                          detail={"cell_index": i, "cell_offset": ptr,
                                  "error": str(exc)})
                continue
            except ParseError as exc:
                self.diag("error", "bad_cell", tree=tree, page=page_no,
                          path=path,
                          detail={"cell_index": i, "cell_offset": ptr,
                                  "error": str(exc)})
                continue
            sink(rowid, payload, chunks, prov)

    # ------------------------------------------------------------------ #
    def _read_leaf_payload(self, page: bytes, ptr: int, tree: str,
                           leaf_page: int, cell_index: int):
        """解析叶 cell：varint、rowid、本地载荷（按 SQLite 规则计算）、溢出链。"""
        usable = self.usable
        payload_len, pos = read_varint(page, ptr, usable)
        rowid_raw, pos = read_varint(page, pos, usable)
        rowid = as_signed64(rowid_raw)
        if payload_len > self.max_payload_bytes:
            self.note_unfinished("payload_limit")
            raise PayloadTooLarge(
                f"载荷声明 {payload_len} 字节，超过单条上限 "
                f"{self.max_payload_bytes}（rowid {rowid}）")
        # SQLite 表叶 cell 的本地载荷规则：
        #   maxLocal = usable - 35
        #   minLocal = (usable - 12) * 32 / 255 - 23
        #   P <= maxLocal 时全部本地；否则本地量 K = minLocal +
        #   (P - minLocal) % (usable - 4)，K > maxLocal 时退化为 minLocal。
        max_local = usable - 35
        min_local = (usable - 12) * 32 // 255 - 23
        if payload_len <= max_local:
            local = payload_len
            has_overflow = False
        else:
            local = min_local + (payload_len - min_local) % (usable - 4)
            if local > max_local:
                local = min_local
            has_overflow = True
        if pos + local + (4 if has_overflow else 0) > usable:
            raise ParseError(
                f"cell 内容越出页面可用区（结束于 {pos + local}"
                f"{'+4' if has_overflow else ''}，可用 {usable}）")
        chunks = [((leaf_page - 1) * self.image.page_size + pos, local)]
        data = bytearray(page[pos:pos + local])
        pos += local
        if has_overflow:
            next_page = int.from_bytes(page[pos:pos + 4], "big")
            data += self._read_overflow(
                next_page, payload_len - local, chunks, tree,
                leaf_page, cell_index)
        return rowid, bytes(data), chunks

    def _read_overflow(self, first_page: int, needed: int, chunks: list,
                       tree: str, leaf_page: int, cell_index: int) -> bytes:
        """沿溢出链取够 needed 字节；缺页/成环/占用冲突抛 ParseError。"""
        usable = self.usable
        owner = f"overflow:{tree}:{leaf_page}:{cell_index}"
        data = bytearray()
        remaining = needed
        page_no = first_page
        seen: set[int] = set()
        while remaining > 0:
            if page_no == 0:
                raise ParseError(f"溢出链提前结束：还缺 {remaining} 字节")
            if page_no in seen:
                raise ParseError(f"溢出链在页 {page_no} 处成环")
            seen.add(page_no)
            if page_no < 1 or page_no > self.image.page_count:
                raise ParseError(
                    f"溢出页 {page_no} 缺失（镜像共 {self.image.page_count} 页，"
                    f"还缺 {remaining} 字节）")
            path = (leaf_page, f"cell{cell_index}", page_no)
            page = self._visit_page(page_no, owner, tree=tree, path=path)
            if page is None:
                raise ParseError(f"溢出页 {page_no} 与他处占用冲突")
            nxt = int.from_bytes(page[0:4], "big")
            take = min(usable - 4, remaining)
            chunks.append(((page_no - 1) * self.image.page_size + 4, take))
            data += page[4:4 + take]
            remaining -= take
            page_no = nxt
        if page_no != 0:
            self.diag("warning", "overflow_chain_surplus", tree=tree,
                      page=leaf_page,
                      detail={"cell_index": cell_index,
                              "surplus_from_page": page_no,
                              "note": "溢出链在取够载荷后仍未结束，多余页不可达"})
        return bytes(data)


# --------------------------------------------------------------------------- #
# 目录（sqlite_schema）解读
# --------------------------------------------------------------------------- #
def extract_column_names(sql: str) -> list[str]:
    """从 CREATE TABLE 语句提取列名（跳过表级约束）。"""
    start = sql.find("(")
    if start < 0:
        raise FatalRejection("CREATE TABLE 语句缺少列定义括号")
    depth = 0
    quote = None
    parts = []
    seg_start = start + 1
    i = start
    while i < len(sql):
        ch = sql[i]
        if quote is not None:
            if ch == quote:
                if quote in ("'", '"') and i + 1 < len(sql) and sql[i + 1] == quote:
                    i += 1  # 双写引号是转义，仍在引号内
                else:
                    quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
        elif ch == "[":
            quote = "]"
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                parts.append(sql[seg_start:i])
                break
        elif ch == "," and depth == 1:
            parts.append(sql[seg_start:i])
            seg_start = i + 1
        i += 1
    else:
        raise FatalRejection("CREATE TABLE 语句括号不配对")
    names = []
    for part in parts:
        tokens = part.strip().split(None, 1)
        if not tokens:
            continue
        first = tokens[0].strip('"`[]')
        if first.upper() in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
            continue  # 表级约束不是列
        names.append(first)
    return names


def read_schema(extractor: Extractor) -> dict:
    """从第 1 页的 sqlite_schema 表树读取目标表根页并核实布局。

    目录必须完整可读、布局必须与本仓库迁移一致，否则整体拒绝。
    """
    records: list[tuple] = []
    extractor.strict = True
    try:
        extractor.walk_table_tree(
            "sqlite_schema", 1, lambda *args: records.append(args))
    finally:
        extractor.strict = False
    tables: dict[str, dict] = {}
    for rowid, payload, _chunks, prov in records:
        try:
            values = parse_record(payload)
        except ParseError as exc:
            raise FatalRejection(
                f"目录记录无法解析（rowid {rowid}，页 {prov['leaf_page']}）：{exc}"
            ) from exc
        if len(values) != 5:
            raise FatalRejection(
                f"目录记录列数 {len(values)} != 5（rowid {rowid}）")
        type_v = values[0][1]
        name_v = values[1][1]
        rootpage_v = values[3][1]
        sql_v = values[4][1]
        if not isinstance(type_v, str):
            raise FatalRejection(f"目录 type 列不是有效 UTF-8 文本（rowid {rowid}）")
        if not isinstance(name_v, str):
            raise FatalRejection(f"目录 name 列不是有效 UTF-8 文本（rowid {rowid}）")
        if not isinstance(rootpage_v, int):
            raise FatalRejection(f"目录 rootpage 列不是整数（rowid {rowid}）")
        if type_v != "table" or name_v not in TARGET_TABLES:
            continue
        if name_v in tables:
            raise FatalRejection(f"目录中表 {name_v} 出现多次，无法确定解释")
        if rootpage_v < 1:
            raise FatalRejection(f"表 {name_v} 根页号无效：{rootpage_v}")
        if not isinstance(sql_v, str):
            raise FatalRejection(f"表 {name_v} 的建表语句不是有效文本")
        columns = extract_column_names(sql_v)
        if [c.lower() for c in columns] != TABLE_COLUMNS[name_v]:
            raise FatalRejection(
                f"表 {name_v} 布局不符：期望列 {TABLE_COLUMNS[name_v]}，"
                f"目录中为 {columns}")
        tables[name_v] = {"root_page": rootpage_v, "columns": columns}
    for name in TARGET_TABLES:
        if name not in tables:
            raise FatalRejection(f"目录中找不到目标表 {name}")
    return tables


# --------------------------------------------------------------------------- #
# 记录还原与交叉核对
# --------------------------------------------------------------------------- #
def convert_record(tree: str, payload: bytes):
    """把记录载荷按目标表列顺序还原；返回 (columns, ranges, problems)。"""
    values = parse_record(payload)  # ParseError 由调用方登记
    columns = TABLE_COLUMNS[tree]
    kinds = TABLE_KINDS[tree]
    problems: list[str] = []
    if len(values) != len(columns):
        problems.append(f"列数 {len(values)} 与布局 {len(columns)} 不符")
    out: dict[str, object] = {}
    ranges: dict[str, tuple[int, int]] = {}
    for idx, name in enumerate(columns):
        if idx >= len(values):
            out[name] = None
            continue
        kind, value, start, end = values[idx]
        expect = kinds[idx]
        if kind == "null":
            problems.append(f"列 {name} 为 NULL（布局要求 NOT NULL）")
        elif kind == "text_invalid":
            problems.append(f"列 {name} 不是有效 UTF-8 文本")
        elif kind != expect:
            problems.append(f"列 {name} 类型 {kind} 与期望 {expect} 不符")
        out[name] = value
        ranges[name] = (start, end)
    if len(values) > len(columns):
        problems.append(f"记录多出 {len(values) - len(columns)} 个未知列")
    return out, ranges, problems


def fragments_for_range(chunks: list[tuple[int, int]], start: int, end: int):
    """把载荷区间 [start, end) 映射为源文件片段列表（偏移+长度）。"""
    fragments = []
    pos = 0
    for file_offset, length in chunks:
        seg_start, seg_end = pos, pos + length
        if seg_end > start and seg_start < end:
            s = max(start, seg_start)
            e = min(end, seg_end)
            if e > s:  # 零长度正文不产生文件片段
                fragments.append({"offset": file_offset + (s - seg_start),
                                  "length": e - s})
        pos = seg_end
    return fragments


def json_safe(value):
    """把解码值转成 JSON 可表达形式（非 UTF-8 字节按十六进制保留）。"""
    if isinstance(value, bytes):
        return {"hex": value.hex(), "note": "非 UTF-8 字节，按十六进制保留"}
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    return value


def _chunk_pages(chunks, page_size: int) -> set[int]:
    return {offset // page_size + 1 for offset, _length in chunks}


# --------------------------------------------------------------------------- #
# 提取主流程
# --------------------------------------------------------------------------- #
def extract(image: ImageFile, diags: Diagnostics, *,
            max_payload_bytes: int, max_pages: int) -> dict:
    """执行提取；返回待写出的结果结构。"""
    extractor = Extractor(image, diags, max_payload_bytes=max_payload_bytes,
                          max_pages=max_pages)

    if image.trailing_bytes:
        diags.add("warning", "trailing_partial_page",
                  detail={"trailing_bytes": image.trailing_bytes,
                          "note": "文件末尾有不足一页的残余，疑似截短"})
    if image.header_size_valid and image.header_page_count != image.page_count:
        diags.add("warning", "db_size_mismatch",
                  detail={"header_pages": image.header_page_count,
                          "file_pages": image.page_count,
                          "note": "头内登记页数与文件实际页数不一致，疑似截短或残留"})

    tables = read_schema(extractor)  # 目录问题 -> FatalRejection

    raw_records: dict[str, list] = {name: [] for name in TARGET_TABLES}
    for name in TARGET_TABLES:
        if extractor.pages_visited >= extractor.max_pages:
            extractor.note_unfinished("page_limit")
            break
        try:
            extractor.walk_table_tree(
                name, tables[name]["root_page"],
                lambda *args, _name=name: raw_records[_name].append(args))
        except PageLimitReached:
            pass

    page_size = image.page_size
    events = []
    bodies = []

    # ---- accepted_events：还原业务列 ------------------------------------
    for rowid, payload, chunks, prov in raw_records["accepted_events"]:
        entry = {
            "rowid": rowid,
            "root_page": tables["accepted_events"]["root_page"],
            "leaf_page": prov["leaf_page"],
            "cell_index": prov["cell_index"],
            "cell_offset": prov["cell_offset"],
            "pages": _chunk_pages(chunks, page_size) | {prov["leaf_page"]},
        }
        try:
            columns, _ranges, problems = convert_record("accepted_events", payload)
        except ParseError as exc:
            diags.add("error", "bad_record", tree="accepted_events",
                      page=prov["leaf_page"],
                      detail={"cell_index": prov["cell_index"], "rowid": rowid,
                              "error": str(exc)})
            continue
        entry["columns"] = columns
        entry["problems"] = problems
        events.append(entry)

    # ---- raw_bodies：还原正文与来源片段 ----------------------------------
    for rowid, payload, chunks, prov in raw_records["raw_bodies"]:
        entry = {
            "rowid": rowid,
            "root_page": tables["raw_bodies"]["root_page"],
            "leaf_page": prov["leaf_page"],
            "cell_index": prov["cell_index"],
            "cell_offset": prov["cell_offset"],
            "pages": _chunk_pages(chunks, page_size) | {prov["leaf_page"]},
        }
        try:
            columns, ranges, problems = convert_record("raw_bodies", payload)
        except ParseError as exc:
            diags.add("error", "bad_record", tree="raw_bodies",
                      page=prov["leaf_page"],
                      detail={"cell_index": prov["cell_index"], "rowid": rowid,
                              "error": str(exc)})
            continue
        entry["columns"] = columns
        entry["problems"] = problems
        body = columns.get("body_blob")
        if isinstance(body, (bytes, bytearray)):
            start, end = ranges["body_blob"]
            entry["body_bytes"] = bytes(body)
            entry["fragments"] = fragments_for_range(chunks, start, end)
            entry["computed_sha256"] = hashlib.sha256(body).hexdigest()
            entry["computed_byte_length"] = len(body)
        bodies.append(entry)

    # ---- 歧义占用隔离：凡用到被重复占用页的记录都不算已确认 --------------
    for entry in events + bodies:
        bad_pages = sorted(entry["pages"] & extractor.contested)
        if bad_pages:
            entry["problems"].append(
                f"page_ownership_conflict: 记录涉及被重复占用的页 {bad_pages}")

    # ---- 业务身份冲突：同键多行一律不算已确认 ----------------------------
    def check_identity(entries, key_fn, code, label):
        groups: dict[object, list] = {}
        for entry in entries:
            if entry["problems"]:
                continue
            key = key_fn(entry["columns"])
            if key is None:
                continue
            groups.setdefault(key, []).append(entry)
        for key, members in groups.items():
            if len(members) < 2:
                continue
            for member in members:
                member["problems"].append(f"identity_conflict: {label} {key!r}")
            diags.add("warning", code,
                      detail={"key": [str(k) for k in key],
                              "rows": [{"rowid": m["rowid"],
                                        "leaf_page": m["leaf_page"],
                                        "cell_index": m["cell_index"]}
                                       for m in members],
                              "note": "同一业务身份解码出多行，均不算已确认"})

    check_identity(
        events,
        lambda c: (c.get("partner_id"), c.get("event_id"))
        if isinstance(c.get("partner_id"), str)
        and isinstance(c.get("event_id"), str) else None,
        "event_identity_conflict", "(partner_id, event_id)")
    check_identity(
        bodies,
        lambda c: (c.get("body_sha256"),)
        if isinstance(c.get("body_sha256"), str) else None,
        "body_identity_conflict", "body_sha256")

    # ---- 正文核验：重算摘要并核对 byte_length ---------------------------
    for entry in bodies:
        declared_sha = entry["columns"].get("body_sha256")
        declared_len = entry["columns"].get("byte_length")
        entry["confirmed"] = not entry["problems"]
        entry["verified"] = False
        if not entry["confirmed"] or "body_bytes" not in entry:
            entry["status"] = "quarantined"
            continue
        ok_sha = entry["computed_sha256"] == declared_sha
        ok_len = entry["computed_byte_length"] == declared_len
        if ok_sha and ok_len:
            entry["verified"] = True
            entry["status"] = "verified"
        else:
            entry["status"] = ("digest_mismatch" if not ok_sha
                               else "length_mismatch")
            diags.add("warning", "body_" + entry["status"], tree="raw_bodies",
                      page=entry["leaf_page"],
                      detail={"rowid": entry["rowid"],
                              "declared_sha256": json_safe(declared_sha),
                              "computed_sha256": entry["computed_sha256"],
                              "declared_byte_length": declared_len,
                              "computed_byte_length":
                                  entry["computed_byte_length"]})

    # ---- 两表关联：事件 -> 正文 ------------------------------------------
    bodies_by_sha: dict[str, list] = {}
    for entry in bodies:
        declared = entry["columns"].get("body_sha256")
        if isinstance(declared, str):
            bodies_by_sha.setdefault(declared, []).append(entry)

    for entry in events:
        entry["confirmed"] = not entry["problems"]
        sha = entry["columns"].get("body_sha256")
        body_state = {"declared_sha256": json_safe(sha), "state": "unknown",
                      "file": None, "body_rowid": None}
        entry["body"] = body_state
        if not entry["confirmed"] or not isinstance(sha, str):
            continue
        matches = bodies_by_sha.get(sha, [])
        for match in matches:  # 登记引用关系（含未确认事件之外的全部匹配）
            match.setdefault("referenced_by", []).append({
                "partner_id": entry["columns"].get("partner_id"),
                "event_id": entry["columns"].get("event_id"),
                "event_rowid": entry["rowid"],
                "event_status": "confirmed" if entry["confirmed"] else "quarantined",
            })
        verified = [m for m in matches if m["status"] == "verified"]
        if verified:
            body_state["state"] = "verified"
            body_state["body_rowid"] = verified[0]["rowid"]
        elif matches:
            worse = [m for m in matches
                     if m["status"] in ("digest_mismatch", "length_mismatch")]
            body_state["state"] = ("digest_mismatch" if worse
                                   else "body_quarantined")
            body_state["body_rowid"] = matches[0]["rowid"]
            diags.add("warning", "event_body_unverified",
                      tree="accepted_events", page=entry["leaf_page"],
                      detail={"rowid": entry["rowid"],
                              "partner_id": entry["columns"].get("partner_id"),
                              "event_id": entry["columns"].get("event_id"),
                              "body_sha256": sha,
                              "body_status": matches[0]["status"]})
        else:
            body_state["state"] = "missing"
            diags.add("warning", "event_missing_body",
                      tree="accepted_events", page=entry["leaf_page"],
                      detail={"rowid": entry["rowid"],
                              "partner_id": entry["columns"].get("partner_id"),
                              "event_id": entry["columns"].get("event_id"),
                              "body_sha256": sha,
                              "note": "事件引用的正文未能完整解码"})

    # 被隔离事件也登记引用关系，便于人工核对（不影响确认状态）
    for entry in events:
        if entry["confirmed"]:
            continue
        sha = entry["columns"].get("body_sha256")
        if not isinstance(sha, str):
            continue
        for match in bodies_by_sha.get(sha, []):
            refs = match.setdefault("referenced_by", [])
            if not any(r["event_rowid"] == entry["rowid"] for r in refs):
                refs.append({
                    "partner_id": entry["columns"].get("partner_id"),
                    "event_id": entry["columns"].get("event_id"),
                    "event_rowid": entry["rowid"],
                    "event_status": "quarantined",
                })

    # ---- 未关联正文：可能来自拒收或冲突投递，保留并说明 -------------------
    for entry in bodies:
        refs = entry.get("referenced_by", [])
        entry["unassociated"] = not refs
        if not refs:
            diags.add("info", "unassociated_body", tree="raw_bodies",
                      page=entry["leaf_page"],
                      detail={"rowid": entry["rowid"],
                              "body_sha256": json_safe(
                                  entry["columns"].get("body_sha256")),
                              "note": "没有事件引用该正文（可能来自拒收或冲突投递），"
                                      "按原样保留，不判为损坏"})

    if diags.limit_hit:
        extractor.note_unfinished("diagnostics_limit")

    events.sort(key=lambda e: (e["rowid"], e["leaf_page"], e["cell_index"]))
    bodies.sort(key=lambda b: (b["rowid"], b["leaf_page"], b["cell_index"]))
    return {"tables": tables, "events": events, "bodies": bodies,
            "unfinished": extractor.unfinished,
            "pages_visited": extractor.pages_visited,
            "contested_pages": sorted(extractor.contested)}


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def write_outputs(out_dir: Path, image: ImageFile, source_sha: str,
                  result: dict, diags: Diagnostics, *,
                  max_payload_bytes: int, max_pages: int,
                  max_diagnostics: int) -> int:
    """写出 events.jsonl / bodies.jsonl / bodies/ / diagnostics.jsonl /
    summary.json；返回退出码。"""
    events = result["events"]
    bodies = result["bodies"]
    bodies_dir = out_dir / "bodies"
    quarantine_dir = bodies_dir / "quarantine"
    bodies_dir.mkdir()
    quarantine_dir.mkdir()

    # ---- 正文文件：已验证按摘要命名，其余进 quarantine（绝不覆盖同名） ----
    quarantine_seq = 0
    for entry in bodies:
        data = entry.get("body_bytes")
        if data is None:
            entry["file"] = None
            continue
        if entry["status"] == "verified":
            rel = f"bodies/{entry['computed_sha256']}.bin"
        else:
            quarantine_seq += 1
            rel = (f"bodies/quarantine/body-{quarantine_seq:05d}"
                   f"-rowid{entry['rowid']}.bin")
        target = out_dir / rel
        if target.exists():
            raise FatalRejection(f"输出文件意外已存在，拒绝覆盖：{rel}")
        target.write_bytes(data)
        entry["file"] = rel

    # 事件关联到正文文件
    for event in events:
        rowid = event["body"].get("body_rowid")
        if rowid is not None:
            for entry in bodies:
                if entry["rowid"] == rowid:
                    event["body"]["file"] = entry["file"]
                    break

    # ---- events.jsonl ----------------------------------------------------
    with open(out_dir / "events.jsonl", "w", encoding="utf-8") as fh:
        for event in events:
            line = {
                "kind": "accepted_event",
                "status": "confirmed" if event["confirmed"] else "quarantined",
                "rowid": event["rowid"],
                "root_page": event["root_page"],
                "leaf_page": event["leaf_page"],
                "cell_index": event["cell_index"],
                "cell_offset": event["cell_offset"],
                "columns": {k: json_safe(v)
                            for k, v in event["columns"].items()},
                "body": event["body"],
            }
            if event["problems"]:
                line["quarantine_reasons"] = event["problems"]
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    # ---- bodies.jsonl ----------------------------------------------------
    with open(out_dir / "bodies.jsonl", "w", encoding="utf-8") as fh:
        for entry in bodies:
            line = {
                "kind": "raw_body",
                "status": entry["status"],
                "verified": entry["verified"],
                "rowid": entry["rowid"],
                "root_page": entry["root_page"],
                "leaf_page": entry["leaf_page"],
                "cell_index": entry["cell_index"],
                "cell_offset": entry["cell_offset"],
                "declared_sha256": json_safe(entry["columns"].get("body_sha256")),
                "declared_byte_length": entry["columns"].get("byte_length"),
                "first_seen_at": entry["columns"].get("first_seen_at"),
                "computed_sha256": entry.get("computed_sha256"),
                "computed_byte_length": entry.get("computed_byte_length"),
                "file": entry["file"],
                "fragments": entry.get("fragments"),
                "referenced_by": entry.get("referenced_by", []),
                "unassociated": entry["unassociated"],
            }
            if entry["problems"]:
                line["quarantine_reasons"] = entry["problems"]
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")

    # ---- diagnostics.jsonl ------------------------------------------------
    with open(out_dir / "diagnostics.jsonl", "w", encoding="utf-8") as fh:
        for entry in diags.entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # ---- summary.json -----------------------------------------------------
    unfinished = result["unfinished"]
    has_problem = (diags.by_severity["error"] > 0
                   or diags.by_severity["warning"] > 0)
    exit_code = EXIT_PARTIAL if (unfinished or has_problem) else EXIT_OK
    counts = {
        "events_confirmed": sum(1 for e in events if e["confirmed"]),
        "events_quarantined": sum(1 for e in events if not e["confirmed"]),
        "bodies_verified": sum(1 for b in bodies if b["status"] == "verified"),
        "bodies_unverified": sum(
            1 for b in bodies
            if b["status"] in ("digest_mismatch", "length_mismatch")),
        "bodies_quarantined": sum(
            1 for b in bodies if b["status"] == "quarantined"),
        "bodies_unassociated": sum(1 for b in bodies if b["unassociated"]),
        "diagnostics": dict(diags.by_severity),
        "diagnostics_dropped": diags.dropped,
    }
    result["counts"] = counts
    summary = {
        "tool": "partner_webhook.salvage",
        "purpose": "离线抢救提取：不修复源库，不回写在线接收或 outbox",
        "source": {
            "path": image.path,
            "size_bytes": image.size,
            "sha256": source_sha,
            "page_size": image.page_size,
            "usable_page_size": image.usable_size,
            "reserved_bytes": image.reserved_bytes,
            "pages_total": image.page_count,
            "pages_visited": result["pages_visited"],
        },
        "tables": result["tables"],
        "limits": {"max_payload_bytes": max_payload_bytes,
                   "max_pages": max_pages,
                   "max_diagnostics": max_diagnostics},
        "unfinished_reasons": unfinished,
        "contested_pages": result["contested_pages"],
        "counts": counts,
        "exit_code": exit_code,
        "evidence_boundary": EVIDENCE_BOUNDARY,
    }
    with open(out_dir / "summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return exit_code


# --------------------------------------------------------------------------- #
# 命令行
# --------------------------------------------------------------------------- #
def run(args) -> int:
    if (args.max_payload_bytes < 1 or args.max_pages < 1
            or args.max_diagnostics < 1):
        raise FatalRejection("上限参数必须为正整数")
    out_dir = Path(args.out)
    if out_dir.exists():
        raise FatalRejection(f"输出目录已存在，拒绝覆盖：{out_dir}")
    check_side_files(args.db)
    image = ImageFile(args.db)
    try:
        source_sha = image.sha256()
        diags = Diagnostics(args.max_diagnostics)
        result = extract(image, diags,
                         max_payload_bytes=args.max_payload_bytes,
                         max_pages=args.max_pages)
        try:
            out_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            raise FatalRejection(f"输出目录已存在，拒绝覆盖：{out_dir}")
        exit_code = write_outputs(
            out_dir, image, source_sha, result, diags,
            max_payload_bytes=args.max_payload_bytes,
            max_pages=args.max_pages,
            max_diagnostics=args.max_diagnostics)
    finally:
        image.close()

    counts = result["counts"]
    print(f"源镜像: {image.path}（页长 {image.page_size}，"
          f"共 {image.page_count} 页，sha256 {source_sha[:16]}…）")
    print(f"事件: 已确认 {counts['events_confirmed']}，"
          f"被隔离 {counts['events_quarantined']}；"
          f"正文: 已验证 {counts['bodies_verified']}，"
          f"未验证 {counts['bodies_unverified']}，"
          f"被隔离 {counts['bodies_quarantined']}，"
          f"未关联 {counts['bodies_unassociated']}")
    print(f"诊断: info {counts['diagnostics']['info']} / "
          f"warning {counts['diagnostics']['warning']} / "
          f"error {counts['diagnostics']['error']}"
          f" -> {out_dir / 'diagnostics.jsonl'}")
    if result["unfinished"]:
        print(f"未完成原因: {', '.join(result['unfinished'])}")
    if exit_code == EXIT_OK:
        print("退出码 0：完整提取，未发现损坏、歧义或失配")
    else:
        print(f"退出码 2：部分结果已保留在 {out_dir}，"
              "请依据诊断人工核对")
    print(f"证据边界: {EVIDENCE_BOUNDARY}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-salvage",
        description="离线接收库提取器：直接解释 SQLite 文件页，从主库镜像抢救"
                    "已接受事件与原始请求体（只读源文件，不修复、不回写）",
    )
    parser.add_argument("--db", required=True,
                        help="SQLite 3 主库镜像路径（只读打开）")
    parser.add_argument("--out", required=True,
                        help="新的输出目录（已存在则拒绝覆盖）")
    parser.add_argument("--max-payload-bytes", type=int,
                        default=DEFAULT_MAX_PAYLOAD_BYTES,
                        help=f"单条记录载荷上限（默认 {DEFAULT_MAX_PAYLOAD_BYTES}）")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES,
                        help=f"访问页数上限（默认 {DEFAULT_MAX_PAGES}）")
    parser.add_argument("--max-diagnostics", type=int,
                        default=DEFAULT_MAX_DIAGNOSTICS,
                        help=f"诊断条数上限（默认 {DEFAULT_MAX_DIAGNOSTICS}）")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except FatalRejection as exc:
        print(f"提取被拒绝：{exc}", file=sys.stderr)
        return EXIT_REJECTED
    except Exception as exc:  # 不打印裸堆栈，给出可读诊断
        print(f"提取失败（内部错误 {type(exc).__name__}）：{exc}",
              file=sys.stderr)
        return EXIT_REJECTED


if __name__ == "__main__":
    raise SystemExit(main())
