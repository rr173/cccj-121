"""正文差量包生成（服务端）：由旧文件签名 + 收件库中的新正文产生差量包。

用法::

    python3 -I partner_webhook/delta.py --db webhook.db --partner acme \\
        --event-id evt-2 --signature old.sig --out delta.bin \\
        [--literal-max 65536] [--tmp-dir 目录]

确定性匹配规则（与 :mod:`partner_webhook.apply` 及手工样例一致）：

1. 在新正文上从左向右滑动长度为 B 的窗口（新正文剩余不足 B 时结束）。
2. 窗口的弱值 + 长度在签名索引中可能有候选。命中候选时按**偏移升序**
   逐个与窗口的 SHA-256 比较强摘要；**第一个**强摘要相同的候选就是命中，
   对应引用旧文件该整块。
3. 有命中：先把此前积累的字面字节按 ``LITERAL_MAX`` 上限切段输出，再输出
   ``COPY(offset, length)``；窗口直接跳过整个块（不做重叠匹配）。
4. 无命中：窗口向前一字节。
5. 旧尾块短于 B 时**只在**新正文剩余长度恰好等于该短块长度时尝试匹配；
   其他短片段一律留在字面数据中，不求全局最小包。
6. COPY 只能引用签名中的一个**完整块**（不跨块、不任意截取）。
7. 字面数据按 ``LITERAL_MAX`` 上限切成多条 LITERAL；长时间无命中也不会
   无限积累。

统计字段（均来自真实执行路径）：

* ``roll_updates``：实际执行滚动递推的次数（每移动一字节一次）；
* ``weak_candidates``：弱值+长度通过固定位图、真正进入索引候选查询的次数；
* ``strong_checks``：只在候选存在时计算窗口 SHA-256 的次数。弱值未命中
  （或位图判否）时**不算**强摘要。

实现与内存：新正文按块从 SQLite 流式读取（``blobopen``），扫描缓冲固定
8 MiB，窗口在其中滑动；候选逐条从临时 SQLite 索引读取，不一次性物化；
字面缓冲上限 ``LITERAL_MAX``。因此内存不随正文或签名总量线性增长。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook.blocksig import WEAK_MASK
    from partner_webhook.deltaformat import (  # noqa: E402
        DEFAULT_LITERAL_MAX, DEFAULT_MAX_OUTPUT, DELTA_MAGIC,
        END_MARKER, FORMAT_VERSION, DeltaError, FormatError, MAX_COPY,
        MAX_LITERAL, MAX_OUTPUT, encode_identity, u16, u32, u64,
        write_atomic,
    )
    from partner_webhook.signature import load_signature_into_index  # noqa: E402
else:
    from .blocksig import WEAK_MASK
    from .deltaformat import (
        DEFAULT_LITERAL_MAX, DEFAULT_MAX_OUTPUT, DELTA_MAGIC, END_MARKER,
        FORMAT_VERSION, DeltaError, FormatError, MAX_COPY, MAX_LITERAL,
        MAX_OUTPUT, encode_identity, u16, u32, u64, write_atomic,
    )
    from .signature import load_signature_into_index

OP_COPY = 1
OP_LITERAL = 2

SOURCE_READ_CHUNK = 512 * 1024
SCAN_BUFFER = 8 * 1024 * 1024
DEFAULT_MAX_OPERATIONS = 4_000_000


def _connect_source(db_path: str) -> sqlite3.Connection:
    """只读打开收件库，绝不在生成差量时修改收件/outbox/档案/账本数据。"""
    from urllib.parse import quote

    uri = "file:" + quote(str(Path(db_path).resolve()), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def locate_event(conn: sqlite3.Connection, partner_id: str,
                 event_id: str) -> sqlite3.Row:
    """只按 accepted_events 主键定位一次首次接受的事件。

    合作方是主键的一部分：其他合作方的同号事件不会命中。不读
    ingest_records 里的重复/冲突行，因此“首次接受”的正文是唯一的。
    """
    row = conn.execute(
        "SELECT partner_id, event_id, source_seq, body_sha256, "
        "       ingest_record_id, accepted_at "
        "FROM accepted_events WHERE partner_id = ? AND event_id = ?",
        (partner_id, event_id),
    ).fetchone()
    if row is None:
        raise DeltaError(f"accepted_events 中不存在事件: {partner_id}/{event_id}")
    return row


def read_body_meta(conn: sqlite3.Connection, body_sha256: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT body_sha256, byte_length, length(body_blob) AS blob_length "
        "FROM raw_bodies WHERE body_sha256 = ?",
        (body_sha256,),
    ).fetchone()
    if row is None:
        raise DeltaError(f"raw_bodies 中缺少正文: {body_sha256}")
    return row


class BodyReader:
    """按块读取 ``raw_bodies.body_blob``，不把整份 BLOB 变成 bytes。"""

    def __init__(self, conn: sqlite3.Connection, body_sha256: str,
                 byte_length: int, *, chunk_size: int = SOURCE_READ_CHUNK):
        self.chunk_size = chunk_size
        self.length = int(byte_length)
        # blobopen 需要 rowid；先按主键只取 rowid，再按 rowid 打开 BLOB。
        try:
            self._blob = conn.blobopen("raw_bodies", "body_blob", body_sha256,
                                       readonly=True)
        except TypeError:
            rowid = conn.execute(
                "SELECT rowid FROM raw_bodies WHERE body_sha256 = ?",
                (body_sha256,)).fetchone()[0]
            self._blob = conn.blobopen("raw_bodies", "body_blob", rowid,
                                       readonly=True)
        self.position = 0

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        data = self._blob.read(min(n, self.chunk_size))
        self.position += len(data)
        return data

    def close(self) -> None:
        try:
            self._blob.close()
        except Exception:
            pass


def _window_weak(data, start: int, length: int) -> tuple[int, int]:
    """按定义求一个窗口的 (a, b)；仅用于段首初始化或短尾块。"""
    a = 0
    b = 0
    weight = length
    for idx in range(start, start + length):
        value = data[idx]
        a += value
        b += weight * value
        weight -= 1
    return a & WEAK_MASK, b & WEAK_MASK


class _ScanBuffer:
    """新正文的固定容量扫描缓冲，支持按需补充与已消费前缀压缩。"""

    def __init__(self, reader: BodyReader, capacity: int = SCAN_BUFFER):
        self.reader = reader
        self.capacity = capacity
        self.buf = bytearray()
        self.base = 0          # buf[0] 对应的正文绝对偏移
        self.eof = False

    @property
    def loaded_end(self) -> int:
        return self.base + len(self.buf)

    def ensure(self, abs_end: int, keep_from: int | None = None) -> None:
        """确保缓冲区覆盖到 abs_end（不含），可按需压缩已消费前缀。

        ``keep_from`` 是当前扫描位置：若请求范围放不进容量，先把该位置
        之前的字节丢弃。缓冲容量因此是硬上限，与正文总长无关。
        """
        if keep_from is not None and keep_from > self.base:
            if abs_end - self.base > self.capacity:
                drop = keep_from - self.base
                del self.buf[:drop]
                self.base = keep_from
        if abs_end <= self.loaded_end:
            return
        if abs_end - self.base > self.capacity:
            raise FormatError("扫描缓冲请求超出容量")
        while abs_end > self.loaded_end and not self.eof:
            room = self.capacity - len(self.buf)
            if room <= 0:
                raise FormatError("扫描缓冲已满仍无法满足窗口")
            need = abs_end - self.loaded_end
            want = min(self.reader.chunk_size, max(need, 4096), room)
            data = self.reader.read(want)
            if not data:
                self.eof = True
                break
            self.buf += data
        if abs_end > self.loaded_end:
            raise FormatError("正文读取提前结束")

    def discard_before(self, abs_offset: int) -> None:
        drop = abs_offset - self.base
        if drop > 0 and (drop >= self.capacity // 2
                         or len(self.buf) >= self.capacity):
            del self.buf[:drop]
            self.base = abs_offset


class DeltaBuilder:
    def __init__(self, *, signature_index, new_digest: bytes,
                 new_length: int, body_reader: BodyReader,
                 partner_id: str, event_id: str, literal_max: int,
                 max_output: int, max_operations: int, out_fh):
        self.index = signature_index
        self.header = signature_index.header
        self.B = self.header.block_size
        self.new_digest = new_digest
        self.new_length = new_length
        self.reader = body_reader
        self.partner_id = partner_id
        self.event_id = event_id
        self.literal_max = literal_max
        self.max_output = max_output
        self.max_operations = max_operations
        self.out = out_fh

        self.hasher = hashlib.sha256()
        self.ops = 0
        self.emitted = 0
        self.copy_ops = 0
        self.literal_ops = 0
        self.copy_bytes = 0
        self.literal_bytes = 0
        self.weak_candidates = 0
        self.strong_checks = 0
        self.roll_updates = 0
        self.literal_buf = bytearray()

    # ------------------------------------------------------------------ #
    def _write(self, raw: bytes) -> None:
        self.out.write(raw)
        self.hasher.update(raw)

    def _count_op(self, length: int) -> None:
        self.ops += 1
        if self.ops > self.max_operations:
            raise DeltaError("指令条数超过上限")
        self.emitted += length
        if self.emitted > self.max_output:
            raise DeltaError("目标总长超过上限")
        if self.emitted > self.new_length:
            raise DeltaError("指令输出超过新正文长度")

    def _emit_copy(self, offset: int, length: int) -> None:
        if length > MAX_COPY:
            raise DeltaError("COPY 长度超过格式上限")
        self._count_op(length)
        self._write(b"\x01" + u64(offset) + u32(length))
        self.copy_ops += 1
        self.copy_bytes += length

    def _emit_literal(self, data: bytes) -> None:
        view = memoryview(data)
        while len(view):
            piece = view[:self.literal_max]
            view = view[len(piece):]
            self._count_op(len(piece))
            self._write(b"\x02" + u32(len(piece)))
            self._write(bytes(piece))
            self.literal_ops += 1
            self.literal_bytes += len(piece)

    def _append_literal_bytes(self, data) -> None:
        """把字节追加进字面缓冲；每次按 LITERAL_MAX 上限切段写出。

        无命中时扫描器会**每走一字节**调用这里（通常只追加 1 字节），
        因此字面缓冲的字节数始终 <= LITERAL_MAX，不随扫描距离增长。
        """
        view = memoryview(data)
        while len(view):
            room = self.literal_max - len(self.literal_buf)
            if room <= 0:
                self._flush_literal()
                room = self.literal_max
            take = min(room, len(view))
            self.literal_buf += view[:take]
            view = view[take:]
            if len(self.literal_buf) >= self.literal_max:
                self._flush_literal()

    def _flush_literal(self) -> None:
        if self.literal_buf:
            data = bytes(self.literal_buf)
            self.literal_buf.clear()
            self._emit_literal(data)

    # ------------------------------------------------------------------ #
    def _header_bytes(self) -> bytes:
        partner_raw = encode_identity(self.partner_id)
        event_raw = encode_identity(self.event_id)
        return (DELTA_MAGIC + u16(FORMAT_VERSION)
                + u16(len(partner_raw)) + u16(len(event_raw))
                + u32(self.B) + u64(self.header.file_length)
                + self.header.file_sha256
                + u64(self.new_length) + self.new_digest
                + partner_raw + event_raw
                + u32(self.literal_max) + u32(self.B))

    def run(self) -> dict:
        self._write(self._header_bytes())
        self._scan()
        self._flush_literal()
        if self.emitted != self.new_length:
            raise DeltaError(
                f"指令输出总长 {self.emitted} != 新正文长度 {self.new_length}")
        self._write(END_MARKER)
        self._write(self.hasher.digest())
        return {
            "partner_id": self.partner_id,
            "event_id": self.event_id,
            "old_length": self.header.file_length,
            "old_sha256": self.header.file_sha256.hex(),
            "new_length": self.new_length,
            "new_sha256": self.new_digest.hex(),
            "block_size": self.B,
            "copy_ops": self.copy_ops,
            "literal_ops": self.literal_ops,
            "copy_bytes": self.copy_bytes,
            "literal_bytes": self.literal_bytes,
            "ops": self.ops,
            "weak_candidates": self.weak_candidates,
            "strong_checks": self.strong_checks,
            "roll_updates": self.roll_updates,
        }

    # ------------------------------------------------------------------ #
    def _lookup_match(self, window_bytes: bytes, length: int, weak: int):
        """弱值命中后按偏移升序逐个比对强摘要，返回最小偏移匹配块。

        先用固定位图过滤明显不可能的长度/弱值组合；位图判“可能”后再
        打开候选游标。只有确实存在候选行时才为窗口计算一次 SHA-256——
        弱值未命中或候选为空时绝不做强摘要。
        """
        if not self.index.bloom.maybe(length, weak):
            return None
        self.weak_candidates += 1
        cursor = self.index.lookup(length, weak)
        try:
            first = next(cursor, None)
            if first is None:
                return None
            strong = hashlib.sha256(window_bytes).digest()
            self.strong_checks += 1
            offset, block_length, digest = first
            if digest == strong:
                return int(offset), int(block_length)
            for offset, block_length, digest in cursor:
                if digest == strong:
                    return int(offset), int(block_length)
            return None
        finally:
            cursor.close()

    def _scan(self) -> None:
        B = self.B
        N = self.new_length
        header = self.header
        # 缓冲容量至少容纳两个块长：B 最大可达 16 MiB，不能小于一个窗口。
        buf = _ScanBuffer(self.reader, capacity=max(SCAN_BUFFER, 2 * B))
        pos = 0
        tail_len = header.tail_length

        while pos < N:
            remaining = N - pos
            if tail_len and tail_len < B and remaining == tail_len:
                # 短尾块只在剩余长度恰为该长度时尝试
                buf.ensure(N, keep_from=pos)
                window_bytes = bytes(buf.buf[pos - buf.base:pos - buf.base + tail_len])
                a, b = _window_weak(window_bytes, 0, tail_len)
                weak = ((b & WEAK_MASK) << 16) | (a & WEAK_MASK)
                matched = self._lookup_match(window_bytes, tail_len, weak)
                if matched is not None:
                    self._flush_literal()
                    self._emit_copy(*matched)
                    pos += tail_len
                    continue
                self._append_literal_bytes(window_bytes)
                pos = N
                break

            if remaining < B:
                buf.ensure(N, keep_from=pos)
                self._append_literal_bytes(
                    buf.buf[pos - buf.base:pos - buf.base + remaining])
                pos = N
                break

            # 载入一段可用缓冲；段内位置 [pos, pos+limit) 可完整开窗。
            want_end = min(N, pos + buf.capacity)
            buf.ensure(want_end, keep_from=pos)
            limit = min(remaining - B + 1, buf.loaded_end - pos - B + 1)
            if limit <= 0:
                raise FormatError("扫描缓冲不足一个窗口")
            base = buf.base
            data = buf.buf
            start = pos
            seg_start = pos
            matched = None
            a, b = _window_weak(data, start - base, B)
            weak = ((b & WEAK_MASK) << 16) | (a & WEAK_MASK)
            bloom_maybe = self.index.bloom.maybe
            last = limit - 1
            for k in range(limit):
                index0 = start - base + k
                if bloom_maybe(B, weak):
                    window_bytes = bytes(data[index0:index0 + B])
                    matched = self._lookup_match(window_bytes, B, weak)
                    if matched is not None:
                        # 此前的字节进入字面数据
                        self._append_literal_bytes(
                            data[seg_start - base:index0])
                        self._flush_literal()
                        self._emit_copy(*matched)
                        pos = start + k + B
                        break
                if k == last:
                    break
                # 滚动到下一个窗口：移出 u，加入 v
                u = data[index0]
                v = data[index0 + B]
                a = (a - u + v) & WEAK_MASK
                b = (b - B * u + a) & WEAK_MASK
                self.roll_updates += 1
                weak = ((b & WEAK_MASK) << 16) | (a & WEAK_MASK)
            if matched is not None:
                buf.discard_before(pos)
                continue
            # 整段都未命中：全部进入字面数据
            self._append_literal_bytes(data[seg_start - base:start - base + limit])
            pos = start + limit
            buf.discard_before(pos)


def generate_delta(db_path: str, partner_id: str, event_id: str,
                   signature_path: str, out_path: str, *,
                   literal_max: int = DEFAULT_LITERAL_MAX,
                   max_output: int = DEFAULT_MAX_OUTPUT,
                   max_operations: int = DEFAULT_MAX_OPERATIONS,
                   index_cache_kib: int = 4096,
                   tmp_dir: str | None = None) -> dict:
    if not (1 <= literal_max <= MAX_LITERAL):
        raise FormatError(f"LITERAL 上限必须在 1..{MAX_LITERAL}")
    if not (1 <= max_output <= MAX_OUTPUT):
        raise FormatError("目标总长上限超出范围")
    encode_identity(partner_id)
    encode_identity(event_id)
    out_path = Path(out_path)
    if out_path.exists():
        raise FileExistsError(f"差量包输出已存在，拒绝覆盖: {out_path}")

    source = _connect_source(db_path)
    tmpdir = tempfile.mkdtemp(prefix="pwdelta-", dir=tmp_dir)
    index = None
    body = None
    try:
        row = locate_event(source, partner_id, event_id)
        meta_row = read_body_meta(source, row["body_sha256"])
        byte_length = int(meta_row["byte_length"])
        if int(meta_row["blob_length"]) != byte_length:
            raise DeltaError("raw_bodies 记录长度与 BLOB 实际长度不符")
        if byte_length > max_output:
            raise DeltaError("新正文长度超过目标总长上限")

        # 第一遍：流式读取正文并算整文件 SHA-256（不缓存正文本身）
        new_hasher = hashlib.sha256()
        body = BodyReader(source, row["body_sha256"], byte_length)
        while True:
            chunk = body.read(body.chunk_size)
            if not chunk:
                break
            new_hasher.update(chunk)
        if body.position != byte_length:
            raise DeltaError("正文读取长度与登记不符")
        new_digest = new_hasher.digest()
        if new_digest.hex() != row["body_sha256"]:
            raise DeltaError(
                "正文内容与 accepted_events 登记的 SHA-256 不符，拒绝生成")
        body.close()

        index = load_signature_into_index(
            signature_path, os.path.join(tmpdir, "sig-index.sqlite"),
            cache_kib=index_cache_kib)
        if index.header.file_length > MAX_OUTPUT:
            raise FormatError("旧文件长度超过格式上限")

        # 第二遍：重新打开正文，生成指令
        body = BodyReader(source, row["body_sha256"], byte_length)
        stats_holder: dict = {}

        def writer(fh):
            builder = DeltaBuilder(
                signature_index=index, new_digest=new_digest,
                new_length=byte_length, body_reader=body,
                partner_id=partner_id, event_id=event_id,
                literal_max=literal_max, max_output=max_output,
                max_operations=max_operations, out_fh=fh,
            )
            stats_holder.update(builder.run())

        write_atomic(out_path, writer)
        stats = stats_holder
        stats["delta"] = str(out_path)
        stats["delta_bytes"] = os.stat(out_path).st_size
        stats["source_byte_length"] = byte_length
        return stats
    finally:
        if body is not None:
            body.close()
        if index is not None:
            index.close()
        source.close()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def command_delta(args) -> int:
    try:
        summary = generate_delta(
            args.db, args.partner, args.event_id, args.signature, args.out,
            literal_max=args.literal_max, max_output=args.max_output,
            max_operations=args.max_operations,
            index_cache_kib=args.index_cache_kib, tmp_dir=args.tmp_dir,
        )
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (DeltaError, FormatError, OSError, sqlite3.Error) as exc:
        print(f"生成差量包失败: {exc}", file=sys.stderr)
        return 1
    json.dump(summary, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-delta",
        description="由旧文件签名与服务端收件正文生成差量包（pwdelta v1）",
    )
    parser.add_argument("--db", required=True, help="收件库（只读打开）")
    parser.add_argument("--partner", required=True, help="合作方 ID")
    parser.add_argument("--event-id", required=True, help="事件 ID")
    parser.add_argument("--signature", required=True, help="下游交来的旧文件签名")
    parser.add_argument("--out", required=True, help="新差量包路径（不得已存在）")
    parser.add_argument("--literal-max", type=int, default=DEFAULT_LITERAL_MAX,
                        help=f"单条 LITERAL 上限（默认 {DEFAULT_LITERAL_MAX}）")
    parser.add_argument("--max-output", type=int, default=DEFAULT_MAX_OUTPUT,
                        help="目标总长上限（默认 1 TiB）")
    parser.add_argument("--max-operations", type=int, default=DEFAULT_MAX_OPERATIONS,
                        help="指令条数上限")
    parser.add_argument("--index-cache-kib", type=int, default=4096,
                        help="临时索引用 SQLite 页缓存上限（KiB）")
    parser.add_argument("--tmp-dir", default=None,
                        help="临时索引目录（默认系统临时目录）")
    parser.set_defaults(func=command_delta)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
