"""正文差量交接：旧文件块签名（``blocksig v1``）的生成与严格读取。

用法::

    python3 -I partner_webhook/signature.py --old 旧文件 --block-size 4096 \\
        --out old.sig

签名格式见 :mod:`partner_webhook.deltaformat` 模块文档。本模块同时提供
:class:`SignatureIndex`：把已严格校验的签名块录入一个**临时 SQLite 索引**，
供 ``delta`` 按 ``(length, weak)`` 查询候选块。索引不放在内存里，也不写入
源库；调用方负责在临时目录中创建并在结束时删除。

内存构成（签名端）：只保留一个块（B 字节）与分块读取缓冲；整文件摘要
边读边算。索引端：SQLite 页缓存固定上限 + 固定大小的弱值预过滤位图。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook.blocksig import WEAK_MAX, weak_checksum  # noqa: E402
    from partner_webhook.deltaformat import (  # noqa: E402
        DEFAULT_READ_CHUNK, FormatError, HashingReader, ReadWrapper, SIG_BLOCK_RECORD,
        SIG_HEADER_FIXED, SIG_MAGIC, FORMAT_VERSION, MAX_BLOCK_SIZE,
        decode_u32, decode_u64, sha256_hex, u16, u32, u64, write_atomic,
    )
else:
    from .blocksig import WEAK_MAX, weak_checksum
    from .deltaformat import (
        DEFAULT_READ_CHUNK, FormatError, HashingReader, ReadWrapper, SIG_BLOCK_RECORD,
        SIG_HEADER_FIXED, SIG_MAGIC, FORMAT_VERSION, MAX_BLOCK_SIZE,
        decode_u32, decode_u64, sha256_hex, u16, u32, u64, write_atomic,
    )


@dataclass(frozen=True)
class SignatureHeader:
    block_size: int
    file_length: int
    file_sha256: bytes
    block_count: int

    @property
    def tail_length(self) -> int:
        if self.block_count == 0:
            return 0
        return self.file_length - (self.block_count - 1) * self.block_size

    @property
    def tail_offset(self) -> int:
        return (self.block_count - 1) * self.block_size


def _scan_file(path: Path, block_size: int, size: int, visitor) -> None:
    """按 B 字节连续切块读取旧文件，逐块回调；不一次读完整文件。"""
    actual = 0
    with open(path, "rb") as fh:
        offset = 0
        while offset < size:
            want = min(block_size, size - offset)
            data = fh.read(want)
            if len(data) != want:
                raise FormatError("旧文件读取短读", offset=offset)
            visitor(offset, data)
            actual += len(data)
            offset += want
        if fh.read(1):
            raise FormatError("旧文件在签名过程中增长", offset=size)
    if actual != size:
        raise FormatError("旧文件长度在签名过程中变化")


def write_signature(old_path: str | Path, block_size: int,
                    out_path: str | Path, *,
                    chunk_size: int = DEFAULT_READ_CHUNK) -> dict:
    """为旧文件生成块签名。已有输出文件拒绝覆盖。

    两遍扫描：第一遍只算整文件 SHA-256（头部需要），第二遍逐块求弱值、
    强摘要并直接写入临时文件。因此签名端内存只有“一个块”，不随文件或
    块数增长。
    """
    if not isinstance(block_size, int) or block_size <= 0:
        raise FormatError("块长 B 必须是正整数")
    if block_size > MAX_BLOCK_SIZE:
        raise FormatError(f"块长 B 超过上限 {MAX_BLOCK_SIZE}")
    old_path = Path(old_path)
    out_path = Path(out_path)
    if old_path.resolve() == out_path.resolve():
        raise FormatError("签名输出不能与旧文件同名")
    if out_path.exists():
        raise FileExistsError(f"签名输出已存在，拒绝覆盖: {out_path}")

    size = os.stat(old_path).st_size
    block_count = (size + block_size - 1) // block_size

    file_hasher = hashlib.sha256()

    def hash_visitor(_offset: int, data: bytes) -> None:
        file_hasher.update(data)

    _scan_file(old_path, block_size, size, hash_visitor)
    file_digest = file_hasher.digest()
    header_raw = (SIG_MAGIC + u16(FORMAT_VERSION) + u32(block_size)
                  + u64(size) + file_digest + u64(block_count))

    def writer(fh):
        fh.write(header_raw)
        hasher = hashlib.sha256()
        hasher.update(header_raw)

        def block_visitor(offset: int, data: bytes) -> None:
            record = (u64(offset) + u32(len(data))
                      + u32(weak_checksum(data)) + hashlib.sha256(data).digest())
            fh.write(record)
            hasher.update(record)

        _scan_file(old_path, block_size, size, block_visitor)
        fh.write(hasher.digest())

    write_atomic(out_path, writer)
    return {
        "signature": str(out_path),
        "block_size": block_size,
        "old_length": size,
        "old_sha256": file_digest.hex(),
        "block_count": block_count,
        "signature_bytes": os.stat(out_path).st_size,
    }


def _read_signature_header(reader: ReadWrapper) -> SignatureHeader:
    magic = reader.read_exact(len(SIG_MAGIC))
    if magic != SIG_MAGIC:
        raise FormatError("签名 magic 不匹配", offset=0)
    version = int.from_bytes(reader.read_exact(2), "big")
    if version != FORMAT_VERSION:
        raise FormatError(f"不支持的签名格式版本 {version}", offset=8)
    block_size = decode_u32(reader.read_exact(4))
    if block_size == 0 or block_size > MAX_BLOCK_SIZE:
        raise FormatError(f"签名块长超出范围: {block_size}", offset=10)
    file_length = decode_u64(reader.read_exact(8))
    file_digest = reader.read_exact(32)
    block_count = decode_u64(reader.read_exact(8))
    expected_count = ((file_length + block_size - 1) // block_size
                      if file_length else 0)
    if block_count != expected_count:
        raise FormatError(
            f"块数与文件长度不一致: 声明 {block_count}, 应为 {expected_count}",
            offset=8 + 2 + 4 + 8 + 32,
        )
    if block_count > (1 << 40):
        raise FormatError("块数超出合理范围", offset=58)
    return SignatureHeader(block_size=block_size, file_length=file_length,
                           file_sha256=file_digest, block_count=block_count)


class WeakFilter:
    """固定大小的弱值预过滤位图（可能误报、绝不漏报）。

    只用于减少 SQLite 点查询；真正候选仍从临时索引按 ``(length, weak)``
    精确取出并核对 SHA-256。位图大小按块数选择，且有硬上限，因此不会随
    签名总量线性增长。
    """

    MIN_BITS = 1 << 20
    MAX_BITS = 1 << 26
    BITS_PER_BLOCK = 512

    def __init__(self, block_count: int):
        want = max(self.MIN_BITS, block_count * self.BITS_PER_BLOCK)
        bits = 1
        while bits < want:
            bits <<= 1
        bits = min(bits, self.MAX_BITS)
        self.bits = bits
        self.mask = bits - 1
        self.data = bytearray(bits // 8)

    def _index(self, length: int, weak: int) -> int:
        mixed = (weak ^ ((length * 0x9E3779B1) & 0xFFFFFFFF)) & 0xFFFFFFFF
        mixed = (mixed * 0x85EBCA77) & 0xFFFFFFFF
        mixed ^= mixed >> 13
        return mixed & self.mask

    def add(self, length: int, weak: int) -> None:
        idx = self._index(length, weak)
        self.data[idx >> 3] |= 1 << (idx & 7)

    def maybe(self, length: int, weak: int) -> bool:
        idx = self._index(length, weak)
        return bool(self.data[idx >> 3] & (1 << (idx & 7)))


class SignatureIndex:
    """已严格校验签名的临时 SQLite 索引。"""

    def __init__(self, db_path: str | Path, header: SignatureHeader,
                 *, cache_kib: int = 4096):
        self.db_path = str(db_path)
        self.header = header
        self.bloom = WeakFilter(header.block_count)
        self.conn = sqlite3.connect(self.db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.execute(f"PRAGMA cache_size = -{int(cache_kib)}")
        self.conn.execute("PRAGMA temp_store = FILE")
        self.conn.execute(
            "CREATE TABLE blocks ("
            "offset INTEGER PRIMARY KEY, length INTEGER NOT NULL, "
            "weak INTEGER NOT NULL, sha BLOB NOT NULL)"
        )
        self._batch: list[tuple[int, int, int, bytes]] = []
        self._batch_size = 500
        self._closed = False

    def add_block(self, offset: int, length: int, weak: int,
                  digest: bytes) -> None:
        self._batch.append((offset, length, weak, digest))
        self.bloom.add(length, weak)
        if len(self._batch) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._batch:
            return
        self.conn.executemany(
            "INSERT INTO blocks (offset, length, weak, sha) VALUES (?, ?, ?, ?)",
            self._batch,
        )
        self._batch.clear()

    def finish(self) -> None:
        self.flush()
        self.conn.execute(
            "CREATE INDEX blocks_lookup ON blocks(length, weak, offset)"
        )

    def lookup(self, length: int, weak: int):
        """按 (length, weak) 依 offset 升序流式返回候选，不整体物化。"""
        cursor = self.conn.execute(
            "SELECT offset, length, sha FROM blocks "
            "WHERE length = ? AND weak = ? ORDER BY offset",
            (length, weak),
        )
        try:
            for row in cursor:
                yield int(row[0]), int(row[1]), bytes(row[2])
        finally:
            cursor.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def load_signature_into_index(sig_path: str | Path, db_path: str | Path, *,
                              read_chunk_limit: int | None = None,
                              cache_kib: int = 4096) -> SignatureIndex:
    """严格校验签名文件并建立临时索引。

    校验：magic/版本/B 范围/声明长度与块数一致/文件总大小恰好匹配/
    每块 offset 与 length 精确覆盖连续非重叠区间/弱值范围/摘要字段长度/
    整文件 SHA-256/结尾无额外字节。任何一项失败都抛 :class:`FormatError`。
    """
    sig_path = Path(sig_path)
    actual_size = os.stat(sig_path).st_size
    with open(sig_path, "rb") as raw_fh:
        reader = ReadWrapper(HashingReader(raw_fh),
                             chunk_limit=read_chunk_limit)
        header = _read_signature_header(reader)
        expected_size = (SIG_HEADER_FIXED + header.block_count * SIG_BLOCK_RECORD
                         + 32)
        if actual_size != expected_size:
            raise FormatError(
                f"签名文件大小不符: 实际 {actual_size}, 头部声明应 {expected_size}",
                offset=min(actual_size, expected_size),
            )
        index = SignatureIndex(db_path, header, cache_kib=cache_kib)
        try:
            for i in range(header.block_count):
                record_offset = SIG_HEADER_FIXED + i * SIG_BLOCK_RECORD
                raw = reader.read_exact(SIG_BLOCK_RECORD)
                offset = decode_u64(raw[0:8])
                length = decode_u32(raw[8:12])
                weak = decode_u32(raw[12:16])
                digest = raw[16:48]
                expected_offset = i * header.block_size
                expected_length = min(header.block_size,
                                      header.file_length - expected_offset)
                if offset != expected_offset:
                    raise FormatError(
                        f"第 {i} 块偏移不连续: {offset} != {expected_offset}",
                        offset=record_offset,
                    )
                if length != expected_length or length <= 0:
                    raise FormatError(
                        f"第 {i} 块长度不符: {length} != {expected_length}",
                        offset=record_offset + 8,
                    )
                if weak > WEAK_MAX:
                    raise FormatError(f"第 {i} 块弱值超出 32 位",
                                      offset=record_offset + 12)
                if len(digest) != 32:
                    raise FormatError(f"第 {i} 块摘要字段长度错误",
                                      offset=record_offset + 16)
                index.add_block(offset, length, weak, digest)
            trailer_offset = reader.bytes_read
            expected = reader.snapshot()
            trailer = reader.read_exact(32)
            if expected != trailer:
                raise FormatError("签名整文件摘要不符", offset=trailer_offset)
            if not reader.at_eof():
                raise FormatError("签名结尾存在额外字节", offset=reader.bytes_read)
            index.finish()
        except BaseException:
            index.close()
            raise
    return index


def _encode_header(header: SignatureHeader) -> bytes:
    return (SIG_MAGIC + u16(FORMAT_VERSION) + u32(header.block_size)
            + u64(header.file_length) + header.file_sha256
            + u64(header.block_count))


def command_signature(args) -> int:
    try:
        summary = write_signature(args.old, args.block_size, args.out)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (OSError, FormatError) as exc:
        print(f"签名失败: {exc}", file=sys.stderr)
        return 1
    _print_json(summary)
    return 0


def _print_json(obj) -> None:
    import json
    json.dump(obj, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-signature",
        description="为旧正文文件生成块签名（blocksig v1）",
    )
    parser.add_argument("--old", required=True, help="旧正文文件")
    parser.add_argument("--block-size", type=int, required=True,
                        help="块长 B（正整数，<= 16 MiB）")
    parser.add_argument("--out", required=True, help="新签名文件路径（不得已存在）")
    parser.set_defaults(func=command_signature)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
