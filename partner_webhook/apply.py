"""差量包应用（下游）：用旧文件与差量包还原新正文。

用法::

    python3 -I partner_webhook/apply.py --old 旧文件 --delta 差量包 \\
        --out 新正文 [--max-block N] [--max-literal N] [--max-output N] \\
        [--max-operations N]

严格顺序：

1. 打开旧文件，核对整文件长度与 SHA-256 是否等于包头部绑定值；
2. 解析头部：版本、身份 UTF-8、B / LITERAL / COPY / 目标长度上限，
   **先检查声明再读取/分配**；不信任包内任何自报长度；
3. 逐条执行 COPY / LITERAL：COPY 必须是签名中的完整块（偏移按 B 对齐、
   长度等于该块真实长度、不越旧文件），字面截短、未知指令、单条指令
   上限、指令条数、累计输出上限都即时检查；
4. 核对结束标记、整包 SHA-256、结束后无额外字节、输出总长；
5. **独立**计算新正文 SHA-256，与头部声明比较；一致才把临时文件改名
   为目标。任何失败都删除临时文件，不留下可误当完整新正文的目标。

错误信息带可定位的包偏移。已有目标拒绝覆盖；旧文件、包和签名只读。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook.deltaformat import (  # noqa: E402
        DEFAULT_MAX_OUTPUT, DELTA_MAGIC, END_MARKER, FORMAT_VERSION,
        FormatError, MAX_BLOCK_SIZE, MAX_ID_BYTES, MAX_LITERAL, MAX_OUTPUT,
        HashingReader, ReadWrapper, decode_identity, decode_u32, decode_u64,
        u16, u32, u64,
    )
else:
    from .deltaformat import (
        DEFAULT_MAX_OUTPUT, DELTA_MAGIC, END_MARKER, FORMAT_VERSION,
        FormatError, MAX_BLOCK_SIZE, MAX_ID_BYTES, MAX_LITERAL, MAX_OUTPUT,
        HashingReader, ReadWrapper, decode_identity, decode_u32, decode_u64,
        u16, u32, u64,
    )

OP_COPY = 1
OP_LITERAL = 2
IO_CHUNK = 1024 * 1024

DEFAULT_MAX_BLOCK = MAX_BLOCK_SIZE
DEFAULT_MAX_LITERAL = MAX_LITERAL
DEFAULT_MAX_OPERATIONS = 4_000_000
DEFAULT_MAX_ID_BYTES = MAX_ID_BYTES


@dataclass
class DeltaHeader:
    block_size: int
    old_length: int
    old_sha256: bytes
    new_length: int
    new_sha256: bytes
    partner_id: str
    event_id: str
    literal_cap: int
    copy_cap: int
    body_offset: int = 0


@dataclass
class ApplyLimits:
    max_block: int = DEFAULT_MAX_BLOCK
    max_literal: int = DEFAULT_MAX_LITERAL
    max_output: int = DEFAULT_MAX_OUTPUT
    max_operations: int = DEFAULT_MAX_OPERATIONS
    max_id_bytes: int = DEFAULT_MAX_ID_BYTES

    def validate(self) -> None:
        if not (1 <= self.max_block <= MAX_BLOCK_SIZE):
            raise FormatError(f"max_block 超出 1..{MAX_BLOCK_SIZE}")
        if not (1 <= self.max_literal <= MAX_LITERAL):
            raise FormatError(f"max_literal 超出 1..{MAX_LITERAL}")
        if not (0 <= self.max_output <= MAX_OUTPUT):
            raise FormatError(f"max_output 超出 0..{MAX_OUTPUT}")
        if not (1 <= self.max_operations <= 0xFFFFFFFF):
            raise FormatError(f"max_operations 超出 1..{0xFFFFFFFF}")
        if not (1 <= self.max_id_bytes <= MAX_ID_BYTES):
            raise FormatError(f"max_id_bytes 超出 1..{MAX_ID_BYTES}")


@dataclass
class ApplyReport:
    partner_id: str
    event_id: str
    old_length: int
    old_sha256: str
    new_length: int
    new_sha256: str
    copy_ops: int = 0
    literal_ops: int = 0
    copy_bytes: int = 0
    literal_bytes: int = 0
    package_bytes: int = 0
    operations: int = 0
    short_reads: int = 0
    read_calls: int = 0
    content_verified: bool = False

    def as_dict(self) -> dict:
        return {
            "partner_id": self.partner_id,
            "event_id": self.event_id,
            "old_length": self.old_length,
            "old_sha256": self.old_sha256,
            "new_length": self.new_length,
            "new_sha256": self.new_sha256,
            "copy_ops": self.copy_ops,
            "literal_ops": self.literal_ops,
            "copy_bytes": self.copy_bytes,
            "literal_bytes": self.literal_bytes,
            "package_bytes": self.package_bytes,
            "operations": self.operations,
            "short_reads": self.short_reads,
            "read_calls": self.read_calls,
            "content_verified": self.content_verified,
        }


def _encode_header(header: DeltaHeader) -> bytes:
    partner_raw = header.partner_id.encode("utf-8")
    event_raw = header.event_id.encode("utf-8")
    return (DELTA_MAGIC + u16(FORMAT_VERSION)
            + u16(len(partner_raw)) + u16(len(event_raw))
            + u32(header.block_size) + u64(header.old_length)
            + header.old_sha256 + u64(header.new_length)
            + header.new_sha256 + partner_raw + event_raw
            + u32(header.literal_cap) + u32(header.copy_cap))


def parse_header(reader: ReadWrapper, limits: ApplyLimits) -> DeltaHeader:
    magic = reader.read_exact(len(DELTA_MAGIC))
    if magic != DELTA_MAGIC:
        raise FormatError("差量包 magic 不匹配", offset=0)
    version = int.from_bytes(reader.read_exact(2), "big")
    if version != FORMAT_VERSION:
        raise FormatError(f"不支持的差量包版本 {version}", offset=8)
    partner_len = int.from_bytes(reader.read_exact(2), "big")
    event_len = int.from_bytes(reader.read_exact(2), "big")
    if not 1 <= partner_len <= limits.max_id_bytes:
        raise FormatError(f"合作方身份长度越界: {partner_len}", offset=10)
    if not 1 <= event_len <= limits.max_id_bytes:
        raise FormatError(f"事件身份长度越界: {event_len}", offset=12)
    block_size = decode_u32(reader.read_exact(4))
    if not 1 <= block_size <= limits.max_block:
        raise FormatError(f"块长 B 越界: {block_size}", offset=14)
    old_length = decode_u64(reader.read_exact(8))
    old_sha = reader.read_exact(32)
    new_length = decode_u64(reader.read_exact(8))
    new_sha = reader.read_exact(32)
    if new_length > limits.max_output:
        raise FormatError(
            f"声明的新正文长度 {new_length} 超过上限 {limits.max_output}",
            offset=62)
    # 声明长度已检查，再按声明读取身份字段。
    partner_raw = reader.read_exact(partner_len)
    event_raw = reader.read_exact(event_len)
    partner = decode_identity(partner_raw, field="合作方 ID")
    event = decode_identity(event_raw, field="事件 ID")
    literal_cap = decode_u32(reader.read_exact(4))
    copy_cap = decode_u32(reader.read_exact(4))
    if not 1 <= literal_cap <= limits.max_literal:
        raise FormatError(f"LITERAL 上限字段越界: {literal_cap}",
                          offset=reader.bytes_read - 8)
    if not 1 <= copy_cap <= block_size:
        raise FormatError(f"COPY 上限字段越界: {copy_cap}",
                          offset=reader.bytes_read - 4)
    header = DeltaHeader(
        block_size=block_size, old_length=old_length, old_sha256=old_sha,
        new_length=new_length, new_sha256=new_sha, partner_id=partner,
        event_id=event, literal_cap=literal_cap, copy_cap=copy_cap,
        body_offset=reader.bytes_read,
    )
    if len(_encode_header(header)) != header.body_offset:
        raise FormatError("头部编码长度不一致", offset=header.body_offset)
    return header


def _open_verified_old(path: Path, header: DeltaHeader):
    """打开旧文件并*在同一句柄上*核对长度与摘要，返回可复用的句柄。"""
    fh = open(path, "rb")
    try:
        size = os.fstat(fh.fileno()).st_size
        if size != header.old_length:
            raise FormatError(
                f"旧文件长度不符: {size} != {header.old_length}")
        hasher = hashlib.sha256()
        while True:
            chunk = fh.read(IO_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
        if hasher.digest() != header.old_sha256:
            raise FormatError("旧文件 SHA-256 与差量包绑定值不符")
        fh.seek(0)
        return fh
    except BaseException:
        fh.close()
        raise


def _execute(reader: ReadWrapper, header: DeltaHeader, limits: ApplyLimits,
             old_fh, out_fh, report: ApplyReport) -> None:
    B = header.block_size
    old_length = header.old_length
    literal_cap = min(header.literal_cap, limits.max_literal)
    copy_cap = min(header.copy_cap, limits.max_block)
    produced = 0
    new_hasher = hashlib.sha256() if out_fh is not None else None
    operations = 0
    while True:
        op_offset = reader.bytes_read
        opcode = reader.read_exact(1)
        if opcode == b"P":
            rest = reader.read_exact(len(END_MARKER) - 1)
            if opcode + rest != END_MARKER:
                raise FormatError("结束标记损坏", offset=op_offset)
            expected = reader.snapshot()
            trailer = reader.read_exact(32)
            if trailer != expected:
                raise FormatError("整包 SHA-256 校验失败",
                                  offset=reader.bytes_read - 32)
            if not reader.at_eof():
                raise FormatError("结束标记之后存在额外字节",
                                  offset=reader.bytes_read - 1)
            if produced != header.new_length:
                raise FormatError(
                    f"目标总长不符: {produced} != {header.new_length}",
                    offset=op_offset)
            if new_hasher is not None:
                actual = new_hasher.digest()
                if actual != header.new_sha256:
                    raise FormatError("新正文 SHA-256 与头部声明不符",
                                      offset=reader.bytes_read)
                report.new_sha256 = actual.hex()
                report.content_verified = True
            return
        if opcode == b"\x01":
            operations += 1
            if operations > limits.max_operations:
                raise FormatError("指令条数超过上限", offset=op_offset)
            raw_offset = reader.read_exact(8)
            raw_length = reader.read_exact(4)
            copy_offset = decode_u64(raw_offset)
            copy_length = decode_u32(raw_length)
            if copy_offset % B != 0:
                raise FormatError(
                    f"COPY 偏移未按 B 对齐（不是签名块起点）: {copy_offset}",
                    offset=op_offset + 1)
            if copy_offset >= old_length:
                raise FormatError(
                    f"COPY 偏移越界: {copy_offset} >= {old_length}",
                    offset=op_offset + 1)
            block_length = min(B, old_length - copy_offset)
            if copy_length != block_length:
                raise FormatError(
                    f"COPY 必须是完整块: 声明 {copy_length}, 该块应为 {block_length}",
                    offset=op_offset + 9)
            if copy_length > copy_cap:
                raise FormatError(f"COPY 长度超过上限: {copy_length}",
                                  offset=op_offset + 9)
            if produced + copy_length > header.new_length:
                raise FormatError("COPY 使输出超过目标总长",
                                  offset=op_offset + 1)
            remaining = copy_length
            if out_fh is not None:
                old_fh.seek(copy_offset)
                while remaining:
                    chunk = old_fh.read(min(IO_CHUNK, remaining))
                    if not chunk:
                        raise FormatError("旧文件读取短读，无法执行 COPY",
                                          offset=op_offset + 1)
                    out_fh.write(chunk)
                    new_hasher.update(chunk)
                    remaining -= len(chunk)
            produced += copy_length
            report.copy_ops += 1
            report.copy_bytes += copy_length
        elif opcode == b"\x02":
            operations += 1
            if operations > limits.max_operations:
                raise FormatError("指令条数超过上限", offset=op_offset)
            raw_length = reader.read_exact(4)
            length = decode_u32(raw_length)
            if length == 0:
                raise FormatError("LITERAL 长度不能为 0", offset=op_offset + 1)
            if length > literal_cap:
                raise FormatError(
                    f"LITERAL 长度 {length} 超过上限 {literal_cap}",
                    offset=op_offset + 1)
            if produced + length > header.new_length:
                raise FormatError("LITERAL 使输出超过目标总长",
                                  offset=op_offset + 1)
            remaining = length
            while remaining:
                chunk = reader.read_exact(min(IO_CHUNK, remaining))
                if out_fh is not None:
                    out_fh.write(chunk)
                    new_hasher.update(chunk)
                remaining -= len(chunk)
            produced += length
            report.literal_ops += 1
            report.literal_bytes += length
        else:
            raise FormatError(f"未知指令码 0x{opcode[0]:02x}", offset=op_offset)


def _walk(package_path: Path, limits: ApplyLimits, *,
          old_path: Path | None, out_fh,
          read_chunk_limit: int | None) -> tuple[DeltaHeader, ApplyReport]:
    package_size = os.stat(package_path).st_size
    old_fh = None
    with open(package_path, "rb") as raw_pkg:
        reader = ReadWrapper(HashingReader(raw_pkg),
                             chunk_limit=read_chunk_limit)
        header = parse_header(reader, limits)
        report = ApplyReport(
            partner_id=header.partner_id, event_id=header.event_id,
            old_length=header.old_length,
            old_sha256=header.old_sha256.hex(),
            new_length=header.new_length,
            new_sha256=header.new_sha256.hex(),
            package_bytes=package_size,
        )
        if old_path is not None:
            old_fh = _open_verified_old(old_path, header)
        try:
            _execute(reader, header, limits, old_fh, out_fh, report)
        finally:
            report.short_reads = reader.short_reads
            report.read_calls = reader.calls
            if old_fh is not None:
                old_fh.close()
    report.operations = report.copy_ops + report.literal_ops
    return header, report


def apply_delta(old_path: str, package_path: str, target_path: str, *,
                limits: ApplyLimits | None = None,
                read_chunk_limit: int | None = None) -> ApplyReport:
    limits = limits or ApplyLimits()
    limits.validate()
    target = Path(target_path)
    if target.exists():
        raise FileExistsError(f"目标已存在，拒绝覆盖: {target}")
    if target.resolve() == Path(package_path).resolve():
        raise FormatError("目标不能与差量包同名")
    if target.resolve() == Path(old_path).resolve():
        raise FormatError("目标不能与旧文件同名")
    parent = target.parent if str(target.parent) else Path(".")
    tmp = parent / (target.name + ".part")
    if tmp.exists():
        tmp.unlink()
    try:
        with open(tmp, "wb") as out_fh:
            header, report = _walk(
                Path(package_path), limits, old_path=Path(old_path),
                out_fh=out_fh, read_chunk_limit=read_chunk_limit)
            out_fh.flush()
            os.fsync(out_fh.fileno())
        if os.stat(tmp).st_size != header.new_length:
            raise FormatError("写入长度与目标总长不符")
        os.replace(tmp, target)
        return report
    except BaseException:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise


def inspect_package(package_path: str, *,
                    limits: ApplyLimits | None = None,
                    read_chunk_limit: int | None = None) -> ApplyReport:
    """只校验包结构/完整性并报告计数，不还原、不输出业务正文。"""
    limits = limits or ApplyLimits()
    limits.validate()
    _, report = _walk(Path(package_path), limits, old_path=None, out_fh=None,
                      read_chunk_limit=read_chunk_limit)
    return report


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-block", type=int, default=DEFAULT_MAX_BLOCK)
    parser.add_argument("--max-literal", type=int, default=DEFAULT_MAX_LITERAL)
    parser.add_argument("--max-output", type=int, default=DEFAULT_MAX_OUTPUT)
    parser.add_argument("--max-operations", type=int,
                        default=DEFAULT_MAX_OPERATIONS)
    parser.add_argument("--max-id-bytes", type=int, default=DEFAULT_MAX_ID_BYTES)


def _limits_from(args) -> ApplyLimits:
    return ApplyLimits(max_block=args.max_block,
                       max_literal=args.max_literal,
                       max_output=args.max_output,
                       max_operations=args.max_operations,
                       max_id_bytes=args.max_id_bytes)


def command_apply(args) -> int:
    try:
        report = apply_delta(args.old, args.delta, args.out,
                             limits=_limits_from(args),
                             read_chunk_limit=args.read_chunk_limit)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (FormatError, OSError) as exc:
        print(f"应用差量包失败: {exc}", file=sys.stderr)
        return 1
    json.dump(report.as_dict(), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def command_inspect(args) -> int:
    try:
        report = inspect_package(args.delta, limits=_limits_from(args),
                                 read_chunk_limit=args.read_chunk_limit)
    except (FormatError, OSError) as exc:
        print(f"检查差量包失败: {exc}", file=sys.stderr)
        return 1
    json.dump(report.as_dict(), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def build_apply_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-apply",
        description="用旧文件与差量包还原新正文（严格校验后交付）",
    )
    parser.add_argument("--old", required=True, help="旧正文文件")
    parser.add_argument("--delta", required=True, help="差量包")
    parser.add_argument("--out", required=True,
                        help="还原出的新正文路径（不得已存在）")
    _add_limits(parser)
    parser.add_argument("--read-chunk-limit", type=int, default=None,
                        help="仅测试用：底层 read 每次至多 N 字节")
    parser.set_defaults(func=command_apply)
    return parser


def build_inspect_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-delta-inspect",
        description="校验差量包并报告身份/长度/指令计数（不输出正文）",
    )
    parser.add_argument("--delta", required=True, help="差量包")
    _add_limits(parser)
    parser.add_argument("--read-chunk-limit", type=int, default=None,
                        help="仅测试用：底层 read 每次至多 N 字节")
    parser.set_defaults(func=command_inspect)
    return parser


def build_parser() -> argparse.ArgumentParser:
    return build_apply_parser()


def main(argv: list[str] | None = None) -> int:
    args = build_apply_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
