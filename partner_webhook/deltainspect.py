"""差量包与签名的只读检查入口（不还原正文、不输出业务内容）。

用法::

    python3 -I partner_webhook/deltainspect.py packet --delta 包
    python3 -I partner_webhook/deltainspect.py signature --signature 签名

``packet`` 完整走一遍 apply 的头部/指令/结束/摘要校验，但不需要旧文件，
也不写任何输出；报告身份、长度、指令数及复用/字面字节。
``signature`` 严格校验签名文件结构并报告块数、块长与文件摘要，
``--index`` 可顺带验证临时索引查询（不打印块内容）。

两者都绝不把正文/字面内容打印到 stdout。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook.apply import (  # noqa: E402
        ApplyLimits, inspect_package,
    )
    from partner_webhook.deltaformat import FormatError  # noqa: E402
    from partner_webhook.signature import load_signature_into_index  # noqa: E402
else:
    from .apply import ApplyLimits, inspect_package
    from .deltaformat import FormatError
    from .signature import load_signature_into_index


def _print_json(obj) -> None:
    json.dump(obj, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def command_signature(args) -> int:
    limit = args.read_chunk_limit
    with tempfile.TemporaryDirectory(prefix="pwsig-inspect-") as tmp:
        try:
            index = load_signature_into_index(
                args.signature, Path(tmp) / "index.sqlite",
                read_chunk_limit=limit)
        except (FormatError, OSError) as exc:
            print(f"检查签名失败: {exc}", file=sys.stderr)
            return 1
        try:
            header = index.header
            summary = {
                "format_version": 1,
                "block_size": header.block_size,
                "file_length": header.file_length,
                "file_sha256": header.file_sha256.hex(),
                "block_count": header.block_count,
                "tail_length": header.tail_length,
                "signature_bytes": Path(args.signature).stat().st_size,
            }
            if args.index:
                summary["indexed_blocks"] = header.block_count
                summary["weak_filter_bits"] = index.bloom.bits
            _print_json(summary)
            return 0
        finally:
            index.close()


def command_packet(args) -> int:
    limits = ApplyLimits(max_block=args.max_block,
                         max_literal=args.max_literal,
                         max_output=args.max_output,
                         max_operations=args.max_operations,
                         max_id_bytes=args.max_id_bytes)
    try:
        report = inspect_package(args.delta, limits=limits,
                                 read_chunk_limit=args.read_chunk_limit)
    except (FormatError, OSError) as exc:
        print(f"检查差量包失败: {exc}", file=sys.stderr)
        return 1
    doc = report.as_dict()
    _print_json(doc)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-delta-inspect",
        description="只读检查签名或差量包（不还原、不输出正文）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_packet = sub.add_parser("packet", aliases=["inspect"],
                              help="检查差量包并报告指令计数")
    p_packet.add_argument("--delta", required=True)
    p_packet.add_argument("--max-block", type=int, default=16 * 1024 * 1024)
    p_packet.add_argument("--max-literal", type=int, default=4 * 1024 * 1024)
    p_packet.add_argument("--max-output", type=int, default=1 << 40)
    p_packet.add_argument("--max-operations", type=int, default=4_000_000)
    p_packet.add_argument("--max-id-bytes", type=int, default=255)
    p_packet.add_argument("--read-chunk-limit", type=int, default=None)
    p_packet.set_defaults(func=command_packet)

    p_sig = sub.add_parser("signature", help="严格校验签名并报告结构")
    p_sig.add_argument("--signature", required=True)
    p_sig.add_argument("--index", action="store_true",
                       help="顺带建立临时索引并报告块数/位图大小")
    p_sig.add_argument("--read-chunk-limit", type=int, default=None)
    p_sig.set_defaults(func=command_signature)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
