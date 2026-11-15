"""离线核验入口（不访问数据库、不读取账本节点文件）。

调用方必须自己传入**可信**检查点文件，以及：

* ``inclusion``：待验叶子的字段（合作方、事件 ID、source_seq、正文摘要）
  与在账证明；核验器只从这些字段与路径重建根，绝不使用证明文件里自带的
  根或合作方身份；
* ``consistency``：另一份可信检查点（新）与一致性证明；核验器同时重建
  旧根和新根。

本模块只 import 标准库与 :mod:`partner_webhook.merkle`，不 import sqlite3，
不读取任何 .db / -wal / 节点文件。退出码：0 全部成立；1 核验失败；2 输入
文件或参数非法。

用法::

    python3 -I partner_webhook/verifylog.py inclusion \\
        --checkpoint cp.json --proof inclusion.json \\
        --event-id evt-1 --source-seq 7 \\
        --body-sha256 <64 hex> [--json]

    python3 -I partner_webhook/verifylog.py consistency \\
        --old-checkpoint old.json --new-checkpoint new.json \\
        --proof consistency.json [--json]

    python3 -I partner_webhook/verifylog.py checkpoint --checkpoint cp.json

只有当检查点由调用方事先保存并信任时，哈希证明才有意义：本工具不内置
任何可信根，也不会从证明文件里取根。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook import merkle  # noqa: E402
else:  # pragma: no cover - 包内调用
    from . import merkle  # noqa: E402


class VerificationFailure(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _load(path: str, what: str) -> dict:
    try:
        return merkle.load_json_document(path, what)
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None


def verify_inclusion(checkpoint_doc: dict, proof_doc: dict, *, partner_id: str,
                     event_id: str, source_seq: int, body_sha256: str) -> dict:
    """用可信检查点核验一条事件的在账证明。"""
    try:
        checkpoint = merkle.parse_checkpoint(checkpoint_doc)
        proof = merkle.parse_inclusion_proof(proof_doc)
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None

    if partner_id != checkpoint.partner_id:
        raise VerificationFailure(
            "cross_partner",
            f"调用方合作方 {partner_id!r} 与检查点 {checkpoint.partner_id!r} 不符")
    if proof.partner_id != checkpoint.partner_id:
        raise VerificationFailure(
            "cross_partner",
            f"证明里的合作方 {proof.partner_id!r} 与可信检查点 "
            f"{checkpoint.partner_id!r} 不符")
    if proof.log_id != checkpoint.log_id:
        raise VerificationFailure("cross_log_id",
                                  "证明里的 log_id 与可信检查点不符")
    if proof.tree_size != checkpoint.tree_size:
        raise VerificationFailure(
            "tree_size_mismatch",
            f"证明树长 {proof.tree_size} 与可信检查点树长"
            f" {checkpoint.tree_size} 不符")
    if checkpoint.tree_size == 0:
        raise VerificationFailure("empty_tree", "空树检查点没有任何叶子可证明")
    # 证明自己声明的叶字段必须与调用方提供的字段完全一致；否则说明证明
    # 是别的叶子/位置的内容，不能凭它通过。
    try:
        expected_digest = merkle.parse_hex32(body_sha256, "body_sha256")
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None
    if (proof.event_id, proof.source_seq, proof.body_sha256) != (
            event_id, source_seq, expected_digest.hex()):
        raise VerificationFailure(
            "leaf_fields_mismatch",
            "证明声明的叶字段与调用方提供的事件字段不一致")
    try:
        value = merkle.leaf_hash(partner_id, event_id, source_seq,
                                 expected_digest)
        rebuilt = merkle.build_inclusion_root(
            value, proof.leaf_index, proof.tree_size, proof.path)
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None
    if rebuilt != checkpoint.root_hash:
        raise VerificationFailure(
            "root_mismatch",
            "由叶与路径重建的根与可信检查点的根不符（叶子/位置/路径被改动）")
    return {
        "ok": True,
        "kind": "inclusion",
        "partner_id": partner_id,
        "log_id": checkpoint.log_id,
        "tree_size": checkpoint.tree_size,
        "leaf_index": proof.leaf_index,
        "event_id": event_id,
        "source_seq": source_seq,
        "body_sha256": expected_digest.hex(),
        "root_hash": merkle.hex32(checkpoint.root_hash),
        "path_length": len(proof.path),
    }


def verify_consistency(old_doc: dict, new_doc: dict, proof_doc: dict) -> dict:
    """用两份可信检查点核验前后追加关系。"""
    try:
        old = merkle.parse_checkpoint(old_doc, "旧检查点")
        new = merkle.parse_checkpoint(new_doc, "新检查点")
        proof = merkle.parse_consistency_proof(proof_doc)
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None

    if old.partner_id != new.partner_id:
        raise VerificationFailure(
            "cross_partner",
            f"两份检查点合作方不同: {old.partner_id!r} vs {new.partner_id!r}")
    if proof.partner_id != old.partner_id:
        raise VerificationFailure(
            "cross_partner",
            f"证明里的合作方 {proof.partner_id!r} 与可信检查点"
            f" {old.partner_id!r} 不符")
    if old.log_id != new.log_id:
        raise VerificationFailure("cross_log_id", "两份检查点的 log_id 不同")
    if proof.log_id != old.log_id:
        raise VerificationFailure("cross_log_id",
                                  "证明里的 log_id 与可信检查点不符")
    if old.protocol != new.protocol or proof.protocol != old.protocol:
        raise VerificationFailure("bad_protocol", "协议版本不一致")
    if new.tree_size < old.tree_size:
        raise VerificationFailure(
            "size_regression",
            f"新检查点树长 {new.tree_size} 小于旧树长 {old.tree_size}")
    if (proof.old_size, proof.new_size) != (old.tree_size, new.tree_size):
        raise VerificationFailure(
            "tree_size_mismatch",
            "证明里的树长与两份可信检查点不符")
    try:
        result = merkle.reconstruct_consistency(
            old.root_hash, new.root_hash, old.tree_size, new.tree_size,
            proof.path)
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None
    if result.old_root != old.root_hash:
        raise VerificationFailure("old_root_mismatch",
                                  "重建的旧根与可信旧检查点不符")
    if result.new_root != new.root_hash:
        raise VerificationFailure("new_root_mismatch",
                                  "重建的新根与可信新检查点不符")
    return {
        "ok": True,
        "kind": "consistency",
        "partner_id": old.partner_id,
        "log_id": old.log_id,
        "old_size": old.tree_size,
        "new_size": new.tree_size,
        "old_root_hash": merkle.hex32(old.root_hash),
        "new_root_hash": merkle.hex32(new.root_hash),
        "path_length": len(proof.path),
        "appended_leaves": new.tree_size - old.tree_size,
    }


def describe_checkpoint(doc: dict) -> dict:
    try:
        checkpoint = merkle.parse_checkpoint(doc)
    except merkle.MerkleError as exc:
        raise VerificationFailure(exc.code, exc.message) from None
    return {
        "ok": True,
        "kind": "checkpoint",
        "partner_id": checkpoint.partner_id,
        "log_id": checkpoint.log_id,
        "tree_size": checkpoint.tree_size,
        "root_hash": merkle.hex32(checkpoint.root_hash),
        "protocol": checkpoint.protocol,
    }


def _strict_int_arg(text: str, field: str) -> int:
    if not text.isascii() or not text.isdigit():
        raise VerificationFailure("bad_integer",
                                  f"{field} 必须是非负十进制整数")
    return int(text, 10)


def _emit(payload: dict, as_json: bool) -> None:
    if as_json:
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2,
                  sort_keys=True)
        sys.stdout.write("\n")
        return
    if payload.get("kind") == "inclusion":
        print(f"OK 在账证明: 合作方 {payload['partner_id']} log_id "
              f"{payload['log_id']} 叶 {payload['leaf_index']}/"
              f"{payload['tree_size']} 事件 {payload['event_id']}")
    elif payload.get("kind") == "consistency":
        print(f"OK 一致性证明: 合作方 {payload['partner_id']} log_id "
              f"{payload['log_id']} {payload['old_size']} ->"
              f" {payload['new_size']}（新增 "
              f"{payload['appended_leaves']} 叶）")
    else:
        print(f"OK 检查点: 合作方 {payload['partner_id']} log_id "
              f"{payload['log_id']} 树长 {payload['tree_size']} 根 "
              f"{payload['root_hash']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook-verify",
        description="离线核验可验证追加账本的检查点与证明（不访问数据库）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inc = sub.add_parser("inclusion", help="核验一条事件的在账证明")
    p_inc.add_argument("--checkpoint", required=True,
                       help="调用方保存并信任的检查点 JSON")
    p_inc.add_argument("--proof", required=True, help="在账证明 JSON")
    p_inc.add_argument("--event-id", required=True)
    p_inc.add_argument("--source-seq", required=True)
    p_inc.add_argument("--body-sha256", required=True,
                       help="正文的 SHA-256 十六进制摘要")
    p_inc.add_argument("--partner", default=None,
                       help="可选：显式合作方；省略时使用检查点里的合作方")
    p_inc.add_argument("--json", action="store_true", help="输出 JSON")

    p_con = sub.add_parser("consistency", help="核验前后追加关系")
    p_con.add_argument("--old-checkpoint", required=True)
    p_con.add_argument("--new-checkpoint", required=True)
    p_con.add_argument("--proof", required=True)
    p_con.add_argument("--json", action="store_true", help="输出 JSON")

    p_cp = sub.add_parser("checkpoint", help="解析并显示一份检查点")
    p_cp.add_argument("--checkpoint", required=True)
    p_cp.add_argument("--json", action="store_true", help="输出 JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "checkpoint":
            payload = describe_checkpoint(_load(args.checkpoint, "检查点"))
        elif args.command == "inclusion":
            checkpoint_doc = _load(args.checkpoint, "检查点")
            proof_doc = _load(args.proof, "在账证明")
            partner = args.partner
            if partner is None:
                try:
                    partner = merkle.parse_checkpoint(checkpoint_doc).partner_id
                except merkle.MerkleError as exc:
                    raise VerificationFailure(exc.code, exc.message) from None
            payload = verify_inclusion(
                checkpoint_doc, proof_doc, partner_id=partner,
                event_id=args.event_id,
                source_seq=_strict_int_arg(args.source_seq, "source_seq"),
                body_sha256=args.body_sha256)
        else:
            payload = verify_consistency(
                _load(args.old_checkpoint, "旧检查点"),
                _load(args.new_checkpoint, "新检查点"),
                _load(args.proof, "一致性证明"))
    except VerificationFailure as exc:
        if getattr(args, "json", False):
            json.dump({"ok": False, "error": exc.code, "message": exc.message},
                      sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
        print(f"核验失败 [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1
    _emit(payload, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
