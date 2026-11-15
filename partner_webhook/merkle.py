"""可验证追加账本的纯哈希协议（不依赖 SQLite、文件或网络）。

本模块只做三件事：

1. 按固定编码构造叶原文、叶哈希、内部节点哈希与空树根；
2. 提供「任意树长」的递归树切分、根/在账路径/一致性路径的直接实现；
3. 校验并解析版本化的检查点、在账证明、一致性证明文件内容。

哈希协议（不得由生成器与核验器各自猜编码）：

    H = SHA-256
    叶原文 = ASCII "PWLOG1"
             || u32be(len(partner_id UTF-8)) || partner_id UTF-8
             || u32be(len(event_id UTF-8))   || event_id UTF-8
             || u64be(source_seq)
             || 32 字节正文 SHA-256 原文
    叶哈希   = H(0x00 || 叶原文)
    内部节点 = H(0x01 || 左哈希 || 右哈希)
    空树根   = H(空字节)

身份不做任何 Unicode 规范化；长度用固定 4 字节大端前缀，整数用 8 字节大端。
超过编码范围（长度 > 2^32-1、序号 > 2^64-1）一律明确拒绝。

非空树的根：只有一叶时就是叶哈希；否则取「严格小于叶数的最大 2 次幂 k」，
在 k 处切成左右两棵树后递归组合。不补虚拟叶，不复制末叶配对。本模块对任意
树长使用同一递归规则。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

PROTOCOL = "PWLOG1"
PROTOCOL_BYTES = b"PWLOG1"
MAX_UINT32 = (1 << 32) - 1
MAX_UINT64 = (1 << 64) - 1

CHECKPOINT_FORMAT = "pwlog-checkpoint-v1"
INCLUSION_FORMAT = "pwlog-inclusion-v1"
CONSISTENCY_FORMAT = "pwlog-consistency-v1"
FORMAT_VERSION = 1

EMPTY_ROOT = hashlib.sha256(b"").digest()

_HEX64_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class MerkleError(Exception):
    """协议输入非法或证明无法成立（可向调用者展示的稳定原因）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------- #
# 基本编码
# --------------------------------------------------------------------- #
def _u32(value: int, field: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MerkleError("bad_integer", f"{field} 必须是整数，不能是布尔值或其他类型")
    if not 0 <= value <= MAX_UINT32:
        raise MerkleError("integer_out_of_range",
                          f"{field}={value} 超出 4 字节无符号大端范围")
    return value.to_bytes(4, "big")


def _u64(value: int, field: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MerkleError("bad_integer", f"{field} 必须是整数，不能是布尔值或其他类型")
    if not 0 <= value <= MAX_UINT64:
        raise MerkleError("integer_out_of_range",
                          f"{field}={value} 超出 8 字节无符号大端范围")
    return value.to_bytes(8, "big")


def utf8_bytes(value: str, field: str) -> bytes:
    """严格 UTF-8 编码，不做规范化；代理项/非字符串明确拒绝。"""
    if not isinstance(value, str):
        raise MerkleError("bad_text", f"{field} 必须是字符串")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise MerkleError("bad_text",
                          f"{field} 不能编码为 UTF-8: {exc.reason}") from None


def length_prefixed(value: str, field: str) -> bytes:
    raw = utf8_bytes(value, field)
    return _u32(len(raw), f"len({field})") + raw


def parse_hex32(value: Any, field: str) -> bytes:
    """严格解析 32 字节十六进制；拒绝非字符串、非 64 位、非十六进制。"""
    if not isinstance(value, str):
        raise MerkleError("bad_hex", f"{field} 必须是 64 位十六进制字符串")
    if len(value) != 64 or not _HEX64_RE.match(value):
        raise MerkleError("bad_hex",
                          f"{field} 不是恰好 32 字节的十六进制字符串")
    return bytes.fromhex(value)


def hex32(value: bytes) -> str:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise MerkleError("bad_hash", "哈希必须是 32 字节")
    return bytes(value).hex()


def leaf_preimage(partner_id: str, event_id: str, source_seq: int,
                  body_sha256: str | bytes) -> bytes:
    """按固定协议拼接叶原文。"""
    partner = length_prefixed(partner_id, "partner_id")
    event = length_prefixed(event_id, "event_id")
    sequence = _u64(source_seq, "source_seq")
    digest = (parse_hex32(body_sha256, "body_sha256")
              if isinstance(body_sha256, str)
              else bytes(body_sha256))
    if len(digest) != 32:
        raise MerkleError("bad_hex", "body_sha256 必须是 32 字节")
    return PROTOCOL_BYTES + partner + event + sequence + digest


def leaf_hash(partner_id: str, event_id: str, source_seq: int,
              body_sha256: str | bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf_preimage(
        partner_id, event_id, source_seq, body_sha256)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise MerkleError("bad_hash", "内部节点两侧必须是 32 字节哈希")
    return hashlib.sha256(b"\x01" + left + right).digest()


def empty_root() -> bytes:
    return EMPTY_ROOT


# --------------------------------------------------------------------- #
# 任意树长的递归切分
# --------------------------------------------------------------------- #
def split_size(size: int) -> int:
    """严格小于 size 的最大 2 次幂；size 必须 >= 2。

    size 恰为 2 的幂时取 size/2（例如 4 -> 2），否则取最高有效位
    （例如 5 -> 4、9 -> 8）。
    """
    if isinstance(size, bool) or not isinstance(size, int) or size < 2:
        raise MerkleError("bad_size", "split_size 需要整数树长 >= 2")
    k = 1 << (size.bit_length() - 1)
    return k // 2 if k == size else k


def is_power_of_two(size: int) -> bool:
    return size >= 1 and (size & (size - 1)) == 0


def root_from_leaves(leaves: Sequence[bytes]) -> bytes:
    """直接递归参考实现（小样本测试用；正式路径走持久节点）。"""
    length = len(leaves)
    if length == 0:
        return empty_root()
    if length == 1:
        return bytes(leaves[0])
    k = split_size(length)
    return node_hash(root_from_leaves(leaves[:k]),
                     root_from_leaves(leaves[k:]))


def inclusion_directions(size: int, index: int) -> list[str]:
    """叶到根的方向序列：'R' 表示兄弟在右侧，'L' 表示在左侧。"""
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise MerkleError("bad_size", "树长必须是正整数")
    if isinstance(index, bool) or not isinstance(index, int):
        raise MerkleError("bad_index", "叶位置必须是整数")
    if not 0 <= index < size:
        raise MerkleError("index_out_of_range",
                          f"叶位置 {index} 不在树长 {size} 的范围内")

    def walk(start_size: int, offset_index: int) -> list[str]:
        if start_size == 1:
            return []
        k = split_size(start_size)
        if offset_index < k:
            return walk(k, offset_index) + ["R"]
        return walk(start_size - k, offset_index - k) + ["L"]

    return walk(size, index)


def inclusion_path_from_leaves(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """直接递归参考实现。"""
    length = len(leaves)
    if length == 1:
        if index != 0:
            raise MerkleError("index_out_of_range", "一叶树只有位置 0")
        return []
    k = split_size(length)
    if index < k:
        return inclusion_path_from_leaves(leaves[:k], index) + [
            root_from_leaves(leaves[k:])]
    return inclusion_path_from_leaves(leaves[k:], index - k) + [
        root_from_leaves(leaves[:k])]


def build_inclusion_root(leaf: bytes, index: int, size: int,
                         path: Iterable[bytes]) -> bytes:
    """按方向序列从叶哈希重建根。"""
    directions = inclusion_directions(size, index)
    nodes = list(path)
    if len(nodes) != len(directions):
        raise MerkleError(
            "path_length_mismatch",
            f"证明路径有 {len(nodes)} 个节点，叶位置 {index}/树长 {size} "
            f"需要 {len(directions)} 个")
    root = bytes(leaf)
    for direction, sibling in zip(directions, nodes):
        if len(sibling) != 32:
            raise MerkleError("bad_hash", "路径节点必须是 32 字节")
        root = node_hash(root, sibling) if direction == "R" else \
            node_hash(sibling, root)
    return root


# --------------------------------------------------------------------- #
# 一致性证明（RFC 6962 的最小子树递归）
# --------------------------------------------------------------------- #
def consistency_path_from_leaves(leaves: Sequence[bytes], m: int) -> list[bytes]:
    """直接递归参考实现：C(m, D, b)，D 为当前连续叶段，初始 b=True。"""
    n = len(leaves)
    if m < 0 or m > n:
        raise MerkleError("bad_size", f"旧叶数 {m} 不在 [0,{n}] 内")
    if m == 0 or m == n:
        return []

    def sub(m_old: int, segment: Sequence[bytes], b: bool) -> list[bytes]:
        length = len(segment)
        if m_old == length:
            return [] if b else [root_from_leaves(segment)]
        k = split_size(length)
        if m_old <= k:
            return sub(m_old, segment[:k], b) + [root_from_leaves(segment[k:])]
        return sub(m_old - k, segment[k:], False) + [
            root_from_leaves(segment[:k])]

    return sub(m, list(leaves), True)


@dataclass(frozen=True)
class ConsistencyCheck:
    old_root: bytes
    new_root: bytes


def reconstruct_consistency(old_root: bytes, new_root: bytes, m: int, n: int,
                            path: Iterable[bytes],
                            empty: bytes | None = None) -> ConsistencyCheck:
    """仅凭 m、n 与路径重建旧根和新根；不信任任何路径自带根。

    返回重建结果，由调用方与可信检查点比较。m=0 时旧根必须等于空树根，
    且路径为空（新根无法从空路径重建，只能由调用方的可信新检查点提供）。
    """
    empty = empty_root() if empty is None else empty
    if isinstance(m, bool) or not isinstance(m, int) or isinstance(n, bool) \
            or not isinstance(n, int):
        raise MerkleError("bad_integer", "树长必须是整数，不能是布尔值")
    if m < 0 or n < m:
        raise MerkleError("size_regression", f"树长不能倒退: m={m}, n={n}")
    nodes = list(path)
    for item in nodes:
        if len(item) != 32:
            raise MerkleError("bad_hash", "路径节点必须是 32 字节")
    if m == 0:
        if nodes:
            raise MerkleError("path_not_empty", "0 到 n 的一致性路径必须为空")
        if old_root != empty:
            raise MerkleError("old_root_mismatch", "旧根不是协议空树根")
        return ConsistencyCheck(old_root, new_root)
    if m == n:
        if nodes:
            raise MerkleError("path_not_empty", "相同树长的一致性路径必须为空")
        if old_root != new_root:
            raise MerkleError("root_mismatch", "相同树长的两个检查点根不一致")
        return ConsistencyCheck(old_root, new_root)

    fn = m - 1
    sn = n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        first_old = old_root
        start = 0
    else:
        if not nodes:
            raise MerkleError("missing_path", "一致性路径缺少首个节点")
        first_old = nodes[0]
        start = 1
    sr = first_old
    fr = first_old
    for position in range(start, len(nodes)):
        node = nodes[position]
        if sn == 0:
            raise MerkleError("path_too_long", "一致性路径节点多于所需")
        if (fn & 1) or fn == sn:
            fr = node_hash(node, fr)
            sr = node_hash(node, sr)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, node)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise MerkleError("path_too_short", "一致性路径节点不足")
    if fr != old_root:
        raise MerkleError("old_root_mismatch", "由路径重建的旧根与可信旧根不符")
    if sr != new_root:
        raise MerkleError("new_root_mismatch", "由路径重建的新根与可信新根不符")
    return ConsistencyCheck(fr, sr)


# --------------------------------------------------------------------- #
# 版本化文件格式
# --------------------------------------------------------------------- #
def _json_constant(name: str):
    raise MerkleError("bad_json", f"JSON 中不允许 {name}")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MerkleError("duplicate_key", f"JSON 对象重复键 {key!r}")
        result[key] = value
    return result


def load_json_document(path: str | Path, what: str) -> dict[str, Any]:
    """读取严格 JSON 对象：UTF-8、无重复键、拒绝 NaN/Infinity。"""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise MerkleError("io_error", f"无法读取{what}: {exc}") from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs_without_duplicates,
                           parse_constant=_json_constant)
    except MerkleError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MerkleError("bad_json", f"{what}不是合法 JSON: {exc}") from None
    if not isinstance(value, dict):
        raise MerkleError("bad_json", f"{what}必须是 JSON 对象")
    return value


def strict_int(value: Any, field: str) -> int:
    """布尔值是 int 子类，必须显式拒绝；浮点/字符串也不当整数。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise MerkleError("bad_integer", f"{field} 必须是整数（布尔值不算整数）")
    return value


def _require_exact_keys(doc: dict[str, Any], expected: set[str], what: str) -> None:
    actual = set(doc)
    extra = actual - expected
    missing = expected - actual
    if extra:
        raise MerkleError("unknown_fields", f"{what}有多余字段: {sorted(extra)!r}")
    if missing:
        raise MerkleError("missing_fields", f"{what}缺少字段: {sorted(missing)!r}")


def _check_header(doc: dict[str, Any], format_name: str, what: str) -> None:
    if doc.get("format") != format_name:
        raise MerkleError("bad_format",
                          f"{what} format 必须是 {format_name!r}")
    if strict_int(doc.get("version"), f"{what}.version") != FORMAT_VERSION:
        raise MerkleError("bad_version",
                          f"{what} version 必须是 {FORMAT_VERSION}")
    if doc.get("protocol") != PROTOCOL:
        raise MerkleError("bad_protocol", f"{what} protocol 必须是 {PROTOCOL!r}")


def _check_identity(doc: dict[str, Any], what: str) -> None:
    for field in ("log_id", "partner_id"):
        value = doc.get(field)
        if not isinstance(value, str) or not value:
            raise MerkleError("bad_identity", f"{what} {field} 必须是非空字符串")
    # 合作方标识按协议直接编码为 UTF-8；这里先拒绝无法编码的值。
    utf8_bytes(doc["partner_id"], f"{what}.partner_id")
    _u32(len(utf8_bytes(doc["partner_id"], "partner_id")), "partner_id 长度")


@dataclass(frozen=True)
class Checkpoint:
    log_id: str
    partner_id: str
    tree_size: int
    root_hash: bytes
    protocol: str = PROTOCOL
    version: int = FORMAT_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": CHECKPOINT_FORMAT,
            "version": self.version,
            "protocol": self.protocol,
            "log_id": self.log_id,
            "partner_id": self.partner_id,
            "tree_size": self.tree_size,
            "root_hash": hex32(self.root_hash),
        }


_CHECKPOINT_KEYS = {
    "format", "version", "protocol", "log_id", "partner_id",
    "tree_size", "root_hash",
}


def parse_checkpoint(doc: dict[str, Any], what: str = "检查点") -> Checkpoint:
    _require_exact_keys(doc, _CHECKPOINT_KEYS, what)
    _check_header(doc, CHECKPOINT_FORMAT, what)
    _check_identity(doc, what)
    tree_size = strict_int(doc["tree_size"], f"{what}.tree_size")
    if tree_size < 0:
        raise MerkleError("bad_size", f"{what}.tree_size 不能为负数")
    root = parse_hex32(doc["root_hash"], f"{what}.root_hash")
    return Checkpoint(doc["log_id"], doc["partner_id"], tree_size, root)


@dataclass(frozen=True)
class InclusionProof:
    log_id: str
    partner_id: str
    tree_size: int
    leaf_index: int
    event_id: str
    source_seq: int
    body_sha256: str
    path: tuple[bytes, ...]
    protocol: str = PROTOCOL
    version: int = FORMAT_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": INCLUSION_FORMAT,
            "version": FORMAT_VERSION,
            "protocol": PROTOCOL,
            "log_id": self.log_id,
            "partner_id": self.partner_id,
            "tree_size": self.tree_size,
            "leaf_index": self.leaf_index,
            "event_id": self.event_id,
            "source_seq": self.source_seq,
            "body_sha256": self.body_sha256,
            "path": [hex32(node) for node in self.path],
        }


_INCLUSION_KEYS = {
    "format", "version", "protocol", "log_id", "partner_id",
    "tree_size", "leaf_index", "event_id", "source_seq", "body_sha256",
    "path",
}


def parse_inclusion_proof(doc: dict[str, Any], what: str = "在账证明") -> InclusionProof:
    _require_exact_keys(doc, _INCLUSION_KEYS, what)
    _check_header(doc, INCLUSION_FORMAT, what)
    _check_identity(doc, what)
    tree_size = strict_int(doc["tree_size"], f"{what}.tree_size")
    leaf_index = strict_int(doc["leaf_index"], f"{what}.leaf_index")
    if tree_size < 0:
        raise MerkleError("bad_size", f"{what}.tree_size 不能为负数")
    if leaf_index < 0 or leaf_index >= tree_size:
        raise MerkleError("index_out_of_range",
                          f"{what}.leaf_index 不在树长范围内")
    event_id = doc["event_id"]
    if not isinstance(event_id, str):
        raise MerkleError("bad_identity", f"{what}.event_id 必须是字符串")
    utf8_bytes(event_id, f"{what}.event_id")
    seq = strict_int(doc["source_seq"], f"{what}.source_seq")
    _u64(seq, f"{what}.source_seq")
    digest = doc["body_sha256"]
    parse_hex32(digest, f"{what}.body_sha256")
    raw_path = doc["path"]
    if not isinstance(raw_path, list):
        raise MerkleError("bad_path", f"{what}.path 必须是数组")
    path = tuple(parse_hex32(item, f"{what}.path[{i}]")
                 for i, item in enumerate(raw_path))
    return InclusionProof(doc["log_id"], doc["partner_id"], tree_size,
                          leaf_index, event_id, seq, digest.lower(), path)


@dataclass(frozen=True)
class ConsistencyProof:
    log_id: str
    partner_id: str
    old_size: int
    new_size: int
    path: tuple[bytes, ...]
    protocol: str = PROTOCOL
    version: int = FORMAT_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": CONSISTENCY_FORMAT,
            "version": FORMAT_VERSION,
            "protocol": PROTOCOL,
            "log_id": self.log_id,
            "partner_id": self.partner_id,
            "old_size": self.old_size,
            "new_size": self.new_size,
            "path": [hex32(node) for node in self.path],
        }


_CONSISTENCY_KEYS = {
    "format", "version", "protocol", "log_id", "partner_id",
    "old_size", "new_size", "path",
}


def parse_consistency_proof(doc: dict[str, Any],
                            what: str = "一致性证明") -> ConsistencyProof:
    _require_exact_keys(doc, _CONSISTENCY_KEYS, what)
    _check_header(doc, CONSISTENCY_FORMAT, what)
    _check_identity(doc, what)
    old_size = strict_int(doc["old_size"], f"{what}.old_size")
    new_size = strict_int(doc["new_size"], f"{what}.new_size")
    if old_size < 0 or new_size < old_size:
        raise MerkleError("size_regression",
                          f"{what} 树长非法或倒退: old={old_size}, new={new_size}")
    raw_path = doc["path"]
    if not isinstance(raw_path, list):
        raise MerkleError("bad_path", f"{what}.path 必须是数组")
    path = tuple(parse_hex32(item, f"{what}.path[{i}]")
                 for i, item in enumerate(raw_path))
    return ConsistencyProof(doc["log_id"], doc["partner_id"],
                            old_size, new_size, path)


def dump_document(doc: dict[str, Any]) -> str:
    """稳定的展示/保存格式（按字段插入顺序，2 空格缩进）。"""
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
