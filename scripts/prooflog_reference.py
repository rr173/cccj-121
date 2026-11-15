"""手写小样本参考实现：直接递归、不调用正式节点存储或证明函数。

本文件独立于 ``partner_webhook/merkle.py`` 与 ``partner_webhook/eventlog.py``：
它自己拼接叶原文、自己计算 SHA-256、自己递归切分树，用来核对正式生成器
的输出。故意使用与正式实现不同的代码组织（显式列表递归、显式弧度），
避免「自己的生成器被自己的核验器接受」式的循环论证。

协议（与任务书一致，本文件独立重写）：

    leaf = b"PWLOG1"
           + u32be(len(partner)) + partner
           + u32be(len(event))   + event
           + u64be(source_seq)   + body_sha256(32 bytes raw)
    leaf_hash = sha256(b"\\x00" + leaf)
    node      = sha256(b"\\x01" + left + right)
    empty     = sha256(b"")
    非空树：k = 严格小于 n 的最大 2 次幂（n 为 2 的幂时 k = n/2）；
    root(n) = leaf (n=1) / node(root(前 k), root(后 n-k))。
"""

from __future__ import annotations

import hashlib

EMPTY_ROOT = hashlib.sha256(b"").digest()


def _lp(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("身份字段必须是字符串")
    raw = text.encode("utf-8", "strict")
    if len(raw) > 0xFFFFFFFF:
        raise ValueError("长度超出 4 字节")
    return len(raw).to_bytes(4, "big") + raw


def leaf_bytes(partner_id: str, event_id: str, source_seq: int,
               body_sha256: bytes) -> bytes:
    if not (0 <= source_seq <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("source_seq 超出 8 字节")
    if len(body_sha256) != 32:
        raise ValueError("正文摘要必须是 32 字节")
    return (b"PWLOG1" + _lp(partner_id) + _lp(event_id)
            + source_seq.to_bytes(8, "big") + body_sha256)


def leaf_hash(partner_id: str, event_id: str, source_seq: int,
              body_sha256: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf_bytes(
        partner_id, event_id, source_seq, body_sha256)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _cut(size: int) -> int:
    """严格小于 size 的最大 2 次幂（size 为 2 的幂时减半）。"""
    if size < 2:
        raise ValueError("树切分需要至少两片叶")
    power = 1
    while power * 2 < size:
        power *= 2
    return power


def tree_root(hashes: list[bytes]) -> bytes:
    if not hashes:
        return EMPTY_ROOT
    if len(hashes) == 1:
        return hashes[0]
    k = _cut(len(hashes))
    return node_hash(tree_root(hashes[:k]), tree_root(hashes[k:]))


def inclusion_proof(hashes: list[bytes], position: int) -> list[bytes]:
    if not 0 <= position < len(hashes):
        raise ValueError("位置越界")
    if len(hashes) == 1:
        return []
    k = _cut(len(hashes))
    left, right = hashes[:k], hashes[k:]
    if position < k:
        return inclusion_proof(left, position) + [tree_root(right)]
    return inclusion_proof(right, position - k) + [tree_root(left)]


def inclusion_root(leaf: bytes, position: int, size: int,
                   path: list[bytes]) -> bytes:
    """按 size/position 递归推导方向后重建根（不读证明里的任何根）。"""
    directions = []

    def walk(length: int, offset: int) -> None:
        if length == 1:
            return
        k = _cut(length)
        if offset < k:
            directions.append("R")
            walk(k, offset)
        else:
            directions.append("L")
            walk(length - k, offset - k)

    walk(size, position)
    if len(path) != len(directions):
        raise ValueError("路径长度不符")
    current = leaf
    # ``walk`` 追加的是从根到叶的方向；路径本身就是从叶到根，
    # 因此把方向反转后与 path 正向配对。
    for side, sibling in zip(reversed(directions), path):
        current = node_hash(current, sibling) if side == "R" else \
            node_hash(sibling, current)
    return current


def consistency_proof(hashes: list[bytes], m: int) -> list[bytes]:
    if not 0 <= m <= len(hashes):
        raise ValueError("旧树长越界")
    if m == 0 or m == len(hashes):
        return []

    def build(m_old: int, segment: list[bytes], at_tree_boundary: bool) -> list[bytes]:
        if m_old == len(segment):
            return [] if at_tree_boundary else [tree_root(segment)]
        k = _cut(len(segment))
        if m_old <= k:
            return build(m_old, segment[:k], at_tree_boundary) + \
                [tree_root(segment[k:])]
        return build(m_old - k, segment[k:], False) + [tree_root(segment[:k])]

    return build(m, hashes, True)


def consistency_verify(old_hash: bytes, new_hash: bytes, m: int, n: int,
                       path: list[bytes]) -> tuple[bytes, bytes]:
    """独立重建新旧根（与 RFC 6962 相同的移位循环，另行手写）。"""
    if m < 0 or n < m:
        raise ValueError("树长非法")
    if m == 0:
        if path:
            raise ValueError("0 到 n 的路径必须为空")
        return EMPTY_ROOT, new_hash
    if m == n:
        if path:
            raise ValueError("相同树长的路径必须为空")
        if old_hash != new_hash:
            raise ValueError("相同树长两根不同")
        return old_hash, new_hash

    path = list(path)
    a = m - 1
    b = n - 1
    while a & 1:
        a >>= 1
        b >>= 1
    if a == 0:
        old_acc = old_hash
    else:
        old_acc = path.pop(0)
    new_acc = old_acc
    while path:
        if b == 0:
            raise ValueError("路径过长")
        sibling = path.pop(0)
        if (a & 1) or a == b:
            old_acc = node_hash(sibling, old_acc)
            new_acc = node_hash(sibling, new_acc)
            while a != 0 and not (a & 1):
                a >>= 1
                b >>= 1
        else:
            new_acc = node_hash(new_acc, sibling)
        a >>= 1
        b >>= 1
    if b != 0:
        raise ValueError("路径过短")
    return old_acc, new_acc


def checkpoint_root(hashes: list[bytes], size: int) -> bytes:
    return tree_root(hashes[:size])
