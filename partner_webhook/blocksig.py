"""块弱校验与滚动更新。

弱值定义（双方共同遵守的纯函数）::

    L = len(x)
    a = sum(x[i] for i in range(L))      mod 65536
    b = sum((L - i) * x[i])              mod 65536
    weak = (b << 16) | a

窗口向右滑动一字节、移出 u 加入 v 时::

    a' = (a - u + v) mod 65536
    b' = (b - L*u + a') mod 65536

这里只做**内容指纹**，不是认证：弱值相同绝不代表内容相同，必须再用
SHA-256 强摘要确认。滚动关系只用于滑动窗口，避免逐窗重求整窗和。
"""

from __future__ import annotations

WEAK_MOD = 1 << 16
WEAK_MASK = WEAK_MOD - 1
WEAK_MAX = 0xFFFFFFFF


def weak_checksum(data, *, start: int = 0, length: int | None = None) -> int:
    """按定义直接求一个块/窗口的 32 位弱值。

    ``data`` 可以是 ``bytes`` / ``memoryview`` / 任何支持下标与切片的序列。
    只应在初始化窗口或一次性的短尾块上调用；滑动时必须用 :func:`roll`。
    """
    if length is None:
        length = len(data) - start
    if length < 0 or start < 0 or start + length > len(data):
        raise ValueError("弱校验范围越界")
    a = 0
    b = 0
    # 先按 L 加权；i 从 0 开始，权重为 (L - i)。
    weight = length
    for i in range(start, start + length):
        value = data[i]
        a += value
        b += weight * value
        weight -= 1
    return ((b & WEAK_MASK) << 16) | (a & WEAK_MASK)


def roll(a: int, b: int, window: int, out_byte: int, in_byte: int) -> tuple[int, int]:
    """把窗口右移一字节，返回新的 ``(a, b)``。

    ``out_byte`` 是刚离开窗口的字节，``in_byte`` 是刚进入的字节。
    严格按题设关系计算，不做整窗重求。
    """
    new_a = (a - out_byte + in_byte) & WEAK_MASK
    new_b = (b - window * out_byte + new_a) & WEAK_MASK
    return new_a, new_b


def combine(a: int, b: int) -> int:
    """把两个 16 位分量拼成 32 位弱值。"""
    return ((b & WEAK_MASK) << 16) | (a & WEAK_MASK)
