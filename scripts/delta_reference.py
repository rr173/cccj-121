"""独立的慢速小样本匹配器（不 import 正式 delta/signature 代码）。

用途：用小数据手工核对生产差量包的**确定性 COPY 选择**。这里刻意用最
直白、可能很慢的方法：

* 每次滑动都用定义直接重求整窗 ``a``/``b``（不用滚动递推、不共享代码）；
* 对每个可能的旧块（按偏移升序）**直接比较字节内容**，不经过弱值/摘要；
* 规则与格式说明相同：长度 B 窗口从左到右；命中先输出字面再输出 COPY，
  并跳过整块；旧尾块短于 B 时仅在新正文剩余恰为该长度时尝试。

输出 ``[("COPY", offset, length) | ("LITERAL", bytes), ...]``，可再按
``LITERAL_MAX`` 切段后与解析出的包指令逐条比对（本模块提供比较辅助）。
"""

from __future__ import annotations

# 这些常量在参考实现里独立重复，故意不从正式模块导入。
MASK = 0xFFFF


def blocked(old: bytes, block_size: int):
    blocks = []
    for offset in range(0, len(old), block_size):
        blocks.append((offset, old[offset:offset + block_size]))
    return blocks


def weak_of(data: bytes) -> int:
    length = len(data)
    a = sum(data) % 65536
    b = sum((length - i) * data[i] for i in range(length)) % 65536
    return (b << 16) | a


def roll(a: int, b: int, window: int, out_byte: int, in_byte: int):
    # 参考实现：仍按定义重新求，但这里也独立实现滚动关系供交叉核对。
    new_a = (a - out_byte + in_byte) % 65536
    new_b = (b - window * out_byte + new_a) % 65536
    return new_a, new_b


def first_block_match(blocks, window: bytes):
    """按偏移升序返回第一个内容相同的整块；纯字节比较，不看弱值。"""
    for offset, content in blocks:
        if content == window:
            return offset, len(content)
    return None


def match(old: bytes, new: bytes, block_size: int):
    """返回参考实现的指令序列（未按 LITERAL_MAX 切段）。"""
    blocks = blocked(old, block_size)
    B = block_size
    tail_len = len(blocks[-1][1]) if blocks else 0
    short_tail = bool(blocks) and tail_len < B
    out = []
    literal = bytearray()
    pos = 0
    N = len(new)

    def flush():
        if literal:
            out.append(("LITERAL", bytes(literal)))
            literal.clear()

    while pos < N:
        remaining = N - pos
        if short_tail and remaining == tail_len:
            window = new[pos:pos + tail_len]
            matched = first_block_match(blocks, window)
            if matched:
                flush()
                out.append(("COPY", matched[0], matched[1]))
                pos += tail_len
                continue
            literal += window
            pos = N
            break
        if remaining < B:
            literal += new[pos:remaining + pos]
            pos = N
            break
        window = new[pos:pos + B]
        matched = first_block_match(blocks, window)
        if matched:
            flush()
            out.append(("COPY", matched[0], matched[1]))
            pos += B
            continue
        literal.append(new[pos])
        pos += 1
    flush()
    return out


def coalesce_literals(ops):
    """把相邻 LITERAL 合并（参考输出可能逐字节追加）。"""
    merged = []
    for op in ops:
        if op[0] == "LITERAL" and merged and merged[-1][0] == "LITERAL":
            merged[-1] = ("LITERAL", merged[-1][1] + op[1])
        else:
            merged.append(op)
    return merged


def compare(ops, package_ops, literal_max: int):
    """把参考指令与解析出的包指令按 LITERAL_MAX 切段后逐条比较。

    返回 ``(ok, detail)``；detail 给出第一个不等的位置或切段后的期望。
    """
    expected = []
    for op in coalesce_literals(ops):
        if op[0] == "COPY":
            expected.append(op)
        else:
            data = op[1]
            for start in range(0, len(data), literal_max):
                expected.append(("LITERAL", data[start:start + literal_max]))
    actual = list(package_ops)
    if len(expected) != len(actual):
        return False, f"指令条数不同: 参考 {len(expected)} / 包 {len(actual)}"
    for idx, (want, got) in enumerate(zip(expected, actual)):
        if want[0] != got[0]:
            return False, f"第 {idx} 条类型不同: 参考 {want[0]} / 包 {got[0]}"
        if want[0] == "COPY":
            if want[1] != got[1] or want[2] != got[2]:
                return (False,
                        f"第 {idx} 条 COPY 不同: 参考 {want[1:]} / 包 {got[1:]}")
        else:
            if want[1] != got[1]:
                return (False,
                        f"第 {idx} 条 LITERAL 内容不同: "
                        f"参考 {len(want[1])} 字节 / 包 {len(got[1])} 字节")
    return True, "一致"


def parse_package(raw: bytes):
    """极简独立解析器：只处理 v1，用于读取生产包做比较（不 import 正式模块）。"""
    if raw[:8] != b"PWDELTA1":
        raise ValueError("bad magic")
    partner_len = int.from_bytes(raw[10:12], "big")
    event_len = int.from_bytes(raw[12:14], "big")
    block_size = int.from_bytes(raw[14:18], "big")
    old_len = int.from_bytes(raw[18:26], "big")
    new_len = int.from_bytes(raw[58:66], "big")
    pos = 98 + partner_len + event_len + 8
    ops = []
    while True:
        if raw[pos:pos + 8] == b"PWEND001":
            break
        opcode = raw[pos]
        if opcode == 1:
            offset = int.from_bytes(raw[pos + 1:pos + 9], "big")
            length = int.from_bytes(raw[pos + 9:pos + 13], "big")
            ops.append(("COPY", offset, length))
            pos += 13
        elif opcode == 2:
            length = int.from_bytes(raw[pos + 1:pos + 5], "big")
            ops.append(("LITERAL", raw[pos + 5:pos + 5 + length]))
            pos += 5 + length
        else:
            raise ValueError(f"bad opcode {opcode} at {pos}")
    return {
        "block_size": block_size,
        "old_length": old_len,
        "new_length": new_len,
        "partner_len": partner_len,
        "event_len": event_len,
        "ops": ops,
    }
