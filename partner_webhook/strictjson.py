"""严格 JSON 正文解析（正文索引专用）。

与日常 ``json.loads`` 的区别（这些区别正是索引能够可信的前提）：

* 只接受 UTF-8 字节的严格 JSON；拒绝 NaN / Infinity / -Infinity；
* 拒绝同一对象内的重复键（不采用「后值覆盖」的宽松行为）；
* 拒绝截断文本（解析器必须恰好消费完全部输入）；
* 拒绝以数字字符串冒充数组下标——解析阶段只产出普通值；
* **数字一律保留原文十进制写法**（``RawNumber``），不经过 float 或
  SQLite REAL。``30`` / ``30.0`` / ``1e400`` / 相邻超大整数等都能精确判等
  与排序。

入口是 ``parse_strict_json``（严格解析）与 ``read_json_body``（读取正文时
附加登记摘要 / 长度核对）。索引构建时调用 ``collect_nodes``，把正文摊平成
「路径 + 类型 + 数组实例」的持久节点；查询阶段不再重新解析任何正文。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable

# 本解析器/摊平规则的版本号。规则变化时提升，索引会为新版本重新解析正文，
# 旧一代索引仍引用旧版本节点，不会被就地改写。
PARSER_VERSION = 1


class JsonBodyError(Exception):
    """正文不能作为严格 JSON 解释。``code`` 供索引登记与演示使用。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------- #
# 值模型
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class RawNumber:
    """JSON 数字的精确十进制表示。"""

    text: str

    def to_decimal(self):
        from decimal import Decimal

        return Decimal(self.text)

    def __str__(self) -> str:
        return self.text


@dataclass(frozen=True)
class JsonObject:
    """按出现顺序保存键值对。"""

    values: dict[str, Any]

    @property
    def keys(self) -> tuple[str, ...]:
        return tuple(self.values.keys())


# --------------------------------------------------------------------- #
# 词法 / 语法
# --------------------------------------------------------------------- #
_WHITESPACE = " \t\n\r"
# 指数以十进制文本持久化（不转 SQLite INTEGER），因此 1e400 乃至更大的
# 有限十进制都能精确保留；比较在 UDF 中用 Python 大整数完成。
_MAX_DEPTH = 512
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.(?:[0-9]+))?(?:[eE][+-]?[0-9]+)?")
_LITERALS = (("true", True), ("false", False), ("null", None))
_HEX = frozenset("0123456789abcdefABCDEF")


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)

    def error(self, code: str, message: str) -> JsonBodyError:
        return JsonBodyError(code, f"{message}（位置 {self.pos}）")

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < self.length else ""

    def skip_ws(self) -> None:
        while self.pos < self.length and self.text[self.pos] in _WHITESPACE:
            self.pos += 1

    def consume(self, ch: str) -> None:
        if self.peek() != ch:
            raise self.error("invalid_json", f"期望字符 {ch!r}")
        self.pos += 1

    # -- 值 ---------------------------------------------------------- #
    def parse_document(self) -> Any:
        self.skip_ws()
        value = self.parse_value(0)
        self.skip_ws()
        if self.pos != self.length:
            raise self.error("trailing_content", "JSON 值之后还有多余内容")
        return value

    def parse_value(self, depth: int) -> Any:
        if depth > _MAX_DEPTH:
            raise self.error("invalid_json", "嵌套过深")
        ch = self.peek()
        if ch == "":
            raise self.error("truncated", "正文在值结束前截断")
        if ch == "{":
            return self.parse_object(depth)
        if ch == "[":
            return self.parse_array(depth)
        if ch == '"':
            return self.parse_string()
        for literal, result in _LITERALS:
            if self.text.startswith(literal, self.pos):
                # 字面量之后必须是分隔符，避免把 truex 当 true
                end = self.pos + len(literal)
                if end < self.length and (
                        self.text[end].isalnum() or self.text[end] in "_."):
                    break
                self.pos = end
                return result
        if ch == "-" or ch.isdigit():
            if self.text.startswith("-Infinity", self.pos):
                raise self.error("non_finite_number", "不接受 Infinity")
            return self.parse_number()
        if self.text.startswith("NaN", self.pos):
            raise self.error("non_finite_number", "不接受 NaN")
        if self.text.startswith("Infinity", self.pos) or \
                self.text.startswith("-Infinity", self.pos):
            raise self.error("non_finite_number", "不接受 Infinity")
        raise self.error("invalid_json", f"非法字符 {ch!r}")

    def parse_object(self, depth: int) -> JsonObject:
        self.consume("{")
        values: dict[str, Any] = {}
        self.skip_ws()
        if self.peek() == "}":
            self.pos += 1
            return JsonObject(values)
        while True:
            self.skip_ws()
            if self.peek() != '"':
                raise self.error("invalid_json", "对象键必须是字符串")
            key = self.parse_string()
            if key in values:
                raise JsonBodyError(
                    "duplicate_key",
                    f"同一对象内重复键 {key!r}（位置 {self.pos}）；拒绝后值覆盖",
                )
            self.skip_ws()
            self.consume(":")
            self.skip_ws()
            values[key] = self.parse_value(depth + 1)
            self.skip_ws()
            ch = self.peek()
            if ch == ",":
                self.pos += 1
                continue
            if ch == "}":
                self.pos += 1
                return JsonObject(values)
            raise self.error("invalid_json", "对象在 } 前结束")

    def parse_array(self, depth: int) -> list:
        self.consume("[")
        items: list[Any] = []
        self.skip_ws()
        if self.peek() == "]":
            self.pos += 1
            return items
        while True:
            self.skip_ws()
            items.append(self.parse_value(depth + 1))
            self.skip_ws()
            ch = self.peek()
            if ch == ",":
                self.pos += 1
                continue
            if ch == "]":
                self.pos += 1
                return items
            raise self.error("invalid_json", "数组在 ] 前结束")

    def parse_string(self) -> str:
        self.consume('"')
        chars: list[str] = []
        while True:
            if self.pos >= self.length:
                raise self.error("truncated", "字符串未闭合（正文截断）")
            ch = self.text[self.pos]
            if ch == '"':
                self.pos += 1
                return "".join(chars)
            if ch == "\\":
                self.pos += 1
                chars.append(self.parse_escape())
                continue
            if ord(ch) < 0x20:
                raise self.error("invalid_json", "字符串中含未转义控制字符")
            chars.append(ch)
            self.pos += 1

    def parse_escape(self) -> str:
        if self.pos >= self.length:
            raise self.error("truncated", "转义序列截断")
        ch = self.text[self.pos]
        self.pos += 1
        simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b",
                  "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
        if ch in simple:
            return simple[ch]
        if ch == "u":
            return self.parse_unicode_escape()
        raise JsonBodyError("invalid_json",
                            f"非法转义 \\{ch}（位置 {self.pos - 1}）")

    def parse_unicode_escape(self) -> str:
        if self.pos + 4 > self.length:
            raise self.error("truncated", "\\u 转义截断")
        digits = self.text[self.pos:self.pos + 4]
        if not all(c in _HEX for c in digits):
            raise self.error("invalid_json", "\\u 转义不是四位十六进制")
        self.pos += 4
        code = int(digits, 16)
        if 0xD800 <= code <= 0xDBFF:
            if not self.text.startswith("\\u", self.pos):
                raise self.error("invalid_json", "孤立的高代理项")
            low_digits = self.text[self.pos + 2:self.pos + 6]
            if len(low_digits) != 4 or not all(c in _HEX for c in low_digits):
                raise self.error("invalid_json", "代理对不完整")
            low = int(low_digits, 16)
            if not 0xDC00 <= low <= 0xDFFF:
                raise self.error("invalid_json", "代理对低半部非法")
            self.pos += 6
            return chr(0x10000 + (code - 0xD800) * 0x400 + (low - 0xDC00))
        if 0xDC00 <= code <= 0xDFFF:
            raise self.error("invalid_json", "孤立的低代理项")
        return chr(code)

    def parse_number(self) -> RawNumber:
        match = _NUMBER_RE.match(self.text, self.pos)
        if not match:
            raise self.error("invalid_json", "数字格式非法")
        text = match.group(0)
        self.pos = match.end()
        return RawNumber(text)


def parse_strict_json(data: bytes | str) -> Any:
    """严格解析 UTF-8 JSON 字节 / 文本，返回上述值模型。"""
    if isinstance(data, bytes):
        if data.startswith(b"\xef\xbb\xbf"):
            raise JsonBodyError("invalid_json", "不允许字节顺序标记(BOM)")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise JsonBodyError("invalid_utf8",
                                f"正文不是严格 UTF-8: {exc.reason}") from None
    else:
        text = data
    if text.startswith("﻿"):
        raise JsonBodyError("invalid_json", "不允许字节顺序标记(BOM)")
    return _Parser(text).parse_document()


# --------------------------------------------------------------------- #
# 读取正文时核对摘要 / 长度
# --------------------------------------------------------------------- #
def read_json_body(
    blob: bytes,
    *,
    expected_sha256: str,
    expected_length: int | None = None,
    require_object_root: bool = True,
) -> Any:
    """核对登记摘要与长度后再严格解释。任何不符都不降级为宽松解析。"""
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected_sha256:
        raise JsonBodyError("digest_mismatch", "正文与登记摘要不符")
    if expected_length is not None and len(blob) != expected_length:
        raise JsonBodyError(
            "length_mismatch",
            f"正文长度 {len(blob)} 与登记长度 {expected_length} 不符",
        )
    root = parse_strict_json(blob)
    if require_object_root and not isinstance(root, JsonObject):
        raise JsonBodyError("non_object_root",
                            "JSON 根必须是对象，才能作为事件正文索引")
    return root


# --------------------------------------------------------------------- #
# 摊平：路径 + 类型 + 数组实例
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class Node:
    """一个值节点。

    ``path`` 从正文根出发，每段是对象真实键名；数组元素与数组本身共享同一
    路径（数组元素没有键名，用 ``field_name=None`` 区分）。``array_instance``
    是直接包含该节点的数组的节点 ID——这正是「归属」信息：多个元素的同名
    字段虽然路径相同，但父节点不同，查询时不会串到邻居。
    """

    node_id: int
    parent_id: int | None
    field_name: str | None
    path: tuple[str, ...]
    json_type: str
    array_instance: int | None = None
    num_neg: int = 0
    num_digits: str | None = None
    num_exp: int | None = None
    str_value: str | None = None
    bool_value: int | None = None


def encode_path(path: Iterable[str]) -> str:
    """无歧义路径编码：每段带长度前缀，点/斜杠/空键/控制字符都无特殊含义。"""
    parts = []
    for segment in path:
        parts.append(f"{len(segment)}:{segment}")
    return "|".join(parts)


def decode_path(encoded: str) -> tuple[str, ...]:
    """仅供核对/诊断使用；查询不依赖该编码。"""
    if encoded == "":
        return ()
    result = []
    pos = 0
    while True:
        colon = encoded.index(":", pos)
        length = int(encoded[pos:colon])
        start = colon + 1
        result.append(encoded[start:start + length])
        pos = start + length
        if pos == len(encoded):
            return tuple(result)
        if encoded[pos] != "|":
            raise ValueError("路径编码损坏")
        pos += 1


def decimal_parts(raw: RawNumber | str) -> tuple[int, str, int]:
    """把精确十进制文本拆成 ``(负数?, 有效数字, 10 的指数)``。

    ``30``   -> (0, "3", 1)     30.0 -> (0, "3", 1)
    ``0.001``-> (0, "1", -3)    1e400 -> (0, "1", 400)
    只做字符串操作，不使用 float/Decimal 上下文，指数范围不设限。
    """
    text = raw.text if isinstance(raw, RawNumber) else raw
    negative = 0
    if text.startswith("-"):
        negative = 1
        text = text[1:]
    exp = 0
    for marker in ("e", "E"):
        idx = text.find(marker)
        if idx != -1:
            exp = int(text[idx + 1:])
            text = text[:idx]
            break
    if "." in text:
        int_part, frac_part = text.split(".", 1)
    else:
        int_part, frac_part = text, ""
    coefficient = int_part + frac_part
    significant_all = coefficient.lstrip("0")
    if not significant_all:
        return 0, "0", 0
    significant = significant_all.rstrip("0")
    removed_trailing = len(significant_all) - len(significant)
    exponent = exp - len(frac_part) + removed_trailing
    return negative, significant, exponent


def num_key(negative: int, digits: str, exponent: int) -> tuple:
    """数字判等键：值与十进制写法无关（1 与 1.0 相同）。"""
    if digits == "0":
        return (0, "0", 0)
    return (negative, digits, exponent)


def compare_numbers(a: tuple[int, str, int], b: tuple[int, str, int]) -> int:
    """精确比较两个 ``decimal_parts`` 结果，返回 -1/0/1。"""
    na, da, ea = a
    nb, db, eb = b
    if da == "0" and db == "0":
        return 0
    if da == "0":
        return 1 if nb else -1  # 0 与正/负数
    if db == "0":
        return -1 if na else 1
    if na != nb:
        return -1 if na else 1  # 负数更小
    # 同号比较绝对值：有效数字 × 10^指数
    order_a = len(da) + ea
    order_b = len(db) + eb
    if order_a != order_b:
        magnitude = -1 if order_a < order_b else 1
    else:
        width = max(len(da), len(db))
        padded_a = da.ljust(width, "0")
        padded_b = db.ljust(width, "0")
        magnitude = (padded_a > padded_b) - (padded_a < padded_b)
    return -magnitude if na else magnitude


def collect_nodes(root: Any) -> list[Node]:
    """把严格 JSON 树摊平成持久节点列表（前序，父节点先于子节点）。"""
    nodes: list[Node] = []
    next_id = 1

    def emit(path, name, value, parent_id, instance):
        nonlocal next_id
        node_id = next_id
        next_id += 1
        if isinstance(value, JsonObject):
            nodes.append(Node(node_id, parent_id, name, path, "object",
                              instance))
            for key in value.keys:
                emit(path + (key,), key, value.values[key], node_id, None)
        elif isinstance(value, list):
            nodes.append(Node(node_id, parent_id, name, path, "array",
                              instance))
            array_id = node_id
            for item in value:
                emit(path, None, item, array_id, array_id)
        elif isinstance(value, RawNumber):
            negative, digits, exponent = decimal_parts(value)
            nodes.append(Node(node_id, parent_id, name, path, "number",
                              instance, negative, digits, exponent))
        elif isinstance(value, str):
            nodes.append(Node(node_id, parent_id, name, path, "string",
                              instance, 0, None, None, value))
        elif isinstance(value, bool):
            nodes.append(Node(node_id, parent_id, name, path, "boolean",
                              instance, 0, None, None, None,
                              1 if value else 0))
        elif value is None:
            nodes.append(Node(node_id, parent_id, name, path, "null", instance))
        else:  # pragma: no cover
            raise AssertionError(f"未知 JSON 值类型: {type(value)!r}")

    emit((), None, root, None, None)
    return nodes


__all__ = [
    "JsonBodyError", "JsonObject", "Node", "RawNumber", "PARSER_VERSION",
    "collect_nodes", "compare_numbers", "decimal_parts", "decode_path",
    "encode_path", "num_key", "parse_strict_json", "read_json_body",
]
