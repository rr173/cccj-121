"""RFC 6901 JSON Pointer 与 RFC 6902 JSON Patch 解释器（档案加工专用）。

本模块只操作普通 Python 容器（``dict`` / ``list``）与
``strictjson.RawNumber``（精确保留的十进制数字）。关键约定：

* :func:`apply_patch` 先深拷贝再逐条应用，**绝不就地改写调用方传入的档案**；
  任一操作失败即抛 :class:`PatchError`，工作副本整体丢弃，调用方手里的原档案
  仍然是合法当前档案——不存在「捕获异常后继续使用半改对象」的路径。
* 指针按 RFC 6901 解码：``~1`` → ``/``、``~0`` → ``~``，未知转义（如 ``~2``）
  拒绝；空字符串指根；对象的空键、数字键、带斜杠键都按原名访问。
* 数组只接受规范非负十进制下标（``0``、``12``），拒绝 ``01``、负数、越界；
  ``-`` 仅允许出现在 ``add`` 的数组末尾位置，不能用于读取。
* 数字比较走 ``strictjson`` 的精确十进制键：``1`` 与 ``1.0`` 相等，
  布尔与数字不相等，超大整数不经过 float。
"""

from __future__ import annotations

import re
from typing import Any

from .strictjson import JsonObject, RawNumber, compare_numbers, decimal_parts

# 档案从未由 seed 建立（区别于根被 remove 后的 MISSING）。
UNBORN = object()
# 根被 remove 后的状态：「本修订没有档案」，与档案内容为 null 不同。
MISSING = object()

_ARRAY_INDEX_RE = re.compile(r"0|[1-9][0-9]*")


class PatchError(Exception):
    """一条 patch 操作不成立。

    ``op_index`` 为 0 基操作序号；``pointer`` 是失败位置（指针原文，根为
    空串）；``code`` 是稳定机器码，``message`` 是可解释中文原因。
    """

    def __init__(self, op_index: int, pointer: str, code: str, message: str):
        super().__init__(message)
        self.op_index = op_index
        self.pointer = pointer
        self.code = code
        self.message = message

    def op_number(self) -> int:
        """1 基操作序号，用于「第几个操作」的人工解释。"""
        return self.op_index + 1


# --------------------------------------------------------------------- #
# 深拷贝（RawNumber 与标量不可变，可直接共享；容器重新建立）
# --------------------------------------------------------------------- #
def deep_copy(value: Any) -> Any:
    if value is MISSING or value is UNBORN:
        return value
    if isinstance(value, JsonObject):
        return {key: deep_copy(item) for key, item in value.values.items()}
    if isinstance(value, dict):
        return {key: deep_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [deep_copy(item) for item in value]
    return value


# --------------------------------------------------------------------- #
# RFC 6901 JSON Pointer
# --------------------------------------------------------------------- #
def parse_pointer(text: Any) -> tuple[str, ...]:
    """把指针字符串解码为 token 元组；非法转义/非字符串直接报错。"""
    if not isinstance(text, str):
        raise ValueError("JSON Pointer 必须是字符串")
    if text == "":
        return ()
    if not text.startswith("/"):
        raise ValueError(f"非空 JSON Pointer 必须以 / 开头: {text!r}")
    tokens: list[str] = []
    for raw in text.split("/")[1:]:
        i = 0
        while i < len(raw):
            if raw[i] == "~" and (i + 1 >= len(raw) or raw[i + 1] not in "01"):
                raise ValueError(
                    f"JSON Pointer 含未知转义 {raw[i:i + 2]!r}（只允许 ~0 与 ~1）"
                )
            i += 1
        # RFC 6901 规定的解码顺序：先 ~1 再 ~0。
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def _array_index(token: str, length: int, *, allow_dash: bool,
                 insert: bool = False) -> int:
    """规范数组下标。

    读取（``insert=False``）：只接受 ``0 <= index < length``。
    插入（``insert=True``，add/move/copy 到数组）：允许 ``index == length``
    追加到末尾；``-`` 也只在插入语义下合法。
    """
    if token == "-":
        if not allow_dash:
            raise ValueError("'-' 只能用于 add 到数组末尾，不能作为读取位置")
        return length
    if not _ARRAY_INDEX_RE.fullmatch(token):
        raise ValueError(
            f"数组下标必须是规范非负十进制整数（拒绝 01、负数等）: {token!r}"
        )
    index = int(token)
    limit = length if insert else length - 1
    if index > limit:
        kind = "插入位置" if insert else "下标"
        raise ValueError(f"数组{kind}越界: {index} > {limit}（当前长度 {length}）")
    return index


def _resolve(doc: Any, tokens: tuple[str, ...], *, op_index: int,
             pointer: str, allow_dash: bool = False) -> Any:
    """按 token 读取目标；对象按键名、数组按规范下标，目标必须存在。"""
    current = doc
    if current is MISSING:
        raise PatchError(op_index, pointer, "target_missing",
                         "档案当前不存在（根已被 remove），无法定位该位置")
    for depth, token in enumerate(tokens):
        if isinstance(current, JsonObject):
            current = current.values
        if isinstance(current, dict):
            if token not in current:
                raise PatchError(
                    op_index, pointer, "target_missing",
                    f"对象缺少成员 {token!r}（指针段 {depth}）",
                )
            current = current[token]
        elif isinstance(current, list):
            try:
                index = _array_index(token, len(current), allow_dash=allow_dash)
            except ValueError as exc:
                raise PatchError(op_index, pointer, "bad_index", str(exc)) from None
            if index >= len(current):
                raise PatchError(op_index, pointer, "target_missing",
                                 f"数组位置 {index} 不存在（长度 {len(current)}）")
            current = current[index]
        else:
            raise PatchError(
                op_index, pointer, "not_a_container",
                f"指针段 {depth} 的当前值不是对象或数组，无法继续访问 {token!r}",
            )
    return current


def _resolve_parent(doc: Any, tokens: tuple[str, ...], *, op_index: int,
                    pointer: str, for_add: bool):
    """导航到父容器与最后一段键；根指针返回 ``(None, None)``。"""
    if not tokens:
        return None, None
    parent_tokens, last = tokens[:-1], tokens[-1]
    parent = _resolve(doc, parent_tokens, op_index=op_index, pointer=pointer)
    if isinstance(parent, JsonObject):
        parent = parent.values
    if not isinstance(parent, (dict, list)):
        raise PatchError(op_index, pointer, "not_a_container",
                         "add 的父节点必须是对象或数组")
    if isinstance(parent, list):
        try:
            key = _array_index(last, len(parent), allow_dash=for_add,
                               insert=for_add)
        except ValueError as exc:
            raise PatchError(op_index, pointer, "bad_index", str(exc)) from None
    else:
        key = last
    return parent, key


# --------------------------------------------------------------------- #
# RFC 6902 结构相等（test 用）
# --------------------------------------------------------------------- #
def json_equal(left: Any, right: Any) -> bool:
    """按 JSON 结构与值比较：对象成员顺序无关、数组顺序有关。

    布尔与数字不相等；数字用精确十进制比较（``1`` == ``1.0``），不经过 float。
    接受严格值模型（``JsonObject`` / ``RawNumber``）与普通 dict/list 的混用。
    """
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, JsonObject):
        left = left.values
    if isinstance(right, JsonObject):
        right = right.values
    if isinstance(left, RawNumber) or isinstance(right, RawNumber):
        if not (isinstance(left, RawNumber) and isinstance(right, RawNumber)):
            return False
        return compare_numbers(decimal_parts(left), decimal_parts(right)) == 0
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, dict) or isinstance(right, dict):
        if not (isinstance(left, dict) and isinstance(right, dict)):
            return False
        if set(left) != set(right):
            return False
        return all(json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list) or isinstance(right, list):
        if not (isinstance(left, list) and isinstance(right, list)):
            return False
        return len(left) == len(right) and all(
            json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


# --------------------------------------------------------------------- #
# 六种操作
# --------------------------------------------------------------------- #
def _op_add(doc: Any, op: dict, op_index: int) -> Any:
    pointer = op["path"]
    tokens = parse_pointer(pointer)
    if not tokens:
        # 根 add：档案不存在时这是唯一能重新建档的操作；已存在时整体替换。
        return deep_copy(op["value"])
    parent, key = _resolve_parent(doc, tokens, op_index=op_index,
                                  pointer=pointer, for_add=True)
    value = deep_copy(op["value"])
    if isinstance(parent, dict):
        parent[key] = value  # 已存在成员：按 RFC 6902 直接替换。
    else:
        parent.insert(key, value)  # key == len(parent) 时即追加（含 "-"）。
    return doc


def _op_remove(doc: Any, op: dict, op_index: int) -> Any:
    pointer = op["path"]
    tokens = parse_pointer(pointer)
    if not tokens:
        # remove 根：进入「本修订没有档案」状态。
        return MISSING
    target = _resolve(doc, tokens, op_index=op_index, pointer=pointer)
    parent_tokens, last = tokens[:-1], tokens[-1]
    parent = _resolve(doc, parent_tokens, op_index=op_index, pointer=pointer)
    if isinstance(parent, dict):
        del parent[last]
    else:
        index = _array_index(last, len(parent), allow_dash=False)
        del parent[index]
    return doc


def _op_replace(doc: Any, op: dict, op_index: int) -> Any:
    pointer = op["path"]
    tokens = parse_pointer(pointer)
    if not tokens:
        if doc is MISSING:
            raise PatchError(op_index, pointer, "target_missing",
                             "档案当前不存在；根位置只能用 add 重新建档")
        return deep_copy(op["value"])
    # 必须先找到目标，否则 replace 不成立。
    _resolve(doc, tokens, op_index=op_index, pointer=pointer)
    parent_tokens, last = tokens[:-1], tokens[-1]
    parent = _resolve(doc, parent_tokens, op_index=op_index, pointer=pointer)
    value = deep_copy(op["value"])
    if isinstance(parent, dict):
        parent[last] = value
    else:
        index = _array_index(last, len(parent), allow_dash=False)
        parent[index] = value
    return doc


def _is_proper_prefix(prefix: tuple[str, ...], path: tuple[str, ...]) -> bool:
    return len(path) > len(prefix) and path[:len(prefix)] == prefix


def _op_move(doc: Any, op: dict, op_index: int) -> Any:
    from_pointer = op["from"]
    to_pointer = op["path"]
    from_tokens = parse_pointer(from_pointer)
    to_tokens = parse_pointer(to_pointer)
    if _is_proper_prefix(from_tokens, to_tokens):
        raise PatchError(op_index, to_pointer, "move_into_descendant",
                         f"不能把 {from_pointer!r} 移动到自己的后代 {to_pointer!r}")
    if from_tokens == to_tokens:
        return doc  # 同位置移动：无操作。
    # 1) 先取出（必须存在；"-" 不允许读取）。
    value = deep_copy(_resolve(doc, from_tokens, op_index=op_index,
                               pointer=from_pointer))
    # 2) 再从原档案删除。
    if not from_tokens:
        doc = MISSING
    else:
        parent = _resolve(doc, from_tokens[:-1], op_index=op_index,
                          pointer=from_pointer)
        last = from_tokens[-1]
        if isinstance(parent, dict):
            del parent[last]
        else:
            del parent[_array_index(last, len(parent), allow_dash=False)]
    # 3) 按删除后的档案定位插入点（数组下标因此基于删除后的长度）。
    if not to_tokens:
        return value
    parent, key = _resolve_parent(doc, to_tokens, op_index=op_index,
                                  pointer=to_pointer, for_add=True)
    if isinstance(parent, dict):
        parent[key] = value
    else:
        parent.insert(key, value)
    return doc


def _op_copy(doc: Any, op: dict, op_index: int) -> Any:
    from_pointer = op["from"]
    to_pointer = op["path"]
    from_tokens = parse_pointer(from_pointer)
    to_tokens = parse_pointer(to_pointer)
    # 独立树：深拷贝后插入，后续改副本不影响原值。
    value = deep_copy(_resolve(doc, from_tokens, op_index=op_index,
                               pointer=from_pointer))
    if not to_tokens:
        return value
    parent, key = _resolve_parent(doc, to_tokens, op_index=op_index,
                                  pointer=to_pointer, for_add=True)
    if isinstance(parent, dict):
        parent[key] = value
    else:
        parent.insert(key, value)
    return doc


def _op_test(doc: Any, op: dict, op_index: int) -> Any:
    pointer = op["path"]
    tokens = parse_pointer(pointer)
    target = _resolve(doc, tokens, op_index=op_index, pointer=pointer)
    if not json_equal(target, op["value"]):
        raise PatchError(op_index, pointer, "test_failed",
                         "test 比较失败：实际值与给定值结构或值不一致")
    return doc


_DISPATCH = {
    "add": _op_add,
    "remove": _op_remove,
    "replace": _op_replace,
    "move": _op_move,
    "copy": _op_copy,
    "test": _op_test,
}


def _plain_ops(operations: list) -> list[dict]:
    """把严格解析的 ``JsonObject`` 操作归一化为普通 dict（值模型原样保留）。"""
    plain: list[dict] = []
    for op in operations:
        if isinstance(op, JsonObject):
            plain.append(dict(op.values))
        elif isinstance(op, dict):
            plain.append(op)
        else:
            raise PatchError(len(plain), "", "invalid_operation",
                             "操作必须是 JSON 对象")
    return plain


def _normalize_numbers(value: Any) -> Any:
    """把操作值里混入的普通 Python 整数归一化为精确数字模型。

    严格解析路径产出的本来就是 ``RawNumber``；这里只兜底手写/程序化构造的
    int（布尔不会被当数字）。float 不在这里隐式转换，以免丢失精度语义，
    调用方应直接给 ``RawNumber``。
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return RawNumber(str(value))
    if isinstance(value, dict):
        return {key: _normalize_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_numbers(item) for item in value]
    return value


def apply_patch(doc: Any, operations: list) -> Any:
    """按顺序对档案副本应用一组操作；全成立才返回新档案，否则抛异常。

    调用方传入的 ``doc`` 不会被修改：所有操作都作用在深拷贝工作副本上，
    失败时工作副本随异常丢弃。
    """
    work = deep_copy(doc)
    for op_index, op in enumerate(_plain_ops(operations)):
        if "value" in op:
            op = {**op, "value": _normalize_numbers(op["value"])}
        handler = _DISPATCH[op["op"]]
        work = handler(work, op, op_index)
    return work


__all__ = [
    "MISSING", "UNBORN", "PatchError", "apply_patch", "deep_copy",
    "json_equal", "parse_pointer",
]
