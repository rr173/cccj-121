"""「同一元素满足整个 where」的独立核对器（不经过正式索引）。

只用于小样本：直接对严格 JSON 树求值，按数组元素逐层下钻。正式查询走
``partner_webhook/query.py`` 的持久索引 SQL；两者互不调用，结果可交叉核对。

求值规则与正式索引保持一致：缺失 ≠ null；eq 按 JSON 类型比较；数字按精确
十进制比较；有序比较只接受数字；``not`` 在当前作用域取反；``any`` 对空数组
为假。
"""

from __future__ import annotations

from typing import Any

from .strictjson import (
    JsonObject,
    RawNumber,
    compare_numbers,
    decimal_parts,
)


def _lookup(value: Any, path: tuple[str, ...]):
    """返回 (是否存在, 值)。数组元素没有字符串键，所以路径永远不会跨数组。"""
    current = value
    for segment in path:
        if not isinstance(current, JsonObject):
            return False, None
        if segment not in current.values:
            return False, None
        current = current.values[segment]
    return True, current


def _is_number(value: Any) -> bool:
    return isinstance(value, RawNumber)


def _compare(op: str, left: Any, right: Any) -> bool:
    if op == "eq":
        if isinstance(right, tuple):
            # 查询值已归一化
            kind = right[0]
            if kind == "null":
                return left is None
            if kind == "bool":
                return isinstance(left, bool) and (1 if left else 0) == right[1]
            if kind == "str":
                return isinstance(left, str) and left == right[1]
            if kind == "num":
                return (_is_number(left)
                        and compare_numbers(decimal_parts(left), right[1:]) == 0)
            raise AssertionError(right)
        return False
    # 有序比较：两侧都必须是数字
    if not (_is_number(left) and isinstance(right, tuple)
            and right[0] == "num"):
        return False
    result = compare_numbers(decimal_parts(left), right[1:])
    return {"lt": result < 0, "lte": result <= 0,
            "gt": result > 0, "gte": result >= 0}[op]


def evaluate(expr, scope: Any, scope_exists: bool = True) -> bool:
    """在当前作用域求值。``scope_exists`` 表示当前值本身是否存在。"""
    op = expr.op
    if op == "and":
        return all(evaluate(child, scope, scope_exists)
                   for child in expr.children)
    if op == "or":
        return any(evaluate(child, scope, scope_exists)
                   for child in expr.children)
    if op == "not":
        return not evaluate(expr.children[0], scope, scope_exists)
    if op == "exists":
        if not expr.path:
            return scope_exists
        found, _ = _lookup(scope, expr.path)
        return found
    if op == "any":
        found, target = _lookup(scope, expr.path) if expr.path else (
            scope_exists, scope)
        if not found or not isinstance(target, list):
            return False
        return any(evaluate(expr.children[0], element, True)
                   for element in target)
    # 比较
    if not expr.path:
        if not scope_exists:
            return False
        return _compare(op, scope, expr.value)
    found, value = _lookup(scope, expr.path)
    if not found:
        return False
    return _compare(op, value, expr.value)


__all__ = ["evaluate"]
