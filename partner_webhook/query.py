"""有限 JSON 查询表达式：校验、SQL 编译与执行。

表达式语法（每个对象只能有**一个**操作键，其他键一律报错）：

    {"and": [expr, ...]}                     非空列表
    {"or":  [expr, ...]}                     非空列表
    {"not": expr}                            按当前作用域取反
    {"any": {"path": [seg, ...], "where": expr}}
    {"exists": {"path": [seg, ...]}}
    {"eq"|"lt"|"lte"|"gt"|"gte": {"path": [...], "value": scalar}}

``path`` 是对象真实键名数组；点、斜杠、空格、空键都没有特殊含义。只有 ``any``
可以跨过数组，路径中的字符串段永远不会被解释为数组下标。

查询完全建立在持久索引（``partner_webhook/indexstore.py``）的 ``nodes`` 表上：
按 ``parent_id`` 逐段解析路径、按 ``array_instance`` 归组数组元素，查询时不再
解析任何源正文。
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .strictjson import (
    JsonBodyError,
    JsonObject,
    RawNumber,
    decimal_parts,
    parse_strict_json,
)

COMPARISONS = ("eq", "lt", "lte", "gt", "gte")
LOGICAL = ("and", "or", "not")
CONTAINERS = ("any", "exists")
OPS = set(COMPARISONS) | set(LOGICAL) | set(CONTAINERS)


class QueryError(Exception):
    """表达式非法或查询环境不可用。调用方必须整体失败，不输出半份结果。"""


# --------------------------------------------------------------------- #
# 表达式校验
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class Expr:
    op: str
    children: tuple["Expr", ...] = ()
    path: tuple[str, ...] = ()
    value: tuple | None = None        # 已归一化的标量


def _scalar(value: Any) -> tuple:
    """把严格解析出的标量归一化为可精确绑定的元组。"""
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", 1 if value else 0)
    if isinstance(value, RawNumber):
        return ("num",) + decimal_parts(value)
    if isinstance(value, str):
        return ("str", value)
    raise QueryError(
        "比较值必须是标量（字符串、数字、布尔或 null），"
        f"实际是 {type(value).__name__}"
    )


def _path_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QueryError(f"{where} 的 path 必须是字符串段数组")
    segments: list[str] = []
    for segment in value:
        if not isinstance(segment, str):
            raise QueryError(
                f"{where} 的 path 段必须是字符串；不允许用数字/数字字符串"
                "冒充满数组下标"
            )
        segments.append(segment)
    return tuple(segments)


def _one_key(value: Any, where: str) -> tuple[str, Any]:
    if not isinstance(value, JsonObject):
        raise QueryError(f"{where} 必须是只有一个操作键的对象")
    keys = list(value.keys)
    if len(keys) != 1:
        raise QueryError(
            f"{where} 每个表达式只允许一个操作，实际键: {keys!r}"
        )
    op = keys[0]
    if op not in OPS:
        raise QueryError(f"未知查询操作 {op!r}")
    return op, value.values[op]


def _exact_keys(value: Any, required: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, JsonObject):
        raise QueryError(f"{where} 必须是对象")
    keys = set(value.keys)
    extra = keys - required
    missing = required - keys
    if extra:
        raise QueryError(f"{where} 有多余参数: {sorted(extra)!r}")
    if missing:
        raise QueryError(f"{where} 缺少参数: {sorted(missing)!r}")
    return value.values


def parse_expression(document: Any) -> Expr:
    """把严格 JSON 解析结果校验为内部表达式树。"""
    op, body = _one_key(document, "表达式")
    if op in ("and", "or"):
        if not isinstance(body, list):
            raise QueryError(f"{op} 需要非空表达式列表")
        if not body:
            raise QueryError(f"{op} 的表达式列表不能为空")
        return Expr(op, tuple(parse_expression(item) for item in body))
    if op == "not":
        return Expr(op, (parse_expression(body),))
    if op == "exists":
        args = _exact_keys(body, {"path"}, "exists")
        return Expr(op, path=_path_list(args["path"], "exists"))
    if op == "any":
        args = _exact_keys(body, {"path", "where"}, "any")
        path = _path_list(args["path"], "any")
        where = parse_expression(args["where"])
        return Expr(op, (where,), path=path)
    # 比较操作
    args = _exact_keys(body, {"path", "value"}, op)
    path = _path_list(args["path"], op)
    value = _scalar(args["value"])
    if op in ("lt", "lte", "gt", "gte") and value[0] != "num":
        raise QueryError(
            f"{op} 只支持数字比较值；字符串/布尔/null 不能参与有序比较"
        )
    return Expr(op, path=path, value=value)


def parse_expression_text(text: str) -> Expr:
    """从 JSON 文本读入表达式（数字保持精确十进制）。"""
    try:
        document = parse_strict_json(text.encode("utf-8"))
    except JsonBodyError as exc:
        raise QueryError(f"表达式不是严格 JSON: {exc.message}") from None
    return parse_expression(document)


# --------------------------------------------------------------------- #
# SQL 编译
# --------------------------------------------------------------------- #
class _Compiler:
    def __init__(self, parser_version: int):
        self.parser_version = parser_version
        self.counter = 0

    def alias(self) -> str:
        self.counter += 1
        return f"n{self.counter}"

    # -- 工具 -------------------------------------------------------- #
    def _path_exists_sql(self, scope: str, path: tuple[str, ...],
                         predicate: str | None) -> tuple[str, list]:
        """从 ``scope`` 节点逐段解析 path；返回相关 EXISTS 子查询。

        ``predicate`` 为 None 时只判断路径存在。数组元素节点的 field_name
        为 NULL，因此任何字符串路径段都不会「跨过」数组。``predicate`` 中
        应使用 ``{P}`` 占位最终节点别名（别名在编译期才知道）。
        """
        alias = self.alias()
        from_sql = f"nodes {alias}"
        params: list[Any] = []
        previous = alias
        for segment in path[1:]:
            child = self.alias()
            from_sql += (
                f" JOIN nodes {child} ON {child}.body_sha256 = {previous}.body_sha256"
                f" AND {child}.parser_version = {previous}.parser_version"
                f" AND {child}.parent_id = {previous}.node_id"
                f" AND {child}.field_name = ?"
            )
            params.append(segment)
            previous = child
        conditions = (
            f"{alias}.body_sha256 = {scope}.body_sha256"
            f" AND {alias}.parser_version = {scope}.parser_version"
            f" AND {alias}.parent_id = {scope}.node_id"
            f" AND {alias}.field_name = ?"
        )
        params.append(path[0])
        if predicate is not None:
            # 谓词作用于路径**最终**节点（previous），而不是首段节点。
            conditions += f" AND ({predicate.replace('{P}', previous)})"
        return f"EXISTS (SELECT 1 FROM {from_sql} WHERE {conditions})", params

    # -- 谓词 -------------------------------------------------------- #
    @staticmethod
    def _number_eq(alias: str, value: tuple) -> tuple[str, list]:
        _, negative, digits, exponent = value
        return (
            f"{alias}.json_type = 'number' AND {alias}.num_neg = ?"
            f" AND {alias}.num_digits = ? AND {alias}.num_exp = ?",
            [negative, digits, str(exponent)],
        )

    @staticmethod
    def _number_order(alias: str, op: str, value: tuple) -> tuple[str, list]:
        _, negative, digits, exponent = value
        operator = {"lt": "< 0", "lte": "<= 0", "gt": "> 0", "gte": ">= 0"}[op]
        return (
            f"{alias}.json_type = 'number' AND pw_num_cmp("
            f"{alias}.num_neg, {alias}.num_digits, {alias}.num_exp, ?, ?, ?) "
            f"{operator}",
            [negative, digits, str(exponent)],
        )

    def _cmp_predicate(self, alias: str, expr: Expr) -> tuple[str, list]:
        """返回使用 ``{P}`` 作为被比较节点占位符的谓词。"""
        assert expr.value is not None
        kind = expr.value[0]
        if expr.op == "eq":
            if kind == "null":
                return "{P}.json_type = 'null'", []
            if kind == "bool":
                return (
                    "{P}.json_type = 'boolean' AND {P}.bool_value = ?",
                    [expr.value[1]],
                )
            if kind == "str":
                return (
                    "{P}.json_type = 'string' AND {P}.str_value = ?",
                    [expr.value[1]],
                )
            return self._number_eq("{P}", expr.value)
        return self._number_order("{P}", expr.op, expr.value)

    # -- 表达式 ------------------------------------------------------ #
    def compile(self, expr: Expr, scope: str) -> tuple[str, list]:
        if expr.op in ("and", "or"):
            parts = []
            params: list[Any] = []
            for child in expr.children:
                sql, child_params = self.compile(child, scope)
                parts.append(f"({sql})")
                params.extend(child_params)
            joiner = " AND " if expr.op == "and" else " OR "
            return joiner.join(parts), params
        if expr.op == "not":
            sql, params = self.compile(expr.children[0], scope)
            return f"NOT ({sql})", params
        if expr.op == "exists":
            if not expr.path:
                return "1", []
            sql, params = self._path_exists_sql(scope, expr.path, None)
            return sql, params
        if expr.op == "any":
            # 内层作用域别名在编译内层时才知道。先编译内层（会继续分配
            # 别名），用本层唯一的占位符引用「当前元素」，之后替换成真实
            # 别名；嵌套 any 各有各的占位符，不会互相串接。
            self.counter += 1
            scope_placeholder = f"__scope_{self.counter}__"
            element_where, element_params = self.compile(expr.children[0],
                                                         scope_placeholder)
            element = self.alias()
            element_where = element_where.replace(scope_placeholder, element)
            # 数组节点由 _path_exists_sql 决定别名，这里统一用 {P} 占位。
            element_sql = (
                f"EXISTS (SELECT 1 FROM nodes {element}"
                f" WHERE {element}.body_sha256 = {{P}}.body_sha256"
                f" AND {element}.parser_version = {{P}}.parser_version"
                f" AND {element}.parent_id = {{P}}.node_id"
                f" AND ({element_where}))"
            )
            # 目标必须是真正的数组（对象也有子节点，不能误当元素）
            predicate = f"{{P}}.json_type = 'array' AND {element_sql}"
            if not expr.path:
                # 空 path：当前值本身就是数组，直接检查作用域节点。
                return (f"({predicate.replace('{P}', scope)})",
                        element_params)
            sql, path_params = self._path_exists_sql(scope, expr.path,
                                                     predicate)
            # _path_exists_sql 的占位符顺序是「path 段参数, predicate 参数」。
            return sql, path_params + element_params
        # 比较
        predicate, params = self._cmp_predicate(scope, expr)
        if not expr.path:
            return f"({predicate.replace('{P}', scope)})", params
        sql, path_params = self._path_exists_sql(scope, expr.path, predicate)
        return sql, path_params + params


# --------------------------------------------------------------------- #
# 数字比较 UDF（只作用于已持久化的规范化数字列，不解析正文）
# --------------------------------------------------------------------- #
def _num_cmp(neg_a, digits_a, exp_a, neg_b, digits_b, exp_b):
    if None in (neg_a, digits_a, exp_a, neg_b, digits_b, exp_b):
        return None
    from .strictjson import compare_numbers

    return compare_numbers(
        (int(neg_a), str(digits_a), int(exp_a)),
        (int(neg_b), str(digits_b), int(exp_b)),
    )

def register_functions(conn: sqlite3.Connection) -> None:
    conn.create_function("pw_num_cmp", 6, _num_cmp, deterministic=True)


# --------------------------------------------------------------------- #
# 执行
# --------------------------------------------------------------------- #
@dataclass
class QueryResult:
    partner_id: str
    generation: int
    total: int
    limit: int
    offset: int
    events: list[dict]


def _current_generation(conn: sqlite3.Connection) -> tuple[int, int]:
    try:
        row = conn.execute(
            "SELECT value FROM index_meta WHERE key = 'current_generation'"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        raise QueryError(f"索引库尚未建立: {exc}") from None
    if row is None:
        raise QueryError("索引尚未发布任何一代；请先执行 index-sync")
    generation = int(row[0])
    published = conn.execute(
        "SELECT status, parser_version FROM index_generations WHERE generation = ?",
        (generation,),
    ).fetchone()
    if published is None or published[0] != "published":
        raise QueryError("索引元数据指向未发布的一代，索引不完整")
    return generation, int(published[1])


def run_query(index_conn: sqlite3.Connection, *, partner_id: str,
              expr: Expr, limit: int, offset: int) -> QueryResult:
    """在索引上执行查询。总数与分页行来自同一只读事务 / 同一代索引。"""
    if not partner_id:
        raise QueryError("必须指定合作方（partner_id）")
    if limit < 1:
        raise QueryError("limit 必须 >= 1")
    if offset < 0:
        raise QueryError("offset 必须 >= 0")
    register_functions(index_conn)
    conn = index_conn
    conn.execute("BEGIN")
    try:
        generation, parser_version = _current_generation(conn)
        compiler = _Compiler(parser_version)
        expr_sql, expr_params = compiler.compile(expr, "root")
        base = (
            " FROM events doc"
            " JOIN nodes root ON root.body_sha256 = doc.body_sha256"
            " AND root.parser_version = doc.parser_version"
            " AND root.parent_id IS NULL AND root.json_type = 'object'"
            " WHERE doc.generation = ? AND doc.partner_id = ?"
            " AND doc.status = 'indexed'"
            f" AND ({expr_sql})"
        )
        base_params: list[Any] = [generation, partner_id] + expr_params
        total = conn.execute("SELECT COUNT(*)" + base, base_params).fetchone()[0]
        rows = conn.execute(
            "SELECT doc.event_id, doc.body_sha256, doc.byte_length"
            " FROM events doc"
            " JOIN nodes root ON root.body_sha256 = doc.body_sha256"
            " AND root.parser_version = doc.parser_version"
            " AND root.parent_id IS NULL AND root.json_type = 'object'"
            " WHERE doc.generation = ? AND doc.partner_id = ?"
            " AND doc.status = 'indexed'"
            f" AND ({expr_sql})"
            " ORDER BY doc.event_id ASC LIMIT ? OFFSET ?",
            base_params + [limit, offset],
        ).fetchall()
        events = [
            {
                "partner_id": partner_id,
                "event_id": row["event_id"],
                "body_sha256": row["body_sha256"],
                "byte_length": row["byte_length"],
            }
            for row in rows
        ]
        conn.execute("COMMIT")
        return QueryResult(partner_id=partner_id, generation=generation,
                           total=int(total), limit=limit, offset=offset,
                           events=events)
    except Exception:
        conn.execute("ROLLBACK")
        raise


__all__ = [
    "Expr", "QueryError", "QueryResult", "parse_expression",
    "parse_expression_text", "register_functions", "run_query",
]
