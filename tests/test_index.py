"""正文索引、严格 JSON、查询表达式与同步语义的自动化测试。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from partner_webhook.direct_eval import evaluate
from partner_webhook.indexstore import (
    IndexError_, connect_index, index_status, sync_index,
)
from partner_webhook.query import (
    QueryError, parse_expression, parse_expression_text, register_functions,
    run_query,
)
from partner_webhook.strictjson import (
    JsonBodyError, JsonObject, RawNumber, compare_numbers, decimal_parts,
    parse_strict_json,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMP_GT_30 = ('{"any":{"path":["measurements"],"where":{"and":['
              '{"eq":{"path":["metric"],"value":"temperature"}},'
              '{"gt":{"path":["value"],"value":30}}]}}}')


class StrictJsonTests(unittest.TestCase):
    def parse(self, text):
        return parse_strict_json(text.encode("utf-8"))

    def assertRejected(self, text: bytes | str, code: str | None = None):
        with self.assertRaises(JsonBodyError) as ctx:
            parse_strict_json(text)
        if code is not None:
            self.assertEqual(ctx.exception.code, code)

    def test_duplicate_key_rejected(self):
        self.assertRejected(b'{"a":1,"a":2}', "duplicate_key")
        self.assertRejected(b'{"outer":{"a":1,"a":1}}', "duplicate_key")

    def test_non_finite_rejected(self):
        for text in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}',
                     b'[NaN]'):
            self.assertRejected(text, "non_finite_number")

    def test_truncated_and_trailing(self):
        for text in (b'{"a":1', b'{"a":"x', b'{"a":tru', b'{"a":1} x',
                     b'{"a":[1,2}'):
            self.assertRejected(text)

    def test_invalid_utf8_and_bom(self):
        self.assertRejected(b'{"a":"\xff"}', "invalid_utf8")
        self.assertRejected(b'\xef\xbb\xbf{"a":1}', "invalid_json")

    def test_surrogates(self):
        self.assertEqual(self.parse('{"a":"\\ud83d\\ude00"}').values["a"], "😀")
        self.assertRejected(b'{"a":"\\ud83d"}')
        self.assertRejected(b'{"a":"\\ude00"}')

    def test_number_text_preserved(self):
        value = self.parse('{"a":1e400,"b":30.0,"c":-0.001}')
        self.assertEqual(value.values["a"], RawNumber("1e400"))
        self.assertEqual(value.values["b"], RawNumber("30.0"))

    def test_number_equality_and_order(self):
        for a, b in (("30", "30.0"), ("1", "1.0"), ("1e2", "100"),
                     ("0.1", "1e-1"), ("-0", "0")):
            self.assertEqual(compare_numbers(decimal_parts(RawNumber(a)),
                                             decimal_parts(RawNumber(b))), 0,
                             (a, b))
        ordered = ["-1e400", "-2", "-0.5", "0", "1e-400", "0.5", "2", "1e400"]
        for left, right in zip(ordered, ordered[1:]):
            self.assertLess(
                compare_numbers(decimal_parts(RawNumber(left)),
                                decimal_parts(RawNumber(right))), 0, (left, right))
        huge_a = "9" * 60
        huge_b = huge_a + "0"
        self.assertLess(compare_numbers(decimal_parts(RawNumber(huge_a)),
                                        decimal_parts(RawNumber(huge_b))), 0)


class ExpressionValidationTests(unittest.TestCase):
    def test_valid_forms(self):
        for text in (
            '{"exists":{"path":[]}}',
            '{"eq":{"path":["a","b"],"value":null}}',
            '{"eq":{"path":[],"value":false}}',
            '{"not":{"exists":{"path":["x"]}}}',
            '{"and":[{"exists":{"path":["x"]}}]}',
            '{"or":[{"lt":{"path":["x"],"value":1}}]}',
            '{"any":{"path":["x"],"where":{"exists":{"path":[]}}}}',
        ):
            parse_expression_text(text)

    def test_rejections(self):
        bad = [
            "[]", "1", '{"and":"x"}', '{"and":[]}', '{"or":[]}',
            '{"and":[{}]}', '{"not":[]}', '{"not":[{},{}]}',
            '{"any":[]}', '{"any":{"path":[]}}',
            '{"any":{"path":["x"],"where":{}}}',
            '{"exists":{"path":"x"}}', '{"exists":{}}',
            '{"exists":{"path":[1]}}', '{"eq":{"path":["x"]}}',
            '{"eq":{"path":["x"],"value":[1]}}',
            '{"eq":{"path":["x"],"value":{"a":1}}}',
            '{"gt":{"path":["x"],"value":"1"}}',
            '{"gte":{"path":["x"],"value":true}}',
            '{"lte":{"path":["x"],"value":null}}',
            '{"eq":{"path":["x"],"value":1,"extra":2}}',
            '{"eq":{"path":["x"],"value":1},"exists":{"path":["x"]}}',
            '{"sum":{"path":["x"]}}',
        ]
        for text in bad:
            with self.assertRaises(QueryError, msg=text):
                parse_expression_text(text)

    def test_path_segments_have_no_special_meaning(self):
        for segment in ("a.b", "a/b", "", " ", "a b", "0"):
            expr = parse_expression_text(
                json.dumps({"exists": {"path": [segment]}}))
            self.assertEqual(expr.path, (segment,))


class IndexTestCase(unittest.TestCase):
    NOW = 2_000_000_000

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.source = self.dir / "source.db"
        self.index = self.dir / "index.db"
        config = {
            "max_skew_seconds": 300,
            "partners": [
                {"id": "acme", "max_skew_seconds": 300, "keys": [
                    {"version": "v1",
                     "secret_b64": "b2xkLWFjbWUtc2VjcmV0LWtleS0wMDE=",
                     "not_before": None, "not_after": None}]},
                {"id": "globex", "max_skew_seconds": 300, "keys": [
                    {"version": "g1",
                     "secret_b64": "Z2xvYmV4LW9ubHkta2V5LWcwMQ==",
                     "not_before": None, "not_after": None}]},
            ],
        }
        self.config_path = self.dir / "config.json"
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        from partner_webhook.config import load_config
        from partner_webhook.storage import Storage
        from partner_webhook.service import WebhookService

        self._config = load_config(str(self.config_path))
        self.storage = Storage(str(self.source))
        self.service = WebhookService(self._config, self.storage,
                                      clock=lambda: float(self.NOW))
        self._sequence = 0

    def tearDown(self):
        self.storage.close()
        self._tmp.cleanup()

    def deliver(self, event_id, body, *, partner="acme", key_version="v1",
                secret="old-secret"):
        from partner_webhook.canonical import (
            HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER,
            HEADER_PROTOCOL, HEADER_SEQUENCE, HEADER_SIGNATURE,
            HEADER_TIMESTAMP, canonical_bytes,
        )
        from partner_webhook.crypto import decode_secret, sign
        from partner_webhook.service import PROTOCOL_VERSION
        import base64

        if secret == "old-secret":
            secret_b64 = "b2xkLWFjbWUtc2VjcmV0LWtleS0wMDE="
        elif secret == "globex-secret":
            secret_b64 = "Z2xvYmV4LW9ubHkta2V5LWcwMQ=="
        else:
            secret_b64 = base64.b64encode(secret.encode()).decode()
        self._sequence += 1
        path = "/webhook/events"
        canonical = canonical_bytes(
            method="POST", path=path, partner_id=partner,
            key_version=key_version, timestamp=self.NOW,
            event_id=event_id, sequence=self._sequence, body=body,
        )
        headers = {
            HEADER_PROTOCOL: PROTOCOL_VERSION, HEADER_PARTNER: partner,
            HEADER_KEY_VERSION: key_version, HEADER_TIMESTAMP: str(self.NOW),
            HEADER_EVENT_ID: event_id, HEADER_SEQUENCE: str(self._sequence),
            HEADER_SIGNATURE: sign(decode_secret(secret_b64), canonical),
        }
        result = self.service.receive(method="POST", path=path,
                                      raw_headers=headers, body=body)
        self.assertEqual(result.result, "accepted", result)
        return result

    def sync(self, **kwargs):
        return sync_index(source_db=str(self.source),
                          index_db=str(self.index), **kwargs)

    def run_expr(self, expression, partner="acme", limit=100, offset=0):
        conn = connect_index(str(self.index), read_only=True)
        try:
            register_functions(conn)
            return run_query(conn, partner_id=partner,
                             expr=parse_expression_text(expression),
                             limit=limit, offset=offset)
        finally:
            conn.close()

    def ids(self, expression, partner="acme"):
        return [e["event_id"] for e in self.run_expr(expression, partner).events]

    def direct_ids(self, expression, partner="acme"):
        conn = sqlite3.connect(str(self.source))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT ae.event_id, rb.body_blob FROM accepted_events ae"
                " JOIN raw_bodies rb ON rb.body_sha256 = ae.body_sha256"
                " WHERE ae.partner_id = ? ORDER BY ae.event_id", (partner,)
            ).fetchall()
        finally:
            conn.close()
        expr = parse_expression_text(expression)
        hits = []
        for row in rows:
            try:
                root = parse_strict_json(bytes(row["body_blob"]))
            except JsonBodyError:
                continue
            # 与索引的可查询集合一致：根不是对象的事件不参与查询。
            if not isinstance(root, JsonObject):
                continue
            if evaluate(expr, root):
                hits.append(row["event_id"])
        return hits


class SameElementTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        self.deliver("acme-t20-h80", b'{"measurements":['
                     b'{"metric":"temperature","value":20},'
                     b'{"metric":"humidity","value":80}]}')
        self.deliver("acme-h80-t35", b'{"measurements":['
                     b'{"metric":"humidity","value":80},'
                     b'{"metric":"temperature","value":35}]}')
        self.deliver("acme-empty", b'{"measurements":[]}')
        self.deliver("acme-object", b'{"measurements":{}}')
        self.sync()

    def test_counterexample_not_matched(self):
        self.assertEqual(self.ids(TEMP_GT_30), ["acme-h80-t35"])

    def test_flattening_would_false_positive(self):
        # 单独看 metric=temperature 会命中 acme-t20-h80，单独看 value>30 也
        # 命中（湿度 80）；组合后必须要求同一元素。
        self.assertEqual(self.ids('{"any":{"path":["measurements"],"where":'
                                  '{"eq":{"path":["metric"],'
                                  '"value":"temperature"}}}}'),
                         ["acme-h80-t35", "acme-t20-h80"])
        self.assertEqual(self.ids('{"any":{"path":["measurements"],"where":'
                                  '{"gt":{"path":["value"],"value":30}}}}'),
                         ["acme-h80-t35", "acme-t20-h80"])

    def test_empty_and_non_array_elements(self):
        # 空数组成立（存在数组但没有元素），但任何元素谓词都命中不了它。
        self.assertEqual(self.ids('{"exists":{"path":["measurements"]}}'),
                         ["acme-empty", "acme-h80-t35", "acme-object",
                          "acme-t20-h80"])
        empty_only = ('{"and":[{"exists":{"path":["measurements"]}},'
                      '{"not":{"any":{"path":["measurements"],"where":'
                      '{"exists":{"path":[]}}}}}]}')
        self.assertEqual(self.ids(empty_only), ["acme-empty", "acme-object"])

    def test_direct_agreement(self):
        for expression in (
            TEMP_GT_30,
            '{"not":{"any":{"path":["measurements"],"where":'
            '{"eq":{"path":["metric"],"value":"temperature"}}}}}',
        ):
            self.assertEqual(self.ids(expression),
                             self.direct_ids(expression))


class NestedAndParallelAnyTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        self.deliver("dev-a", b'{"devices":['
                     b'{"name":"d1","samples":[{"v":1}]},'
                     b'{"name":"d2","samples":[{"v":50}]}]}')
        self.deliver("dev-b", b'{"devices":['
                     b'{"name":"d1","samples":[{"v":5},{"v":7}]}]}')
        self.deliver("mixed", b'{"measurements":['
                     b'{"metric":"temperature","value":20},'
                     b'{"metric":"humidity","value":80}]}')
        self.deliver("both", b'{"measurements":['
                     b'{"metric":"temperature","value":10},'
                     b'{"metric":"humidity","value":20}]}')
        self.sync()

    def test_nested_any_stays_in_element(self):
        expression = ('{"any":{"path":["devices"],"where":{"any":'
                      '{"path":["samples"],"where":'
                      '{"eq":{"path":["v"],"value":7}}}}}}')
        self.assertEqual(self.ids(expression), ["dev-b"])
        cross = ('{"any":{"path":["devices"],"where":{"and":['
                 '{"eq":{"path":["name"],"value":"d1"}},'
                 '{"any":{"path":["samples"],"where":'
                 '{"eq":{"path":["v"],"value":50}}}}]}}}')
        self.assertEqual(self.ids(cross), [])

    def test_parallel_any_may_hit_different_elements(self):
        expression = ('{"and":[{"any":{"path":["measurements"],"where":'
                      '{"eq":{"path":["metric"],"value":"temperature"}}}},'
                      '{"any":{"path":["measurements"],"where":'
                      '{"eq":{"path":["metric"],"value":"humidity"}}}}]}')
        self.assertEqual(self.ids(expression), ["both", "mixed"])

    def test_not(self):
        expression = ('{"not":{"any":{"path":["measurements"],"where":'
                      '{"eq":{"path":["metric"],"value":"temperature"}}}}}')
        self.assertEqual(self.ids(expression), ["dev-a", "dev-b"])
        self.assertEqual(self.ids(expression), self.direct_ids(expression))


class MissingNullTypeTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        self.deliver("n-null", b'{"n":null}')
        self.deliver("n-false", b'{"flag":false,"num":0,"s":"false"}')
        self.deliver("n-missing", b'{"other":1}')
        self.deliver("n-one", b'{"v":1,"one_str":"1"}')
        self.deliver("n-one-float", b'{"v":1.0}')
        self.deliver("n-dotted", b'{"a.b":{"c/d":1},"":2,"a b":3}')
        self.deliver("n-zero", b'{"v":0}')
        self.sync()

    def test_exists_null(self):
        self.assertEqual(self.ids('{"exists":{"path":["n"]}}'), ["n-null"])

    def test_eq_null(self):
        self.assertEqual(self.ids('{"eq":{"path":["n"],"value":null}}'),
                         ["n-null"])

    def test_false_is_not_zero(self):
        self.assertEqual(self.ids('{"eq":{"path":["flag"],"value":0}}'), [])
        self.assertEqual(self.ids('{"eq":{"path":["num"],"value":false}}'), [])
        self.assertEqual(self.ids('{"eq":{"path":["num"],"value":0}}'),
                         ["n-false"])

    def test_string_not_number(self):
        self.assertEqual(self.ids('{"eq":{"path":["one_str"],"value":1}}'), [])
        self.assertEqual(self.ids('{"eq":{"path":["one_str"],"value":"1"}}'),
                         ["n-one"])

    def test_numeric_equality_across_spellings(self):
        self.assertEqual(self.ids('{"eq":{"path":["v"],"value":1}}'),
                         ["n-one", "n-one-float"])

    def test_dotted_and_slashed_keys(self):
        self.assertEqual(self.ids('{"eq":{"path":["a.b","c/d"],"value":1}}'),
                         ["n-dotted"])
        self.assertEqual(self.ids('{"eq":{"path":[""],"value":2}}'),
                         ["n-dotted"])
        self.assertEqual(self.ids('{"eq":{"path":["a b"],"value":3}}'),
                         ["n-dotted"])
        self.assertEqual(self.ids('{"eq":{"path":["a"],"value":2}}'), [])

    def test_numeric_string_is_not_array_index(self):
        self.deliver("arr", b'{"measurements":[{"metric":"temperature",'
                            b'"value":35}]}')
        self.sync()
        self.assertEqual(self.ids(
            '{"eq":{"path":["measurements","0","metric"],'
            '"value":"temperature"}}'), [])

    def test_empty_path_scope(self):
        # any 的空 path 表示「当前值本身是数组」。
        self.deliver("root-array", b'[1,2]')
        self.deliver("nested-array", b'{"list":[1,2]}')
        self.sync()
        nested = ('{"any":{"path":["list"],"where":'
                  '{"eq":{"path":[],"value":2}}}}')
        self.assertEqual(self.ids(nested), ["nested-array"])
        self.assertEqual(self.ids('{"eq":{"path":[],"value":1}}'), [])
        self.assertEqual(self.ids('{"exists":{"path":[]}}'), self.direct_ids(
            '{"exists":{"path":[]}}'))

    def test_missing_and_type_mismatch_ordered_compare(self):
        for expression in ('{"lt":{"path":["missing"],"value":1}}',
                           '{"gt":{"path":["s"],"value":0}}',
                           '{"gte":{"path":["n"],"value":0}}'):
            self.assertEqual(self.ids(expression), [])

    def test_not_of_missing_becomes_true(self):
        self.assertEqual(self.ids('{"not":{"exists":{"path":["n"]}}}'),
                         ["n-dotted", "n-false", "n-missing", "n-one",
                          "n-one-float", "n-zero"])


class ExactNumberTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        self.deliver("huge-a", b'{"big":123456789012345678901234567891,'
                     b'"tiny":0.000000000000000000001}')
        self.deliver("huge-b", b'{"big":123456789012345678901234567890}')
        self.deliver("exp", b'{"v":1e400,"w":-1e400,"half":0.5}')
        self.sync()

    def test_adjacent_big_integers(self):
        self.assertEqual(self.ids('{"eq":{"path":["big"],"value":'
                                  '123456789012345678901234567891}}'),
                         ["huge-a"])
        self.assertEqual(self.ids('{"eq":{"path":["big"],"value":'
                                  '123456789012345678901234567890}}'),
                         ["huge-b"])

    def test_huge_exponent(self):
        self.assertEqual(self.ids('{"eq":{"path":["v"],"value":1e400}}'),
                         ["exp"])
        self.assertEqual(self.ids('{"gt":{"path":["v"],"value":1e399}}'),
                         ["exp"])
        self.assertEqual(self.ids('{"lt":{"path":["w"],"value":0}}'), ["exp"])

    def test_many_decimal_places(self):
        self.assertEqual(self.ids('{"gt":{"path":["tiny"],"value":0}}'),
                         ["huge-a"])
        self.assertEqual(self.ids('{"lt":{"path":["half"],"value":0.6}}'),
                         ["exp"])
        self.assertEqual(self.ids('{"eq":{"path":["half"],"value":0.5000}}'),
                         ["exp"])

    def test_spelling_independent_equality(self):
        self.deliver("spell", b'{"a":100,"b":0.1,"c":-0.0}')
        self.sync()
        for path, value in (("a", "1e2"), ("a", "100.000"), ("b", "1e-1"),
                            ("c", "0"), ("c", "-0")):
            self.assertEqual(
                self.ids(json.dumps({"eq": {"path": [path], "value":
                          __import__("json").loads(value)}})),
                ["spell"], (path, value))

    def test_negative_ordering(self):
        self.deliver("neg", b'{"v":-5}')
        self.deliver("zero", b'{"v":0}')
        self.sync()
        # exp 的 w=-1e400 也小于 -5
        self.assertEqual(self.ids('{"lt":{"path":["v"],"value":-5}}'), [])
        self.assertEqual(self.ids('{"lte":{"path":["v"],"value":-5}}'), ["neg"])
        self.assertEqual(self.ids('{"gt":{"path":["v"],"value":-5}}'),
                         ["exp", "zero"])
        self.assertEqual(self.ids('{"lt":{"path":["w"],"value":-5}}'), ["exp"])


class PartnerIsolationTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        self.deliver("acme-hit", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}')
        self.deliver("acme-miss", b'{"measurements":[{"metric":"humidity",'
                     b'"value":80}]}')
        self.deliver("acme-bad", b"not json")
        self.deliver("globex-hit", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}', partner="globex", key_version="g1",
                     secret="globex-secret")
        self.sync()

    def test_positive_isolation(self):
        self.assertEqual(self.ids(TEMP_GT_30, "acme"), ["acme-hit"])
        self.assertEqual(self.ids(TEMP_GT_30, "globex"), ["globex-hit"])

    def test_not_does_not_leak_or_revive_skipped(self):
        expression = ('{"not":{"any":{"path":["measurements"],"where":'
                      '{"eq":{"path":["metric"],"value":"temperature"}}}}}')
        self.assertEqual(self.ids(expression, "acme"), ["acme-miss"])
        self.assertEqual(self.ids(expression, "globex"), [])

    def test_partner_required(self):
        conn = connect_index(str(self.index), read_only=True)
        try:
            with self.assertRaises(QueryError):
                run_query(conn, partner_id="", expr=parse_expression_text(
                    '{"exists":{"path":[]}}'), limit=10, offset=0)
        finally:
            conn.close()


class PagingTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        for i in range(5):
            self.deliver(f"evt-{i}", json.dumps(
                {"measurements": [{"metric": "temperature", "value": 40}]}
            ).encode())
        self.sync()

    def test_total_and_page(self):
        first = self.run_expr('{"exists":{"path":["measurements"]}}', limit=2)
        self.assertEqual(first.total, 5)
        self.assertEqual([e["event_id"] for e in first.events],
                         ["evt-0", "evt-1"])
        second = self.run_expr('{"exists":{"path":["measurements"]}}',
                               limit=2, offset=2)
        self.assertEqual(second.total, 5)
        self.assertEqual([e["event_id"] for e in second.events],
                         ["evt-2", "evt-3"])
        last = self.run_expr('{"exists":{"path":["measurements"]}}',
                             limit=2, offset=4)
        self.assertEqual([e["event_id"] for e in last.events], ["evt-4"])

    def test_not_computed_before_paging(self):
        expression = ('{"not":{"any":{"path":["measurements"],"where":'
                      '{"gt":{"path":["value"],"value":50}}}}}')
        result = self.run_expr(expression, limit=2)
        self.assertEqual(result.total, 5)
        self.assertEqual(len(result.events), 2)

    def test_invalid_paging(self):
        for limit, offset in ((0, 0), (-1, 0), (10, -1)):
            conn = connect_index(str(self.index), read_only=True)
            try:
                with self.assertRaises(QueryError):
                    run_query(conn, partner_id="acme",
                              expr=parse_expression_text('{"exists":{"path":[]}}'),
                              limit=limit, offset=offset)
            finally:
                conn.close()


class SkippedBodyTests(IndexTestCase):
    def test_skipped_reasons(self):
        cases = {
            "text": (b"hello", "invalid_json"),
            "array-root": (b"[1,2]", None),
            "dup": (b'{"a":1,"a":2}', "duplicate_key"),
            "nan": (b'{"a":NaN}', "non_finite_number"),
            "truncated": (b'{"a":1', None),
            "utf8": (b'{"a":"\xff"}', "invalid_utf8"),
            "empty": (b"", None),
        }
        for event_id, (body, _) in cases.items():
            self.deliver(event_id, body)
        self.deliver("good", b'{"a":1}')
        report = self.sync()
        self.assertEqual(report.source_events, len(cases) + 1)
        self.assertEqual(report.indexed_events, 1)
        self.assertEqual(report.skipped_events, len(cases))
        status = index_status(str(self.index))
        reasons = {e["event_id"]: e["reason_code"] for e in status["skipped"]}
        self.assertEqual(reasons["dup"], "duplicate_key")
        self.assertEqual(reasons["nan"], "non_finite_number")
        self.assertEqual(reasons["utf8"], "invalid_utf8")
        for event_id, (_, expected) in cases.items():
            if expected:
                self.assertEqual(reasons[event_id], expected)
        # 跳过事件对所有查询都不可见（包括顶层 not）
        self.assertEqual(self.ids('{"not":{"exists":{"path":[]}}}'), [])
        self.assertEqual(self.ids('{"exists":{"path":["a"]}}'), ["good"])

    def test_missing_body_row(self):
        self.deliver("orphan", b'{"a":1}')
        conn = sqlite3.connect(str(self.source))
        conn.execute("DELETE FROM raw_bodies")
        conn.commit()
        conn.close()
        report = self.sync()
        self.assertEqual(report.skipped_events, 1)
        status = index_status(str(self.index))
        self.assertEqual(status["skipped"][0]["reason_code"], "missing_body")

    def test_registered_length_mismatch_skips(self):
        self.deliver("short", b'{"a":1}')
        self.deliver("ok", b'{"a":2}')
        conn = sqlite3.connect(str(self.source))
        conn.execute("UPDATE raw_bodies SET byte_length = byte_length + 5"
                     " WHERE body_sha256 = (SELECT body_sha256 FROM"
                     " accepted_events WHERE event_id = 'short')")
        conn.commit()
        conn.close()
        report = self.sync()
        self.assertEqual(report.indexed_events, 1)
        self.assertEqual(report.skipped_events, 1)
        self.assertEqual(report.skipped[0]["reason_code"], "length_mismatch")
        self.assertEqual(self.ids('{"exists":{"path":["a"]}}'), ["ok"])


class SyncSemanticsTests(IndexTestCase):
    def _modify_source(self, sql, params=()):
        conn = sqlite3.connect(str(self.source))
        conn.execute(sql, params)
        conn.commit()
        conn.close()

    def _swap_body(self, partner, event_id, body):
        digest = hashlib.sha256(body).hexdigest()
        conn = sqlite3.connect(str(self.source))
        conn.execute("INSERT OR IGNORE INTO raw_bodies VALUES (?,?,?,?)",
                     (digest, body, len(body), self.NOW))
        conn.execute("UPDATE accepted_events SET body_sha256 = ?"
                     " WHERE partner_id = ? AND event_id = ?",
                     (digest, partner, event_id))
        conn.commit()
        conn.close()

    def setUp(self):
        super().setUp()
        self.deliver("keep", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}')
        self.deliver("drop", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}')
        self.deliver("replace", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}')
        self.deliver("plain", b'{"a":1}')
        self.first = self.sync()
        self.assertEqual(self.ids(TEMP_GT_30), ["drop", "keep", "replace"])

    def test_add_replace_remove(self):
        self.deliver("added", b'{"measurements":[{"metric":"temperature",'
                     b'"value":36}]}')
        self._modify_source(
            "DELETE FROM accepted_events WHERE event_id IN ('drop')")
        self._swap_body("acme", "replace",
                        b'{"measurements":[{"metric":"temperature",'
                        b'"value":5}]}')
        report = self.sync()
        self.assertEqual(report.generation, self.first.generation + 1)
        self.assertIn("acme/added", report.added)
        self.assertIn("acme/drop", report.removed)
        self.assertIn("acme/replace", report.changed)
        self.assertEqual(report.unchanged, 2)
        self.assertEqual(sorted(self.ids(TEMP_GT_30)), ["added", "keep"])
        self.assertEqual(self.ids(TEMP_GT_30),
                         self.direct_ids(TEMP_GT_30))

    def test_replaced_body_becomes_skipped(self):
        self._swap_body("acme", "replace", b"broken")
        report = self.sync()
        self.assertEqual(report.indexed_events, 3)
        self.assertEqual(report.skipped_events, 1)
        self.assertEqual(self.ids(TEMP_GT_30), ["drop", "keep"])
        self.assertEqual(self.ids('{"exists":{"path":["a"]}}'), ["plain"])

    def test_repeat_sync_is_stable(self):
        report = self.sync()
        self.assertEqual(report.added, [])
        self.assertEqual(report.changed, [])
        self.assertEqual(report.removed, [])
        self.assertEqual(report.parsed_bodies, 0)
        first_status = index_status(str(self.index))
        again = self.sync()
        second_status = index_status(str(self.index))
        self.assertEqual(again.parsed_bodies, 0)
        self.assertEqual(second_status["node_rows"], first_status["node_rows"])
        self.assertEqual(second_status["indexed_events"],
                         first_status["indexed_events"])

    def test_shared_digest_not_cross_modified(self):
        same = b'{"measurements":[{"metric":"temperature","value":35}]}'
        self._swap_body("acme", "keep", same)
        self.sync()
        # 只替换 drop，keep 共享同一摘要不受影响
        self._swap_body("acme", "drop",
                        b'{"measurements":[{"metric":"temperature",'
                        b'"value":1}]}')
        report = self.sync()
        self.assertEqual(report.changed, ["acme/drop"])
        self.assertEqual(self.ids(TEMP_GT_30), ["keep", "replace"])

    def test_swap_away_and_back_reparses(self):
        original = b'{"measurements":[{"metric":"temperature","value":35}]}'
        self._swap_body("acme", "keep", b'{"x":1}')
        self.sync()
        self.assertNotIn("keep", self.ids(TEMP_GT_30))
        self._swap_body("acme", "keep", original)
        report = self.sync()
        self.assertIn("acme/keep", report.changed)
        self.assertIn("keep", self.ids(TEMP_GT_30))

    def test_source_identity_recorded(self):
        conn = sqlite3.connect(str(self.index))
        try:
            row = conn.execute(
                "SELECT source_identity FROM index_generations"
                " WHERE generation = ?", (self.first.generation,)).fetchone()
        finally:
            conn.close()
        self.assertEqual(len(row[0]), 64)

    def test_reader_sees_generation_atomically(self):
        """查询开始前发布的代，在整个查询事务内保持不变。"""
        conn = connect_index(str(self.index), read_only=True)
        try:
            register_functions(conn)
            expr = parse_expression_text(TEMP_GT_30)
            first = run_query(conn, partner_id="acme", expr=expr, limit=10,
                              offset=0)
            # 查询连接保持打开；另一个进程发布新一代也不改变已读快照。
            self.deliver("late", b'{"measurements":[{"metric":"temperature",'
                         b'"value":99}]}')
            self.sync()
            second = run_query(conn, partner_id="acme", expr=expr, limit=10,
                               offset=0)
            # 每次 run_query 自己开启只读事务，读到的是各自开始时的当前代。
            self.assertGreaterEqual(second.generation, first.generation)
            self.assertIn("late", [e["event_id"] for e in second.events])
        finally:
            conn.close()

    def test_publish_removes_old_generation_rows(self):
        self.deliver("late", b'{"measurements":[{"metric":"temperature",'
                     b'"value":99}]}')
        second = self.sync()
        conn = sqlite3.connect(str(self.index))
        try:
            generations = [r[0] for r in conn.execute(
                "SELECT generation FROM index_generations ORDER BY generation")]
            event_generations = {r[0] for r in conn.execute(
                "SELECT DISTINCT generation FROM events")}
        finally:
            conn.close()
        self.assertEqual(generations, [second.generation])
        self.assertEqual(event_generations, {second.generation})


class TransactionAndIsolationTests(IndexTestCase):
    def setUp(self):
        super().setUp()
        self.deliver("a", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}')
        self.sync()

    def test_query_does_not_need_source(self):
        before = self.run_expr(TEMP_GT_30)
        moved = self.source.with_suffix(".db.hidden")
        self.source.rename(moved)
        try:
            after = self.run_expr(TEMP_GT_30)
            self.assertEqual(after.total, before.total)
            self.assertEqual([e["event_id"] for e in after.events],
                             [e["event_id"] for e in before.events])
        finally:
            moved.rename(self.source)

    def test_source_opened_read_only(self):
        from partner_webhook.indexstore import connect_source_readonly
        conn = connect_source_readonly(str(self.source))
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM accepted_events")
        finally:
            conn.close()

    def test_sync_failure_rolls_back_generation(self):
        # 制造索引侧写入失败：预先放一个不兼容的 nodes 表会让同步抛错。
        before = index_status(str(self.index))
        conn = sqlite3.connect(str(self.index))
        conn.execute("ALTER TABLE nodes RENAME TO nodes_old")
        conn.execute("CREATE TABLE nodes (body_sha256 TEXT)")
        conn.commit()
        conn.close()
        with self.assertRaises(sqlite3.Error):
            self.sync()
        conn = sqlite3.connect(str(self.index))
        conn.execute("DROP TABLE nodes")
        conn.execute("ALTER TABLE nodes_old RENAME TO nodes")
        conn.commit()
        conn.close()
        after = index_status(str(self.index))
        self.assertEqual(after["generation"], before["generation"])
        self.assertEqual(self.ids(TEMP_GT_30), ["a"])

    def test_no_generation_yet(self):
        empty = self.dir / "empty-index.db"
        conn = connect_index(str(empty))
        try:
            from partner_webhook.indexstore import ensure_schema
            ensure_schema(conn)
        finally:
            conn.close()
        conn = connect_index(str(empty), read_only=True)
        try:
            with self.assertRaises(QueryError):
                run_query(conn, partner_id="acme",
                          expr=parse_expression_text('{"exists":{"path":[]}}'),
                          limit=10, offset=0)
        finally:
            conn.close()


class CliTests(IndexTestCase):
    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-I", str(REPO_ROOT / "partner_webhook" / "cli.py"),
             "--config", str(self.config_path), "--db", str(self.source), *args],
            capture_output=True, text=True,
        )

    def test_cli_flow_and_errors(self):
        self.deliver("evt", b'{"measurements":[{"metric":"temperature",'
                     b'"value":35}]}')
        sync_result = self.cli("index-sync", "--index-db", str(self.index))
        self.assertEqual(sync_result.returncode, 0, sync_result.stderr)
        self.assertEqual(json.loads(sync_result.stdout)["indexed_events"], 1)
        status = self.cli("index-status", "--index-db", str(self.index))
        self.assertEqual(status.returncode, 0, status.stderr)
        query = self.cli("index-query", "--index-db", str(self.index),
                         "--partner", "acme", "--expr", TEMP_GT_30)
        self.assertEqual(query.returncode, 0, query.stderr)
        payload = json.loads(query.stdout)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["events"][0]["event_id"], "evt")

        bad = self.cli("index-query", "--index-db", str(self.index),
                       "--partner", "acme", "--expr", '{"and":[]}')
        self.assertEqual(bad.returncode, 2)
        self.assertIn("不能为空", bad.stderr)
        self.assertEqual(bad.stdout, "")

        missing_partner = self.cli("index-query", "--index-db",
                                   str(self.index), "--expr", TEMP_GT_30)
        self.assertNotEqual(missing_partner.returncode, 0)

        missing_expr = self.cli("index-query", "--index-db", str(self.index),
                                "--partner", "acme")
        self.assertEqual(missing_expr.returncode, 2)

    def test_crash_flag_exits_without_publishing(self):
        self.deliver("evt", b'{"a":1}')
        self.cli("index-sync", "--index-db", str(self.index))
        before = json.loads(self.cli(
            "index-status", "--index-db", str(self.index)).stdout)
        crashed = self.cli("index-sync", "--index-db", str(self.index),
                           "--simulate-crash-after-nodes")
        self.assertEqual(crashed.returncode, 97)
        after = json.loads(self.cli(
            "index-status", "--index-db", str(self.index)).stdout)
        self.assertEqual(after["generation"], before["generation"])
        self.assertEqual(after["node_rows"], before["node_rows"])
        recovered = self.cli("index-sync", "--index-db", str(self.index))
        self.assertEqual(recovered.returncode, 0)
        self.assertEqual(json.loads(recovered.stdout)["generation"],
                         before["generation"] + 1)


if __name__ == "__main__":
    unittest.main()
