"""设备档案加工管线与 RFC 6901/6902 引擎的自动化测试。

覆盖：
* JSON Pointer 解码（空键、~0/~1、未知转义、对象数字键 vs 数组下标、01/负数）；
* 六种 patch 操作、原子回滚、move 删除后定位、copy 独立树、test 精确比较；
* 根 remove 的 MISSING 状态与根 add 重新建档（区别于内容为 null）；
* 信封校验：缺失/多余/重复键/类型错误/布尔冒充整数，全部不强制转型；
* 乱序等待、分支退回、人工选择/撤销、两个 seed 冲突、失败阻断后续；
* 合作方隔离、重复同步无操作、重开进程状态仍在、未提交崩溃恢复。
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from partner_webhook.docarchive import (
    ArchiveError,
    DISP_ADOPTED,
    DISP_BLOCKED,
    DISP_BRANCH_UNRESOLVED,
    DISP_INVALID,
    DISP_NON_ARCHIVE,
    DISP_NOT_SELECTED,
    DISP_OP_FAILED,
    DISP_WAITING,
    ExactNumber,
    connect_archive,
    deselect_revision,
    dumps_exact,
    dumps_plain,
    ensure_schema,
    get_current_document,
    list_dispositions,
    list_revisions,
    select_revision,
    sync_archive,
    validate_envelope,
)
from partner_webhook.jsonpatch import (
    MISSING,
    UNBORN,
    PatchError,
    apply_patch,
    deep_copy,
    json_equal,
    parse_pointer,
)
from partner_webhook.strictjson import (
    JsonBodyError,
    JsonObject,
    RawNumber,
    parse_strict_json,
)


def parse(text: str):
    return parse_strict_json(text.encode("utf-8"))


def op(text: str):
    """把单个 JSON Patch 操作文本解析为普通 dict。"""
    value = parse(text)
    return dict(value.values)


# --------------------------------------------------------------------- #
# JSON Pointer
# --------------------------------------------------------------------- #
class PointerTests(unittest.TestCase):
    def test_root_and_escapes(self):
        self.assertEqual(parse_pointer(""), ())
        self.assertEqual(parse_pointer("/a/b"), ("a", "b"))
        self.assertEqual(parse_pointer("/a~1b"), ("a/b",))
        self.assertEqual(parse_pointer("/a~0b"), ("a~b",))
        self.assertEqual(parse_pointer("/~01"), ("~1",))
        self.assertEqual(parse_pointer("/~10"), ("/0",))
        self.assertEqual(parse_pointer("/"), ("",))
        self.assertEqual(parse_pointer("//"), ("", ""))

    def test_unknown_escape_rejected(self):
        for text in ("/a~2b", "/~", "/a~x"):
            with self.assertRaises(ValueError):
                parse_pointer(text)

    def test_non_string_rejected(self):
        with self.assertRaises(ValueError):
            parse_pointer(12)
        with self.assertRaises(ValueError):
            parse_pointer("/a".encode())

    def test_must_start_with_slash(self):
        with self.assertRaises(ValueError):
            parse_pointer("a/b")


# --------------------------------------------------------------------- #
# JSON Patch 六操作与精确语义
# --------------------------------------------------------------------- #
class PatchEngineTests(unittest.TestCase):
    def test_empty_key_and_numeric_object_key(self):
        doc = parse('{"":{"k":1},"0":"string-key","arr":[10,20]}')
        out = apply_patch(doc, [
            op('{"op":"replace","path":"//k","value":2}'),
            op('{"op":"replace","path":"/0","value":"x"}'),
            op('{"op":"replace","path":"/arr/1","value":200}'),
        ])
        self.assertEqual(out[""]["k"], RawNumber("2"))
        self.assertEqual(out["0"], "x")
        self.assertEqual(out["arr"][1], RawNumber("200"))
        # 原对象未被就地修改
        self.assertEqual(doc.values[""].values["k"], RawNumber("1"))

    def test_pointer_with_slash_key(self):
        doc = parse('{"a/b":1,"c~d":2}')
        out = apply_patch(doc, [
            op('{"op":"test","path":"/a~1b","value":1}'),
            op('{"op":"replace","path":"/c~0d","value":9}'),
        ])
        self.assertEqual(out["c~d"], RawNumber("9"))

    def test_array_index_canonical_only(self):
        doc = parse('{"arr":[1,2,3]}')
        for bad in ("/arr/01", "/arr/-1", "/arr/3"):
            with self.assertRaises(PatchError) as ctx:
                apply_patch(doc, [{"op": "remove", "path": bad}])
            self.assertIn(ctx.exception.code, ("bad_index", "target_missing"))
        # "-" 不能读取
        with self.assertRaises(PatchError):
            apply_patch(doc, [{"op": "test", "path": "/arr/-", "value": 1}])
        # "-" 可以 add 到末尾
        out = apply_patch(doc, [{"op": "add", "path": "/arr/-", "value": 4}])
        self.assertEqual(len(out["arr"]), 4)

    def test_add_parent_must_exist_and_insert_semantics(self):
        doc = parse('{"arr":[1,2]}')
        with self.assertRaises(PatchError):
            apply_patch(doc, [{"op": "add", "path": "/missing/x", "value": 1}])
        out = apply_patch(doc, [{"op": "add", "path": "/arr/2", "value": 9}])
        self.assertEqual([n.text for n in out["arr"]], ["1", "2", "9"])
        out2 = apply_patch(doc, [{"op": "add", "path": "/arr/0", "value": 0}])
        self.assertEqual([n.text for n in out2["arr"]], ["0", "1", "2"])
        # add 替换已有对象成员
        out3 = apply_patch(parse('{"a":1}'),
                           [{"op": "add", "path": "/a", "value": 2}])
        self.assertEqual(out3["a"], RawNumber("2"))

    def test_replace_remove_require_target(self):
        doc = parse('{"a":1}')
        with self.assertRaises(PatchError):
            apply_patch(doc, [{"op": "replace", "path": "/b", "value": 1}])
        with self.assertRaises(PatchError):
            apply_patch(doc, [{"op": "remove", "path": "/b"}])

    def test_move_forward_and_backward_same_array(self):
        doc = parse('{"a":[0,1,2,3]}')
        back = apply_patch(doc, [{"op": "move", "from": "/a/3", "path": "/a/1"}])
        self.assertEqual([n.text for n in back["a"]], ["0", "3", "1", "2"])
        forward = apply_patch(doc, [{"op": "move", "from": "/a/0", "path": "/a/3"}])
        self.assertEqual([n.text for n in forward["a"]], ["1", "2", "3", "0"])

    def test_move_uses_post_removal_position(self):
        # 删除 /a/1 后数组长度变 3，插入下标 2 合法且指向新位置。
        doc = parse('{"a":[0,1,2],"b":{}}')
        out = apply_patch(doc, [
            {"op": "move", "from": "/a/1", "path": "/b/x"},
        ])
        self.assertEqual([n.text for n in out["a"]], ["0", "2"])
        self.assertEqual(out["b"]["x"], RawNumber("1"))

    def test_move_into_descendant_rejected(self):
        doc = parse('{"a":{"b":1}}')
        with self.assertRaises(PatchError) as ctx:
            apply_patch(doc, [{"op": "move", "from": "/a", "path": "/a/b"}])
        self.assertEqual(ctx.exception.code, "move_into_descendant")

    def test_copy_is_independent_tree(self):
        doc = parse('{"src":{"n":[1,2]}}')
        out = apply_patch(doc, [
            {"op": "copy", "from": "/src", "path": "/dst"},
            {"op": "add", "path": "/dst/n/-", "value": 3},
            {"op": "replace", "path": "/dst/n/0", "value": 99},
        ])
        self.assertEqual([n.text for n in out["src"]["n"]], ["1", "2"])
        self.assertEqual([n.text for n in out["dst"]["n"]], ["99", "2", "3"])

    def test_test_equality_rules(self):
        doc = parse('{"n":1,"b":true,"s":"1","o":{"a":1,"b":2},"arr":[1,2]}')
        good = [
            ("/n", parse("1.0")),
            ("/o", parse('{"b":2,"a":1}')),       # 对象成员顺序无关
            ("/arr", parse("[1,2]")),
        ]
        for pointer, value in good:
            # 不抛异常即 test 成立
            apply_patch(doc, [{"op": "test", "path": pointer,
                               "value": _plain(value)}])
        # 布尔 != 数字、字符串 != 数字、数组顺序有关
        self.assertFalse(json_equal(doc.values["b"], RawNumber("1")))
        self.assertFalse(json_equal(doc.values["s"], RawNumber("1")))
        self.assertFalse(json_equal(doc.values["arr"], parse("[2,1]")))
        # test 失败抛错并指出位置
        with self.assertRaises(PatchError) as ctx:
            apply_patch(doc, [{"op": "test", "path": "/n", "value": 2}])
        self.assertEqual(ctx.exception.code, "test_failed")
        self.assertEqual(ctx.exception.pointer, "/n")

    def test_huge_integer_test_exact(self):
        doc = parse('{"big":123456789012345678901234567891}')
        same = parse("123456789012345678901234567891.0")
        neighbor = parse("123456789012345678901234567890")
        self.assertTrue(json_equal(doc.values["big"], same))
        self.assertFalse(json_equal(doc.values["big"], neighbor))

    def test_atomic_rollback_keeps_original(self):
        doc = parse('{"a":1,"arr":[1,2]}')
        original = deep_copy(doc)
        with self.assertRaises(PatchError) as ctx:
            apply_patch(doc, [
                {"op": "replace", "path": "/a", "value": 9},
                {"op": "add", "path": "/arr/-", "value": 3},
                {"op": "test", "path": "/a", "value": 1},   # 必失败
            ])
        self.assertEqual(ctx.exception.op_number(), 3)
        # 调用方手里的原档案一个字节都没变
        self.assertTrue(json_equal(doc, original))

    def test_root_remove_then_root_add(self):
        doc = parse('{"a":1}')
        gone = apply_patch(doc, [{"op": "remove", "path": ""}])
        self.assertIs(gone, MISSING)
        with self.assertRaises(PatchError):
            # 档案不存在时 replace 不能建档
            apply_patch(gone, [{"op": "replace", "path": "", "value": 1}])
        reborn = apply_patch(gone, [
            {"op": "add", "path": "", "value": {"x": 1}},
        ])
        self.assertEqual(reborn, {"x": RawNumber("1")})

    def test_missing_differs_from_null(self):
        null_doc = parse('null')
        self.assertIsNot(null_doc, MISSING)
        # 内容为 null 时仍可正常 replace 根
        out = apply_patch(null_doc, [{"op": "replace", "path": "", "value": 1}])
        self.assertEqual(out, RawNumber("1"))


def _plain(value):
    if isinstance(value, JsonObject):
        return {k: _plain(v) for k, v in value.values.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _strict(value):
    """把手写操作里的普通 Python 数字归一化为精确数字模型（不经过 float）。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return RawNumber(str(value))
    if isinstance(value, float):
        return RawNumber(repr(value))
    if isinstance(value, dict):
        return {k: _strict(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strict(v) for v in value]
    return value


def num(text: str) -> RawNumber:
    return RawNumber(text)


# --------------------------------------------------------------------- #
# 信封校验
# --------------------------------------------------------------------- #
class EnvelopeTests(unittest.TestCase):
    def check_invalid(self, text: str):
        result = validate_envelope(parse(text))
        self.assertEqual(result.code, DISP_INVALID, text)
        return result

    def check_non_archive(self, text: str):
        result = validate_envelope(parse(text))
        self.assertEqual(result.code, DISP_NON_ARCHIVE, text)

    def test_seed_ok_any_document_value(self):
        for document in ("1", '"x"', "null", "true", "[1,2]", '{"k":1}'):
            parsed = validate_envelope(
                parse(f'{{"kind":"seed","document_id":"d","revision":0,'
                      f'"document":{document}}}'))
            self.assertEqual(parsed.kind, "seed")

    def test_patch_ok(self):
        parsed = validate_envelope(parse(
            '{"kind":"patch","document_id":"d","base_revision":3,'
            '"revision":4,"operations":[{"op":"remove","path":"/a"}]}'))
        self.assertEqual(parsed.revision, 4)
        self.assertEqual(parsed.base_revision, 3)

    def test_missing_and_extra_fields(self):
        self.check_invalid('{"kind":"seed","revision":0,"document":1}')
        self.check_invalid('{"kind":"seed","document_id":"d","revision":0,'
                           '"document":1,"extra":2}')
        self.check_invalid('{"kind":"patch","document_id":"d","base_revision":0,'
                           '"revision":1,"operations":[],"extra":2}')

    def test_type_errors_no_coercion(self):
        self.check_invalid('{"kind":"seed","document_id":7,"revision":0,'
                           '"document":1}')
        self.check_invalid('{"kind":"seed","document_id":"d","revision":true,'
                           '"document":1}')
        self.check_invalid('{"kind":"seed","document_id":"d","revision":"0",'
                           '"document":1}')
        self.check_invalid('{"kind":"seed","document_id":"d","revision":1.0,'
                           '"document":1}')
        self.check_invalid('{"kind":"patch","document_id":"d",'
                           '"base_revision":false,"revision":1,"operations":[]}')
        self.check_invalid('{"kind":"patch","document_id":"d","base_revision":0,'
                           '"revision":2,"operations":[]}')
        self.check_invalid('{"kind":"patch","document_id":"d","base_revision":0,'
                           '"revision":1,"operations":{}}')

    def test_seed_revision_must_be_zero(self):
        self.check_invalid('{"kind":"seed","document_id":"d","revision":1,'
                           '"document":1}')

    def test_duplicate_key_rejected_upstream(self):
        with self.assertRaises(JsonBodyError) as ctx:
            parse('{"kind":"seed","kind":"patch","document_id":"d",'
                  '"revision":0,"document":1}')
        self.assertEqual(ctx.exception.code, "duplicate_key")

    def test_unknown_kind_is_non_archive(self):
        self.check_non_archive('{"kind":"heartbeat","document_id":"d"}')
        self.check_non_archive('[1,2,3]')
        self.check_non_archive('"just a string"')

    def test_operation_field_rules(self):
        base = ('{"kind":"patch","document_id":"d","base_revision":0,'
                '"revision":1,"operations":[%s]}')
        self.check_invalid(base % '{"op":"frob","path":"/a"}')
        self.check_invalid(base % '{"op":"add","path":"/a"}')
        self.check_invalid(base % '{"op":"remove","path":"/a","value":1}')
        self.check_invalid(base % '{"op":"move","path":"/a"}')
        self.check_invalid(base % '{"op":"move","from":"/a","path":"/b","x":1}')
        self.check_invalid(base % '{"op":"test","path":"/a~2b","value":1}')
        self.check_invalid(base % '["not","an","object"]')


# --------------------------------------------------------------------- #
# 加工库：需要一个能直接插 accepted_events/raw_bodies 的源库
# --------------------------------------------------------------------- #
class ArchiveDbTestCase(unittest.TestCase):
    SCHEMA = """
    CREATE TABLE raw_bodies (
        body_sha256 TEXT PRIMARY KEY, body_blob BLOB NOT NULL,
        byte_length INTEGER NOT NULL, first_seen_at INTEGER NOT NULL);
    CREATE TABLE accepted_events (
        event_id TEXT NOT NULL, partner_id TEXT NOT NULL, source_seq INTEGER NOT NULL,
        key_version TEXT NOT NULL, body_sha256 TEXT NOT NULL,
        ingest_record_id INTEGER NOT NULL, claimed_timestamp INTEGER NOT NULL,
        accepted_at INTEGER NOT NULL, PRIMARY KEY (partner_id, event_id));
    CREATE TABLE outbox (id INTEGER PRIMARY KEY);
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.source_db = str(self.dir / "source.db")
        self.archive_db = str(self.dir / "archive.db")
        conn = sqlite3.connect(self.source_db)
        conn.executescript(self.SCHEMA)
        conn.commit()
        conn.close()
        self._seq = 0

    def tearDown(self):
        self.tmp.cleanup()

    def deliver(self, partner: str, event_id: str, body: str | bytes):
        """模拟签名接收库已接受一条事件（源表由接收流程写入，这里直接造数）。"""
        import hashlib

        blob = body.encode("utf-8") if isinstance(body, str) else body
        digest = hashlib.sha256(blob).hexdigest()
        self._seq += 1
        conn = sqlite3.connect(self.source_db)
        conn.execute("INSERT OR IGNORE INTO raw_bodies VALUES (?,?,?,?)",
                     (digest, blob, len(blob), 1000))
        conn.execute(
            "INSERT INTO accepted_events (event_id, partner_id, source_seq,"
            " key_version, body_sha256, ingest_record_id, claimed_timestamp,"
            " accepted_at) VALUES (?,?,?,?,?,?,?,?)",
            (event_id, partner, self._seq, "v1", digest, self._seq, 1000, 1000))
        conn.commit()
        conn.close()

    def sync(self):
        return sync_archive(source_db=self.source_db,
                            archive_db=self.archive_db)

    def seed(self, partner="acme", doc="dev-1", event_id=None, document='{"v":0}'):
        event_id = event_id or f"seed-{partner}-{doc}"
        self.deliver(partner, event_id,
                     f'{{"kind":"seed","document_id":"{doc}","revision":0,'
                     f'"document":{document}}}')
        return event_id

    def patch(self, rev_pair, operations, partner="acme", doc="dev-1",
              event_id=None):
        base, revision = rev_pair
        event_id = event_id or f"patch-{partner}-{doc}-{revision}"
        ops = json.dumps(operations, ensure_ascii=False)
        self.deliver(partner, event_id,
                     f'{{"kind":"patch","document_id":"{doc}",'
                     f'"base_revision":{base},"revision":{revision},'
                     f'"operations":{ops}}}')
        return event_id

    def disposition_map(self, partner="acme", doc="dev-1"):
        return {row["event_id"]: row for row in
                list_dispositions(self.archive_db, partner, doc)}

    def current(self, partner="acme", doc="dev-1"):
        return get_current_document(self.archive_db, partner, doc)


class SyncBasicTests(ArchiveDbTestCase):
    def test_seed_then_patch_chain(self):
        self.seed()
        self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 1}])
        report = self.sync()
        self.assertEqual(report.imported, 2)
        self.assertEqual(report.adopted, 2)
        current = self.current()
        self.assertEqual(current["state"], "present")
        self.assertEqual(current["current_revision"], 1)
        self.assertEqual(current["document"]["v"], ExactNumber("1"))
        self.assertEqual([c["event_id"] for c in current["chain"]][0],
                         "seed-acme-dev-1")

    def test_non_archive_and_invalid_recorded_with_event_identity(self):
        self.deliver("acme", "hb", '{"kind":"heartbeat"}')
        self.deliver("acme", "bad", '{"kind":"seed","document_id":"d",'
                                    '"revision":true,"document":1}')
        self.deliver("acme", "dup", '{"a":1,"a":2}')
        report = self.sync()
        self.assertEqual(report.non_archive, 1)   # heartbeat
        self.assertEqual(report.invalid, 2)       # 类型错误 + 重复键
        rows = {r["event_id"]: r for r in list_dispositions(self.archive_db)}
        self.assertEqual(rows["hb"]["disposition"], DISP_NON_ARCHIVE)
        self.assertEqual(rows["bad"]["disposition"], DISP_INVALID)
        self.assertEqual(rows["dup"]["disposition"], DISP_INVALID)
        self.assertIn("revision", rows["bad"]["reason"])
        self.assertTrue(rows["hb"]["body_preview"])

    def test_outbox_untouched_and_source_readonly(self):
        self.seed()
        self.sync()
        conn = sqlite3.connect(self.source_db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)
        # 源库没有任何加工侧对象
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("archive_events", names)
        conn.close()

    def test_repeat_sync_is_noop(self):
        self.seed()
        first = self.sync()
        self.assertEqual(first.imported, 1)
        second = self.sync()
        self.assertEqual(second.imported, 0)
        self.assertEqual(second.source_events, 1)
        conn = connect_archive(self.archive_db, read_only=True)
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM archive_events").fetchone()[0], 1)
        conn.close()


class OrderingAndBranchTests(ArchiveDbTestCase):
    def test_out_of_order_waits_then_resolves(self):
        # 修订 2 先到、seed 最后到
        self.patch((1, 2), [{"op": "replace", "path": "/v", "value": 2}],
                   event_id="p2")
        self.sync()
        rows = self.disposition_map()
        self.assertEqual(rows["p2"]["disposition"], DISP_WAITING)
        self.assertIsNone(self.current()["current_revision"])

        self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 1}],
                   event_id="p1")
        self.sync()
        rows = self.disposition_map()
        self.assertEqual(rows["p1"]["disposition"], DISP_WAITING)  # 仍缺 seed
        self.assertEqual(rows["p2"]["disposition"], DISP_WAITING)

        self.seed(event_id="s0")
        self.sync()
        rows = self.disposition_map()
        self.assertEqual(rows["s0"]["disposition"], DISP_ADOPTED)
        self.assertEqual(rows["p1"]["disposition"], DISP_ADOPTED)
        self.assertEqual(rows["p2"]["disposition"], DISP_ADOPTED)
        self.assertEqual(self.current()["current_revision"], 2)
        self.assertEqual(self.current()["document"]["v"], ExactNumber("2"))

    def test_branch_rolls_back_publication_then_selection_restores(self):
        self.seed(event_id="s0")
        id_a = self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 1}],
                          event_id="evt-A")
        id_b = self.patch((1, 2), [{"op": "replace", "path": "/v", "value": 2}],
                          event_id="evt-B")
        self.sync()
        self.assertEqual(self.current()["current_revision"], 2)

        # 后来另一条 0→1 的 C：公布必须退回第 0 版
        id_c = self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 11}],
                          event_id="evt-C")
        self.sync()
        current = self.current()
        self.assertEqual(current["current_revision"], 0)
        rows = self.disposition_map()
        self.assertEqual(rows[id_a]["disposition"], DISP_BRANCH_UNRESOLVED)
        self.assertEqual(rows[id_c]["disposition"], DISP_BRANCH_UNRESOLVED)
        # B 仍在账上，但被含糊的第 1 版挡在后面
        self.assertEqual(rows[id_b]["disposition"], DISP_BLOCKED)

        # 人工选择 A：恢复到第 2 版
        result = select_revision(archive_db=self.archive_db, partner_id="acme",
                                 document_id="dev-1", revision=1,
                                 event_id=id_a)
        self.assertEqual(result["current_revision"], 2)
        rows = self.disposition_map()
        self.assertEqual(rows[id_a]["disposition"], DISP_ADOPTED)
        self.assertEqual(rows[id_c]["disposition"], DISP_NOT_SELECTED)
        self.assertEqual(rows[id_b]["disposition"], DISP_ADOPTED)

        # 撤销选择：再次退回第 0 版
        deselect_revision(archive_db=self.archive_db, partner_id="acme",
                          document_id="dev-1", revision=1)
        self.assertEqual(self.current()["current_revision"], 0)
        rows = self.disposition_map()
        self.assertEqual(rows[id_a]["disposition"], DISP_BRANCH_UNRESOLVED)
        self.assertEqual(rows[id_b]["disposition"], DISP_BLOCKED)

    def test_select_other_partner_same_id_rejected(self):
        self.seed(partner="acme", event_id="acme-s")
        self.seed(partner="globex", doc="dev-1", event_id="globex-s")
        self.sync()
        # globex 同号档案的事件不能被 acme 坐标选择
        with self.assertRaises(ArchiveError):
            select_revision(archive_db=self.archive_db, partner_id="acme",
                            document_id="dev-1", revision=0,
                            event_id="globex-s")
        # 不存在的事件同样拒绝且不改状态
        with self.assertRaises(ArchiveError):
            select_revision(archive_db=self.archive_db, partner_id="acme",
                            document_id="dev-1", revision=0, event_id="ghost")
        revisions = list_revisions(self.archive_db, "acme", "dev-1")
        self.assertEqual(revisions["selections"], {})

    def test_two_seeds_conflict_publishes_nothing(self):
        self.seed(event_id="seed-one", document='{"v":1}')
        self.seed(event_id="seed-two", document='{"v":2}')
        self.sync()
        current = self.current()
        self.assertIsNone(current["current_revision"])
        rows = self.disposition_map()
        self.assertTrue(all(r["disposition"] == DISP_BRANCH_UNRESOLVED
                            for r in rows.values()))
        # 选择其中一个 seed 后才公布
        select_revision(archive_db=self.archive_db, partner_id="acme",
                        document_id="dev-1", revision=0, event_id="seed-one")
        current = self.current()
        self.assertEqual(current["current_revision"], 0)
        self.assertEqual(current["document"]["v"], ExactNumber("1"))
        rows = self.disposition_map()
        self.assertEqual(rows["seed-two"]["disposition"], DISP_NOT_SELECTED)

    def test_failed_revision_blocks_successors(self):
        self.seed()
        self.patch((0, 1),
                   [{"op": "replace", "path": "/missing", "value": 1}],
                   event_id="bad-p1")
        self.patch((1, 2), [{"op": "replace", "path": "/v", "value": 2}],
                   event_id="p2")
        self.sync()
        rows = self.disposition_map()
        self.assertEqual(rows["bad-p1"]["disposition"], DISP_OP_FAILED)
        self.assertEqual(rows["bad-p1"]["failed_op"], 1)
        self.assertEqual(rows["bad-p1"]["failed_pointer"], "/missing")
        self.assertEqual(rows["p2"]["disposition"], DISP_BLOCKED)
        self.assertEqual(self.current()["current_revision"], 0)

    def test_failed_patch_is_atomic_and_kept_for_audit(self):
        self.seed(document='{"a":1,"arr":[1]}')
        self.patch((0, 1), [
            {"op": "replace", "path": "/a", "value": 9},
            {"op": "test", "path": "/a", "value": 1},
        ], event_id="atomic")
        self.sync()
        rows = self.disposition_map()
        self.assertEqual(rows["atomic"]["disposition"], DISP_OP_FAILED)
        self.assertEqual(rows["atomic"]["failed_op"], 2)
        # 当前档案仍是 seed 原样，前一个 replace 没有留下
        self.assertEqual(self.current()["document"]["a"], ExactNumber("1"))
        # 原事件仍在加工库可查
        conn = connect_archive(self.archive_db, read_only=True)
        self.assertIsNotNone(conn.execute(
            "SELECT 1 FROM archive_events WHERE event_id='atomic'").fetchone())
        conn.close()

    def test_partner_isolation_same_document_id(self):
        self.seed(partner="acme", doc="same", event_id="a-s",
                  document='{"owner":"acme"}')
        self.seed(partner="globex", doc="same", event_id="g-s",
                  document='{"owner":"globex"}')
        self.patch((0, 1), [{"op": "replace", "path": "/owner",
                             "value": "acme-1"}],
                   partner="acme", doc="same", event_id="a-p")
        self.sync()
        acme = get_current_document(self.archive_db, "acme", "same")
        globex = get_current_document(self.archive_db, "globex", "same")
        self.assertEqual(acme["document"]["owner"], "acme-1")
        self.assertEqual(globex["document"]["owner"], "globex")


class RootStateTests(ArchiveDbTestCase):
    def test_root_remove_and_recreate(self):
        self.seed(document='{"a":1}')
        self.patch((0, 1), [{"op": "remove", "path": ""}], event_id="rm")
        self.sync()
        current = self.current()
        self.assertEqual(current["state"], "absent")
        self.assertEqual(current["current_revision"], 1)
        self.assertIsNone(current["document"])
        # 只有根 add 能重新建档
        self.patch((1, 2), [{"op": "add", "path": "",
                             "value": {"reborn": True}}], event_id="reborn")
        self.sync()
        current = self.current()
        self.assertEqual(current["state"], "present")
        self.assertEqual(current["current_revision"], 2)
        self.assertEqual(current["document"], {"reborn": True})

    def test_null_document_distinct_from_absent(self):
        self.seed(document="null")
        self.sync()
        current = self.current()
        self.assertEqual(current["state"], "present")
        self.assertIsNone(current["document"])
        self.assertEqual(current["current_revision"], 0)


class PersistenceTests(ArchiveDbTestCase):
    def test_reopen_keeps_waiting_selections_and_results(self):
        self.patch((0, 1), [{"op": "add", "path": "/x", "value": 1}],
                   event_id="p1")
        self.sync()
        self.seed(event_id="s0")
        self.sync()
        # 重开进程：等待项转采用、内容仍在
        report = sync_archive(source_db=self.source_db,
                              archive_db=self.archive_db)
        self.assertEqual(report.imported, 0)
        current = self.current()
        self.assertEqual(current["current_revision"], 1)
        # 选择也持久
        self.patch((1, 2), [{"op": "replace", "path": "/v", "value": 2}],
                   event_id="b1")
        self.patch((1, 2), [{"op": "replace", "path": "/v", "value": 3}],
                   event_id="b2")
        self.sync()
        select_revision(archive_db=self.archive_db, partner_id="acme",
                        document_id="dev-1", revision=2, event_id="b2")
        reopened = get_current_document(self.archive_db, "acme", "dev-1")
        self.assertEqual(reopened["document"]["v"], ExactNumber("3"))
        selections = list_revisions(self.archive_db, "acme", "dev-1")["selections"]
        self.assertEqual(selections, {2: "b2"})

    def test_crash_before_commit_keeps_old_result(self):
        self.seed(event_id="s0")
        self.sync()
        self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 1}],
                   event_id="p1")
        # 写入新档案后、提交前强制退出
        import subprocess
        import sys

        helper = (
            "import sys; sys.path.insert(0, %r);"
            "from partner_webhook.docarchive import sync_archive;"
            "sync_archive(source_db=%r, archive_db=%r,"
            " simulate_crash_before_commit=True)"
            % (str(Path(__file__).resolve().parent.parent),
               self.source_db, self.archive_db)
        )
        proc = subprocess.run([sys.executable, "-I", "-c", helper],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 97, proc.stderr)
        # 重开仍是旧结果（第 0 版），p1 未登记
        current = self.current()
        self.assertEqual(current["current_revision"], 0)
        rows = self.disposition_map()
        self.assertNotIn("p1", rows)
        # 重新同步即可继续
        self.sync()
        self.assertEqual(self.current()["current_revision"], 1)

    def test_new_branch_respects_existing_selection_keeps_diagnostics(self):
        self.seed(event_id="s0")
        self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 1}],
                   event_id="a1")
        self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 9}],
                   event_id="c1")
        self.sync()
        select_revision(archive_db=self.archive_db, partner_id="acme",
                        document_id="dev-1", revision=1, event_id="a1")
        self.assertEqual(self.current()["current_revision"], 1)
        # 已明确选择后又来一条同修订分支
        self.patch((0, 1), [{"op": "replace", "path": "/v", "value": 7}],
                   event_id="d1")
        self.sync()
        self.assertEqual(self.current()["current_revision"], 1)
        self.assertEqual(self.current()["document"]["v"], ExactNumber("1"))
        rows = self.disposition_map()
        self.assertEqual(rows["d1"]["disposition"], DISP_NOT_SELECTED)
        self.assertEqual(rows["c1"]["disposition"], DISP_NOT_SELECTED)


class SerializationTests(unittest.TestCase):
    def test_dumps_exact_keeps_number_text(self):
        value = {"big": RawNumber("123456789012345678901234567891"),
                 "nested": [RawNumber("1.0"), True, None, "x"]}
        text = dumps_exact(value)
        self.assertIn("123456789012345678901234567891", text)
        self.assertIn("1.0", text)
        # 回读仍是精确数字
        parsed = parse(text)
        self.assertEqual(parsed.values["big"],
                         RawNumber("123456789012345678901234567891"))

    def test_dumps_plain_exact_marker(self):
        text = dumps_plain({"n": ExactNumber("1e400"), "s": "x"})
        self.assertIn('"n": 1e400', text)
        self.assertIn('"s": "x"', text)


if __name__ == "__main__":
    unittest.main()
