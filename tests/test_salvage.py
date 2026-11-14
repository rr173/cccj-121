"""离线接收库提取器（partner_webhook.salvage）测试。

造库使用标准 sqlite3 与现有服务（允许），提取路径本身不经过 SQL 引擎。
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import os
import shutil
import sqlite3
import unittest
from pathlib import Path

from partner_webhook import salvage
from tests.helpers import WebhookTestCase, b64

REPO_ROOT = Path(__file__).resolve().parent.parent
# 只建 0001 的表：抢救目标固定是这些表，后续迁移（投递表等）不参与。
MIGRATION_SQL = (REPO_ROOT / "migrations" / "0001_init.sql").read_text(
    encoding="utf-8")

ACME = {"id": "acme", "keys": [
    {"version": "v1", "secret_b64": b64("old-secret"),
     "not_before": None, "not_after": None},
]}


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def sha256_file(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SalvageCase(WebhookTestCase):
    """公共工具：按页长造库、独立 SQL 参照、文件破坏。"""

    def setUp(self):
        super().setUp()
        self.page_size = 512

    # ------------------------------------------------------------------ #
    def build_db(self, db_path=None, *, page_size=512, n_events=30,
                 deliveries=None):
        """用标准 sqlite3 定页长 + 仓库迁移建库，再走正常接收路径投递。"""
        db_path = db_path or self.db_path
        conn = sqlite3.connect(db_path)
        conn.execute(f"PRAGMA page_size={page_size}")
        conn.executescript(MIGRATION_SQL)
        conn.commit()
        conn.close()
        self.page_size = page_size
        self.write_config([ACME])
        service = self.make_service(db_path)
        for i in range(n_events):
            result = self.deliver(service, event_id=f"evt-{i:04d}",
                                  sequence=i + 1,
                                  body=json.dumps({"n": i}).encode())
            self.assertEqual("accepted", result.result)
        for kwargs in (deliveries or []):
            self.deliver(service, **kwargs)
        self.storage.close()
        self.checkpoint(db_path)
        return db_path

    def make_service(self, db_path=None):  # noqa: D102 - 允许指定库路径
        from partner_webhook.config import load_config
        from partner_webhook.service import WebhookService
        from partner_webhook.storage import Storage
        self.storage = Storage(db_path or self.db_path)
        return WebhookService(load_config(self.config_path), self.storage,
                              clock=self.clock)

    @staticmethod
    def checkpoint(db_path):
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        for suffix in ("-wal", "-journal"):
            side = str(db_path) + suffix
            if os.path.exists(side):
                assert os.path.getsize(side) == 0, f"旁文件未清空: {side}"

    # ------------------------------------------------------------------ #
    def extract(self, db_path, out_name="out", *extra):
        out_dir = self.dir / out_name
        argv = ["--db", str(db_path), "--out", str(out_dir), *extra]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = salvage.main(argv)
        return code, out_dir, stdout.getvalue(), stderr.getvalue()

    # ------------------------------------------------------------------ #
    def sql_reference(self, db_path):
        """独立参照：标准 SQL 查询结果。"""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        events = [dict(r) for r in conn.execute(
            "SELECT rowid AS _rowid, * FROM accepted_events ORDER BY rowid")]
        bodies = [dict(r) for r in conn.execute(
            "SELECT rowid AS _rowid, body_sha256, body_blob, byte_length,"
            " first_seen_at FROM raw_bodies ORDER BY rowid")]
        conn.close()
        for body in bodies:
            body["body_blob"] = bytes(body["body_blob"])
        return events, bodies

    def assert_full_match(self, db_path, out_dir):
        """提取结果与 SQL 参照逐字段一致；片段可独立拼回原字节。"""
        ref_events, ref_bodies = self.sql_reference(db_path)
        events = read_jsonl(out_dir / "events.jsonl")
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        confirmed = [e for e in events if e["status"] == "confirmed"]
        self.assertEqual(len(ref_events), len(confirmed),
                         "确认事件数应与参照一致")
        by_key = {(e["columns"]["partner_id"], e["columns"]["event_id"]): e
                  for e in confirmed}
        for ref in ref_events:
            got = by_key.get((ref["partner_id"], ref["event_id"]))
            self.assertIsNotNone(got, f"缺少事件 {ref['event_id']}")
            self.assertEqual(ref["_rowid"], got["rowid"])
            for col in salvage.TABLE_COLUMNS["accepted_events"]:
                self.assertEqual(ref[col], got["columns"][col],
                                 f"{ref['event_id']}.{col}")
            self.assertEqual("verified", got["body"]["state"])
        verified = {b["declared_sha256"]: b for b in bodies
                    if b["status"] == "verified"}
        with open(db_path, "rb") as image:
            for ref in ref_bodies:
                got = verified.get(ref["body_sha256"])
                self.assertIsNotNone(got, f"正文未验证 {ref['body_sha256'][:12]}")
                self.assertEqual(ref["_rowid"], got["rowid"])
                self.assertEqual(ref["byte_length"],
                                 got["declared_byte_length"])
                self.assertEqual(ref["first_seen_at"], got["first_seen_at"])
                data = (out_dir / got["file"]).read_bytes()
                self.assertEqual(ref["body_blob"], data)
                # 独立片段读取器：按 fragments 从源镜像拼回正文
                spliced = b"".join(
                    self._read_at(image, f["offset"], f["length"])
                    for f in got["fragments"])
                self.assertEqual(ref["body_blob"], spliced,
                                 "片段拼接应等于原始正文")
        return events, bodies

    @staticmethod
    def _read_at(fh, offset, length):
        fh.seek(offset)
        return fh.read(length)

    # ------------------------------------------------------------------ #
    @staticmethod
    def poke(path, offset, data: bytes):
        with open(path, "r+b") as fh:
            fh.seek(offset)
            fh.write(data)

    def page_offset(self, page_no):
        return (page_no - 1) * self.page_size

    def copy_db(self, name="copy.db"):
        target = self.dir / name
        shutil.copyfile(self.db_path, target)
        return str(target)


class HealthyExtractionTest(SalvageCase):
    """正常库：三种页长、各类正文、大 rowid、大整数、内部页分裂。"""

    def test_healthy_all_page_sizes(self):
        for page_size in (512, 4096, 65536):
            with self.subTest(page_size=page_size):
                db = self.dir / f"healthy-{page_size}.db"
                self.build_db(str(db), page_size=page_size,
                              n_events=60 if page_size == 512 else 20)
                before = sha256_file(db)
                code, out_dir, _stdout, _stderr = self.extract(
                    str(db), f"out-{page_size}")
                self.assertEqual(salvage.EXIT_OK, code)
                self.assert_full_match(str(db), out_dir)
                self.assertEqual(before, sha256_file(db),
                                 "提取不得修改源文件")

    def test_enough_rows_to_split_interior_pages(self):
        self.build_db(page_size=512, n_events=200)
        code, out_dir, _o, _e = self.extract(self.db_path)
        self.assertEqual(salvage.EXIT_OK, code)
        events, _bodies = self.assert_full_match(self.db_path, out_dir)
        self.assertEqual(200, len([e for e in events
                                   if e["status"] == "confirmed"]))
        leaf_pages = {e["leaf_page"] for e in events}
        self.assertGreater(len(leaf_pages), 5, "应分裂出多个叶页")

    def test_empty_zero_byte_and_non_utf8_bodies(self):
        self.build_db(n_events=0, deliveries=[
            {"event_id": "evt-empty", "sequence": 1, "body": b""},
            {"event_id": "evt-zeros", "sequence": 2, "body": b"\x00\x01\x00"},
            {"event_id": "evt-bin", "sequence": 3,
             "body": b"\xff\xfe\x00binary\x00"},
        ])
        code, out_dir, _o, _e = self.extract(self.db_path)
        self.assertEqual(salvage.EXIT_OK, code)
        _events, bodies = self.assert_full_match(self.db_path, out_dir)
        by_sha = {b["declared_sha256"]: b for b in bodies}
        empty = by_sha[hashlib.sha256(b"").hexdigest()]
        self.assertEqual(0, empty["computed_byte_length"])
        self.assertEqual([], empty["fragments"], "零长度正文没有文件片段")

    def test_multi_overflow_page_body(self):
        big = bytes(range(256)) * 30  # 7680 字节，512 页下跨十余张溢出页
        self.build_db(n_events=0, deliveries=[
            {"event_id": "evt-big", "sequence": 1, "body": big},
        ])
        code, out_dir, _o, _e = self.extract(self.db_path)
        self.assertEqual(salvage.EXIT_OK, code)
        _events, bodies = self.assert_full_match(self.db_path, out_dir)
        entry = bodies[0]
        self.assertGreater(len(entry["fragments"]), 10,
                           "大正文应跨多张溢出页")
        self.assertEqual((out_dir / entry["file"]).read_bytes(), big)

    def test_big_rowid_and_big_int_columns(self):
        self.build_db(n_events=1)
        body = b"big-rowid-body"
        sha = hashlib.sha256(body).hexdigest()
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO raw_bodies(rowid, body_sha256, body_blob,"
            " byte_length, first_seen_at) VALUES (?,?,?,?,?)",
            (1 << 61, sha, body, len(body), self.NOW))
        conn.execute(
            "INSERT INTO accepted_events(rowid, event_id, partner_id,"
            " source_seq, key_version, body_sha256, ingest_record_id,"
            " claimed_timestamp, accepted_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (1 << 60, "evt-huge", "acme", 1 << 50, "v1", sha, 1,
             1 << 40, self.NOW))
        conn.commit()
        conn.close()
        self.checkpoint(self.db_path)
        code, out_dir, _o, _e = self.extract(self.db_path)
        self.assertEqual(salvage.EXIT_OK, code)
        events, _bodies = self.assert_full_match(self.db_path, out_dir)
        huge = [e for e in events if e["columns"]["event_id"] == "evt-huge"]
        self.assertEqual(1, len(huge))
        self.assertEqual(1 << 60, huge[0]["rowid"])  # 9 字节 varint rowid
        self.assertEqual(1 << 50, huge[0]["columns"]["source_seq"])
        self.assertEqual(1 << 40, huge[0]["columns"]["claimed_timestamp"])

    def test_unassociated_bodies_kept_and_exit_ok(self):
        self.build_db(n_events=1, deliveries=[
            {"event_id": "evt-0000", "sequence": 1, "body": b'{"n": 0}'},
            {"event_id": "evt-0000", "sequence": 1, "body": b'{"n":999}'},
            {"event_id": "evt-bad", "sequence": 9, "body": b'{"bad":1}',
             "bad_signature": True},
        ])
        code, out_dir, _o, _e = self.extract(self.db_path)
        self.assertEqual(salvage.EXIT_OK, code)
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        unassociated = [b for b in bodies if b["unassociated"]]
        self.assertEqual(2, len(unassociated),
                         "冲突与拒收的正文应保留为未关联")
        self.assertTrue(all(b["verified"] for b in unassociated))
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(all(d["severity"] == "info" for d in diags))
        self.assertEqual({"unassociated_body"},
                         {d["code"] for d in diags})


class CorruptionTest(SalvageCase):
    """坏页隔离：坏的部分精确登记，邻近好数据不丢。"""

    def healthy_index(self, out_dir):
        events = read_jsonl(out_dir / "events.jsonl")
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        return events, bodies

    def test_corrupt_leaf_page_isolates_only_that_page(self):
        self.build_db(n_events=60)
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        events, _ = self.healthy_index(out_ok)
        # 选一个上面至少有 2 条事件的叶页
        by_leaf: dict[int, list] = {}
        for event in events:
            by_leaf.setdefault(event["leaf_page"], []).append(event)
        leaf = next(p for p, evs in by_leaf.items() if len(evs) >= 2)
        lost_ids = {e["columns"]["event_id"] for e in by_leaf[leaf]}
        damaged = self.copy_db("damaged.db")
        self.poke(damaged, self.page_offset(leaf), b"\x00" * 16)
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        after = read_jsonl(out_dir / "events.jsonl")
        confirmed_ids = {e["columns"]["event_id"] for e in after
                         if e["status"] == "confirmed"}
        self.assertTrue(lost_ids.isdisjoint(confirmed_ids),
                        "坏页上的事件不应再被确认")
        expected = {e["columns"]["event_id"] for e in events} - lost_ids
        self.assertEqual(expected, confirmed_ids, "邻近好数据不应一起丢失")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] in ("bad_page_type", "bad_page_header")
                            and d.get("page") == leaf for d in diags))

    def test_corrupt_single_cell_isolates_only_that_record(self):
        self.build_db(n_events=60)
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        events, _ = self.healthy_index(out_ok)
        target = next(e for e in events if e["leaf_page"] != 1)
        damaged = self.copy_db("damaged.db")
        ptr_off = (self.page_offset(target["leaf_page"])
                   + 8 + 2 * target["cell_index"])
        self.poke(damaged, ptr_off, b"\xff\xff")  # cell 指针指向界外
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        after = read_jsonl(out_dir / "events.jsonl")
        confirmed_ids = {e["columns"]["event_id"] for e in after
                         if e["status"] == "confirmed"}
        lost = target["columns"]["event_id"]
        self.assertNotIn(lost, confirmed_ids)
        neighbours = {e["columns"]["event_id"] for e in events
                      if e["leaf_page"] == target["leaf_page"]
                      and e["columns"]["event_id"] != lost}
        self.assertTrue(neighbours <= confirmed_ids,
                        "同叶页的其他记录不应被牵连")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "bad_cell_pointer"
                            and d.get("page") == target["leaf_page"]
                            for d in diags))

    def _big_body_entry(self, out_dir):
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        return next(b for b in bodies
                    if b["fragments"] and len(b["fragments"]) > 2)

    def test_overflow_chain_cut(self):
        big = bytes(range(256)) * 20
        self.build_db(n_events=5, deliveries=[
            {"event_id": "evt-big", "sequence": 100, "body": big}])
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        entry = self._big_body_entry(out_ok)
        first_overflow = entry["fragments"][1]["offset"] - 4  # 链指针在片段前
        damaged = self.copy_db("damaged.db")
        self.poke(damaged, first_overflow, (10 ** 9).to_bytes(4, "big"))
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        self.assertNotIn(entry["declared_sha256"],
                         {b["declared_sha256"] for b in bodies
                          if b["status"] == "verified"})
        events = read_jsonl(out_dir / "events.jsonl")
        big_event = next(e for e in events
                         if e["columns"]["event_id"] == "evt-big")
        self.assertEqual("missing", big_event["body"]["state"])
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "event_missing_body"
                            for d in diags))
        others = [b for b in bodies if b["status"] == "verified"]
        self.assertEqual(5, len(others), "其他正文不应受溢出链损坏影响")

    def test_overflow_cycle_terminates(self):
        big = bytes(range(256)) * 20
        self.build_db(n_events=0, deliveries=[
            {"event_id": "evt-big", "sequence": 1, "body": big}])
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        entry = self._big_body_entry(out_ok)
        first_page = entry["fragments"][1]["offset"] // self.page_size + 1
        damaged = self.copy_db("damaged.db")
        self.poke(damaged, self.page_offset(first_page),
                  first_page.to_bytes(4, "big"))  # 指向自身成环
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)  # 有界结束
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        self.assertFalse(any(b["status"] == "verified" for b in bodies),
                         "受影响正文不得列为已验证")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any("成环" in json.dumps(d, ensure_ascii=False)
                            for d in diags))

    def test_shared_page_conflict_quarantines_both_sides(self):
        big = bytes(range(256)) * 20
        self.build_db(n_events=30, deliveries=[
            {"event_id": "evt-big", "sequence": 100, "body": big}])
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        events, _ = self.healthy_index(out_ok)
        victim_leaf = events[10]["leaf_page"]
        victim_ids = {e["columns"]["event_id"] for e in events
                      if e["leaf_page"] == victim_leaf}
        entry = self._big_body_entry(out_ok)
        first_overflow = entry["fragments"][1]["offset"] - 4
        damaged = self.copy_db("damaged.db")
        # 溢出链指向 accepted_events 的叶页 -> 同一页被重复占用
        self.poke(damaged, first_overflow, victim_leaf.to_bytes(4, "big"))
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        after = read_jsonl(out_dir / "events.jsonl")
        quarantined = {e["columns"]["event_id"] for e in after
                       if e["status"] == "quarantined"}
        self.assertEqual(victim_ids, quarantined,
                         "被歧义占用影响的事件应全部隔离，"
                         "不能先输出第一条再把第二条报错")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "page_ownership_conflict"
                            and d.get("page") == victim_leaf for d in diags))
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        self.assertNotIn(entry["declared_sha256"],
                         {b["declared_sha256"] for b in bodies
                          if b["status"] == "verified"})

    def test_identity_conflict_quarantines_all_copies(self):
        self.build_db(n_events=60)
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        events, _ = self.healthy_index(out_ok)
        leaves = sorted({e["leaf_page"] for e in events})
        src, dst = leaves[0], leaves[1]
        duplicated = {e["columns"]["event_id"] for e in events
                      if e["leaf_page"] == src}
        with open(self.db_path, "rb") as fh:
            fh.seek(self.page_offset(src))
            page_bytes = fh.read(self.page_size)
        damaged = self.copy_db("damaged.db")
        self.poke(damaged, self.page_offset(dst), page_bytes)  # 叶页内容重复
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        after = read_jsonl(out_dir / "events.jsonl")
        conflicted = {e["columns"]["event_id"] for e in after
                      if e["status"] == "quarantined"}
        self.assertEqual(duplicated, conflicted,
                         "同一业务身份解码出多行，全部不得算已确认")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "event_identity_conflict"
                            for d in diags))

    def test_body_digest_mismatch_listed(self):
        self.build_db(n_events=5)
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        bodies = read_jsonl(out_ok / "bodies.jsonl")
        victim = next(b for b in bodies
                      if b["fragments"] and b["fragments"][0]["length"] >= 4)
        flip_at = victim["fragments"][0]["offset"] + 2
        damaged = self.copy_db("damaged.db")
        with open(damaged, "r+b") as fh:
            fh.seek(flip_at)
            original = fh.read(1)
            fh.seek(flip_at)
            fh.write(bytes([original[0] ^ 0xFF]))
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        after = read_jsonl(out_dir / "bodies.jsonl")
        entry = next(b for b in after if b["rowid"] == victim["rowid"])
        self.assertEqual("digest_mismatch", entry["status"])
        self.assertFalse(entry["verified"])
        events = read_jsonl(out_dir / "events.jsonl")
        linked = [e for e in events
                  if e["body"].get("declared_sha256")
                  == victim["declared_sha256"]]
        self.assertTrue(linked)
        self.assertTrue(all(e["body"]["state"] == "digest_mismatch"
                            for e in linked))
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "body_digest_mismatch"
                            for d in diags))
        # 未验证正文保留在 quarantine，不覆盖同名文件
        self.assertTrue(entry["file"].startswith("bodies/quarantine/"))

    def test_event_missing_body_listed(self):
        self.build_db(n_events=3)
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO accepted_events(event_id, partner_id, source_seq,"
            " key_version, body_sha256, ingest_record_id, claimed_timestamp,"
            " accepted_at) VALUES (?,?,?,?,?,?,?,?)",
            ("evt-ghost", "acme", 99, "v1", "ab" * 32, 1, self.NOW, self.NOW))
        conn.commit()
        conn.close()
        self.checkpoint(self.db_path)
        code, out_dir, _o, _e = self.extract(self.db_path)
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        events = read_jsonl(out_dir / "events.jsonl")
        ghost = next(e for e in events
                     if e["columns"]["event_id"] == "evt-ghost")
        self.assertEqual("missing", ghost["body"]["state"])
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "event_missing_body"
                            for d in diags))

    def test_truncated_file_partial_exit(self):
        self.build_db(n_events=60)
        size = os.path.getsize(self.db_path)
        keep_pages = (size // self.page_size) // 2
        damaged = self.copy_db("truncated.db")
        with open(damaged, "r+b") as fh:
            fh.truncate(keep_pages * self.page_size)
        code, out_dir, _o, _e = self.extract(damaged, "out-truncated")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        events = read_jsonl(out_dir / "events.jsonl")
        self.assertTrue(any(e["status"] == "confirmed" for e in events),
                        "截短后仍应交付可达部分")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        codes = {d["code"] for d in diags}
        self.assertTrue(codes & {"page_out_of_bounds", "db_size_mismatch",
                                 "child_out_of_bounds"})


class RejectionTest(SalvageCase):
    """整体拒绝（退出码 1）与资源上限（退出码 2）。"""

    def test_catalog_corruption_rejects(self):
        self.build_db(n_events=5)
        damaged = self.copy_db("catalog.db")
        self.poke(damaged, 100, b"\x00")  # 第 1 页类型字节
        code, out_dir, _o, stderr = self.extract(damaged)
        self.assertEqual(salvage.EXIT_REJECTED, code)
        self.assertIn("提取被拒绝", stderr)
        self.assertFalse(out_dir.exists(), "整体拒绝不应产生输出目录")

    def test_layout_mismatch_rejects(self):
        self.build_db(n_events=5)
        damaged = self.copy_db("layout.db")
        data = Path(damaged).read_bytes()
        # 目录中 accepted_events 的建表语句（可能跨溢出页，列定义行是连续的）
        col_at = data.index(b"event_id           TEXT NOT NULL")
        self.poke(damaged, col_at, b"event_XX")
        code, out_dir, _o, stderr = self.extract(damaged)
        self.assertEqual(salvage.EXIT_REJECTED, code)
        self.assertIn("布局不符", stderr)
        self.assertFalse(out_dir.exists())

    def test_non_empty_wal_sidefile_rejects(self):
        self.build_db(n_events=2)
        for suffix in ("-wal", "-journal"):
            with self.subTest(suffix=suffix):
                side = self.db_path + suffix
                Path(side).write_bytes(b"\x01" * 32)
                try:
                    code, out_dir, _o, stderr = self.extract(self.db_path)
                    self.assertEqual(salvage.EXIT_REJECTED, code)
                    self.assertIn("旁文件", stderr)
                    self.assertFalse(out_dir.exists())
                finally:
                    os.unlink(side)

    def test_empty_wal_sidefile_is_accepted(self):
        self.build_db(n_events=2)
        side = self.db_path + "-wal"
        Path(side).write_bytes(b"")
        try:
            code, _out, _o, _e = self.extract(self.db_path)
            self.assertEqual(salvage.EXIT_OK, code)
        finally:
            os.unlink(side)

    def test_output_dir_exists_rejects(self):
        self.build_db(n_events=2)
        (self.dir / "out").mkdir()
        code, _out, _o, stderr = self.extract(self.db_path, "out")
        self.assertEqual(salvage.EXIT_REJECTED, code)
        self.assertIn("拒绝覆盖", stderr)

    def test_bad_magic_rejects(self):
        damaged = self.dir / "notadb.db"
        damaged.write_bytes(b"not a sqlite file" + b"\x00" * 200)
        code, _out, _o, stderr = self.extract(str(damaged))
        self.assertEqual(salvage.EXIT_REJECTED, code)
        self.assertIn("魔数", stderr)

    def test_page_limit_partial(self):
        # 4096 页下目录占 1 页，上限在数据树遍历中触发 -> 部分结果（退出码 2）
        self.build_db(page_size=4096, n_events=60)
        code, out_dir, _o, _e = self.extract(self.db_path, "out",
                                             "--max-pages", "4")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        summary = json.loads((out_dir / "summary.json").read_text(
            encoding="utf-8"))
        self.assertIn("page_limit", summary["unfinished_reasons"])
        self.assertEqual(2, summary["exit_code"])

    def test_payload_limit_partial(self):
        big = bytes(range(256)) * 20
        self.build_db(n_events=3, deliveries=[
            {"event_id": "evt-big", "sequence": 100, "body": big}])
        code, out_dir, _o, _e = self.extract(
            self.db_path, "out", "--max-payload-bytes", "1024")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        summary = json.loads((out_dir / "summary.json").read_text(
            encoding="utf-8"))
        self.assertIn("payload_limit", summary["unfinished_reasons"])
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertTrue(any(d["code"] == "payload_exceeds_limit"
                            for d in diags))
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        self.assertEqual(3, len([b for b in bodies
                                 if b["status"] == "verified"]),
                         "小正文不受单条上限影响")

    def test_diagnostics_limit_partial(self):
        self.build_db(n_events=60)
        code, out_ok, _o, _e = self.extract(self.db_path, "out-ok")
        self.assertEqual(salvage.EXIT_OK, code)
        events = read_jsonl(out_ok / "events.jsonl")
        leaves = sorted({e["leaf_page"] for e in events})
        damaged = self.copy_db("damaged.db")
        for leaf in leaves[:5]:  # 制造多页损坏，诊断条数超过上限
            self.poke(damaged, self.page_offset(leaf), b"\x00" * 16)
        code, out_dir, _o, _e = self.extract(damaged, "out-damaged",
                                             "--max-diagnostics", "3")
        self.assertEqual(salvage.EXIT_PARTIAL, code)
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        self.assertLessEqual(len(diags), 4)
        self.assertEqual("diagnostics_limit_reached", diags[-1]["code"])
        summary = json.loads((out_dir / "summary.json").read_text(
            encoding="utf-8"))
        self.assertIn("diagnostics_limit", summary["unfinished_reasons"])
        self.assertGreater(summary["counts"]["diagnostics_dropped"], 0)


class ModuleBoundaryTest(unittest.TestCase):
    """提取路径不得借助 SQLite 库解码源文件。"""

    def test_salvage_module_does_not_import_sqlite3(self):
        source = (REPO_ROOT / "partner_webhook" / "salvage.py").read_text(
            encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertNotIn("sqlite3",
                                 [a.name for a in node.names])
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual("sqlite3", node.module)


class VarintTest(unittest.TestCase):
    """varint 基础行为（含 9 字节形式）。"""

    def test_nine_byte_varint(self):
        raw = b"\xff" * 8 + b"\xff"
        value, pos = salvage.read_varint(raw, 0, len(raw))
        self.assertEqual((1 << 64) - 1, value)
        self.assertEqual(9, pos)
        self.assertEqual(-1, salvage.as_signed64(value))

    def test_varint_boundary(self):
        with self.assertRaises(salvage.ParseError):
            salvage.read_varint(b"\x80", 0, 1)  # continuation 后无字节

    def test_local_payload_rule_matches_sqlite(self):
        # SQLite 表叶规则：maxLocal=U-35，minLocal=(U-12)*32/255-23
        for usable in (512, 4096, 65536):
            max_local = usable - 35
            min_local = (usable - 12) * 32 // 255 - 23
            self.assertGreater(max_local, min_local)
            self.assertGreaterEqual(min_local, 0)


if __name__ == "__main__":
    unittest.main()
