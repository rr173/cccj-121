"""可验证追加账本的自动化测试（协议、持久节点、证明、离线核验）。"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from partner_webhook import merkle
from partner_webhook.eventlog import (
    LedgerError, ReadTrace, install, log_status, prove_consistency,
    prove_inclusion, read_checkpoint,
)
from partner_webhook.verifylog import (
    VerificationFailure, verify_consistency, verify_inclusion,
)

from .helpers import WebhookTestCase, b64

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = {
    "max_skew_seconds": 300,
    "partners": [
        {"id": "acme", "max_skew_seconds": 300, "keys": [
            {"version": "v1", "secret_b64": b64("acme-secret"),
             "not_before": None, "not_after": None}]},
        {"id": "globex", "max_skew_seconds": 300, "keys": [
            {"version": "g1", "secret_b64": b64("globex-secret"),
             "not_before": None, "not_after": None}]},
    ],
}


def ref_leaf(partner, event_id, seq, body):
    """独立的叶编码（不调用 merkle.leaf_hash）。"""
    def lp(text):
        raw = text.encode("utf-8")
        return len(raw).to_bytes(4, "big") + raw
    material = (b"PWLOG1" + lp(partner) + lp(event_id)
                + int(seq).to_bytes(8, "big")
                + hashlib.sha256(body).digest())
    return hashlib.sha256(b"\x00" + material).digest()


def ref_root(hashes):
    if not hashes:
        return hashlib.sha256(b"").digest()
    if len(hashes) == 1:
        return hashes[0]
    k = 1 << (len(hashes).bit_length() - 1)
    if k == len(hashes):
        k //= 2
    return hashlib.sha256(b"\x01" + ref_root(hashes[:k])
                          + ref_root(hashes[k:])).digest()


class MerkleProtocolTests(unittest.TestCase):
    def test_leaf_preimage_length_prefixes(self):
        digest = bytes(range(32))
        preimage = merkle.leaf_preimage("ab", "cd", 0x0102030405060708,
                                        digest)
        expected = (b"PWLOG1" + b"\x00\x00\x00\x02ab"
                    + b"\x00\x00\x00\x02cd"
                    + b"\x01\x02\x03\x04\x05\x06\x07\x08" + digest)
        self.assertEqual(preimage, expected)
        self.assertEqual(merkle.leaf_hash("ab", "cd", 0x0102030405060708,
                                          digest),
                         hashlib.sha256(b"\x00" + expected).digest())

    def test_no_unicode_normalization_and_no_delimiter_join(self):
        # 两个字段的拼接不得与「单字段内含分隔符」混淆
        a = merkle.leaf_preimage("a", "b|c", 1, b"\x00" * 32)
        b = merkle.leaf_preimage("a|b", "c", 1, b"\x00" * 32)
        self.assertNotEqual(a, b)
        # NFC/NFD 不同，编码必须不同
        composed = merkle.leaf_preimage("é", "e", 1, b"\x00" * 32)
        decomposed = merkle.leaf_preimage("é", "e", 1, b"\x00" * 32)
        self.assertNotEqual(composed, decomposed)

    def test_encoding_range_rejected(self):
        with self.assertRaises(merkle.MerkleError) as ctx:
            merkle.leaf_hash("acme", "e", -1, b"\x00" * 32)
        self.assertEqual(ctx.exception.code, "integer_out_of_range")
        with self.assertRaises(merkle.MerkleError) as ctx:
            merkle.leaf_hash("acme", "e", 1 << 64, b"\x00" * 32)
        self.assertEqual(ctx.exception.code, "integer_out_of_range")
        with self.assertRaises(merkle.MerkleError):
            merkle.leaf_hash("acme", "e", True, b"\x00" * 32)
        with self.assertRaises(merkle.MerkleError):
            merkle.leaf_preimage("acme", "e", 1, "zz" * 32)

    def test_split_size_for_arbitrary_tree_lengths(self):
        self.assertEqual(merkle.split_size(2), 1)
        self.assertEqual(merkle.split_size(3), 2)
        self.assertEqual(merkle.split_size(4), 2)
        self.assertEqual(merkle.split_size(5), 4)
        self.assertEqual(merkle.split_size(8), 4)
        self.assertEqual(merkle.split_size(9), 8)
        for size in range(2, 200):
            k = merkle.split_size(size)
            self.assertLess(k, size)
            self.assertGreaterEqual(k * 2, size)
            self.assertEqual(k & (k - 1), 0)

    def test_root_and_paths_match_reference_for_0_to_40(self):
        leaves = [merkle.leaf_hash("p", f"e{i}", i, bytes([i]) * 32)
                  for i in range(40)]
        for size in range(41):
            self.assertEqual(merkle.root_from_leaves(leaves[:size]),
                             ref_root(leaves[:size]))
            for index in range(size):
                path = merkle.inclusion_path_from_leaves(leaves[:size], index)
                self.assertEqual(
                    merkle.build_inclusion_root(leaves[index], index, size,
                                                path),
                    ref_root(leaves[:size]))
            for m in range(size + 1):
                path = merkle.consistency_path_from_leaves(leaves[:size], m)
                old = ref_root(leaves[:m]) if m else merkle.empty_root()
                new = ref_root(leaves[:size])
                check = merkle.reconstruct_consistency(old, new, m, size,
                                                       path)
                self.assertEqual((check.old_root, check.new_root), (old, new))

    def test_no_dummy_leaves_for_non_power_of_two(self):
        # 5 叶：前 4 叶的完美子树 + 单叶，不复制第 5 叶配对。
        leaves = [merkle.leaf_hash("p", f"e{i}", i, b"\x00" * 32)
                  for i in range(5)]
        expected = merkle.node_hash(
            merkle.root_from_leaves(leaves[:4]), leaves[4])
        self.assertEqual(merkle.root_from_leaves(leaves), expected)

    def test_consistency_zero_and_equal_sizes(self):
        leaf = merkle.leaf_hash("p", "e", 1, b"\x00" * 32)
        result = merkle.reconstruct_consistency(merkle.empty_root(), leaf,
                                                0, 1, [])
        self.assertEqual(result.new_root, leaf)
        with self.assertRaises(merkle.MerkleError) as ctx:
            merkle.reconstruct_consistency(merkle.empty_root(), leaf, 0, 1,
                                           [leaf])
        self.assertEqual(ctx.exception.code, "path_not_empty")
        result = merkle.reconstruct_consistency(leaf, leaf, 1, 1, [])
        self.assertEqual(result.old_root, leaf)
        with self.assertRaises(merkle.MerkleError) as ctx:
            merkle.reconstruct_consistency(leaf, b"\x01" * 32, 1, 1, [])
        self.assertEqual(ctx.exception.code, "root_mismatch")

    def test_boolean_is_not_an_integer(self):
        with self.assertRaises(merkle.MerkleError) as ctx:
            merkle.reconstruct_consistency(b"\x00" * 32, b"\x00" * 32,
                                           True, 1, [])
        self.assertEqual(ctx.exception.code, "bad_integer")
        with self.assertRaises(merkle.MerkleError):
            merkle.parse_checkpoint({
                "format": merkle.CHECKPOINT_FORMAT, "version": 1,
                "protocol": merkle.PROTOCOL, "log_id": "x",
                "partner_id": "acme", "tree_size": True,
                "root_hash": "0" * 64,
            })

    def test_checkpoint_parser_rejects_extra_and_missing_fields(self):
        doc = merkle.Checkpoint("log", "acme", 3, b"\x02" * 32).as_dict()
        merkle.parse_checkpoint(doc)
        for mutated in ({**doc, "extra": 1}, {k: v for k, v in doc.items()
                                              if k != "root_hash"}):
            with self.assertRaises(merkle.MerkleError):
                merkle.parse_checkpoint(mutated)


class LedgerTestCase(WebhookTestCase):
    NOW = 2_000_000_000

    def setUp(self):
        super().setUp()
        self.write_config(CONFIG["partners"])
        self.service = self.make_service()

    def deliver_body(self, event_id, sequence, body, partner="acme",
                     key_version="v1", secret="acme-secret"):
        result = self.deliver(self.service, partner=partner,
                              key_version=key_version, secret=secret,
                              event_id=event_id, sequence=sequence, body=body)
        self.assertEqual(result.result, "accepted", result)
        self.bodies[event_id] = body
        self.sequences[event_id] = sequence
        return result

    def deliver_acme(self, event_id, sequence, body, **kwargs):
        kwargs.setdefault("partner", "acme")
        kwargs.setdefault("key_version", "v1")
        kwargs.setdefault("secret", "acme-secret")
        return self.deliver(self.service, event_id=event_id, sequence=sequence,
                            body=body, **kwargs)

    def setUpLedger(self) -> None:
        self.bodies = {}
        self.sequences = {}

    def install(self, partner="acme"):
        return install(db_path=self.db_path, partner_id=partner)


class InstallTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()

    def test_install_includes_existing_events_in_ingest_order(self):
        self.deliver_body("b", 30, b'{"x":1}')
        self.deliver_body("a", 10, b'{"x":2}')
        self.deliver_body("c", 20, b'{"x":3}')
        report = self.install()
        self.assertEqual(report["tree_size"], 3)
        self.assertFalse(report["already_installed"])
        rows = self.storage.iter_all(
            "SELECT event_id FROM log_leaves ORDER BY leaf_index")
        self.assertEqual([r[0] for r in rows], ["b", "a", "c"])
        leaves = [ref_leaf("acme", e, self.sequences[e], self.bodies[e])
                  for e in ("b", "a", "c")]
        self.assertEqual(bytes.fromhex(report["root_hash"]), ref_root(leaves))

    def test_reinstall_keeps_log_id_and_order(self):
        self.deliver_body("a", 1, b"{}")
        first = self.install()
        second = self.install()
        self.assertEqual(first["log_id"], second["log_id"])
        self.assertEqual(first["root_hash"], second["root_hash"])
        self.assertTrue(second["already_installed"])
        self.assertEqual(second["tree_size"], 1)
        # 再次安装后继续收件仍从叶 1 开始
        self.deliver_body("b", 2, b'{"b":1}')
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], 2)

    def test_install_rejects_missing_or_mismatched_body(self):
        self.deliver_body("a", 1, b'{"a":1}')
        digest = hashlib.sha256(b'{"a":1}').hexdigest()
        import sqlite3
        raw = sqlite3.connect(self.db_path)  # 默认不启用外键，模拟正文行缺失
        raw.execute("DELETE FROM raw_bodies WHERE body_sha256 = ?", (digest,))
        raw.commit()
        raw.close()
        with self.assertRaises(LedgerError) as ctx:
            self.install()
        self.assertEqual(ctx.exception.code, "body_missing")
        self.assertEqual(log_status(self.db_path)["logs"], [])

    def test_install_is_per_partner(self):
        self.deliver_body("a", 1, b"{}", partner="acme")
        acme = self.install("acme")
        self.assertEqual(acme["tree_size"], 1)
        globex = self.install("globex")
        self.assertEqual(globex["tree_size"], 0)
        self.assertNotEqual(acme["log_id"], globex["log_id"])

    def test_install_does_not_change_business_tables(self):
        self.deliver_body("a", 1, b'{"a":1}')
        before = self.storage.iter_all(
            "SELECT event_id, partner_id, source_seq, body_sha256,"
            " ingest_record_id, claimed_timestamp, accepted_at"
            " FROM accepted_events")
        outbox_before = self.storage.iter_all(
            "SELECT id, partner_id, event_id, source_seq, body_sha256, status"
            " FROM outbox")
        self.install()
        after = self.storage.iter_all(
            "SELECT event_id, partner_id, source_seq, body_sha256,"
            " ingest_record_id, claimed_timestamp, accepted_at"
            " FROM accepted_events")
        self.assertEqual([tuple(r) for r in before], [tuple(r) for r in after])
        outbox_after = self.storage.iter_all(
            "SELECT id, partner_id, event_id, source_seq, body_sha256, status"
            " FROM outbox")
        self.assertEqual([tuple(r) for r in outbox_before],
                         [tuple(r) for r in outbox_after])


class AppendMessageTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()

    def test_leaves_grow_contiguously_regardless_of_source_seq(self):
        for index, seq in enumerate([9, 2, 40, 0, 7]):
            self.deliver_body(f"e{index}", seq, json.dumps({"i": index}).encode())
        rows = self.storage.iter_all(
            "SELECT leaf_index, source_seq FROM log_leaves ORDER BY leaf_index")
        self.assertEqual([tuple(r) for r in rows],
                         [(0, 9), (1, 2), (2, 40), (3, 0), (4, 7)])

    def test_duplicate_conflict_rejected_do_not_append(self):
        self.deliver_body("a", 1, b'{"a":1}')
        size = log_status(self.db_path, "acme")["tree_size"]
        duplicate = self.deliver_acme("a", 1, b'{"a":1}')
        self.assertEqual(duplicate.result, "duplicate")
        conflict = self.deliver_acme("a", 1, b'{"a":2}')
        self.assertEqual(conflict.result, "conflict")
        rejected = self.deliver_acme("b", 2, b'{"b":1}', bad_signature=True)
        self.assertEqual(rejected.result, "rejected")
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], size)

    def test_same_source_seq_different_events_both_appended(self):
        self.deliver_body("a", 77, b'{"a":1}')
        self.deliver_body("b", 77, b'{"b":1}')
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], 2)

    def test_binary_body_and_shared_body(self):
        binary = bytes(range(256)) + b"\x00\xff\xfe"
        self.deliver_body("bin", 1, binary)
        self.deliver_body("s1", 2, b'{"same":1}')
        self.deliver_body("s2", 3, b'{"same":1}')
        checkpoint = read_checkpoint(self.db_path, "acme")
        for event_id in ("bin", "s1", "s2"):
            proof = prove_inclusion(self.db_path, "acme", checkpoint, event_id)
            verify_inclusion(checkpoint.as_dict(), proof.as_dict(),
                             partner_id="acme", event_id=event_id,
                             source_seq=self.sequences[event_id],
                             body_sha256=hashlib.sha256(
                                 self.bodies[event_id]).hexdigest())

    def test_append_updates_root_and_is_verifiable(self):
        hashes = []
        for index in range(9):
            body = json.dumps({"i": index}).encode()
            self.deliver_body(f"e{index}", index, body)
            hashes.append(ref_leaf("acme", f"e{index}", index, body))
            checkpoint = read_checkpoint(self.db_path, "acme")
            self.assertEqual(checkpoint.root_hash, ref_root(hashes))
        for index in range(9):
            proof = prove_inclusion(self.db_path, "acme", checkpoint,
                                    f"e{index}")
            verify_inclusion(checkpoint.as_dict(), proof.as_dict(),
                             partner_id="acme", event_id=f"e{index}",
                             source_seq=index,
                             body_sha256=hashlib.sha256(
                                 self.bodies[f"e{index}"]).hexdigest())


class ProofTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()
        self.checkpoints = {}
        for index in range(1, 10):
            body = json.dumps({"i": index}).encode()
            self.deliver_body(f"e{index:02d}", index * 3, body)
            self.checkpoints[index] = read_checkpoint(self.db_path, "acme")

    def test_checkpoint_fields_and_stability(self):
        checkpoint = self.checkpoints[3]
        self.assertEqual(checkpoint.tree_size, 3)
        self.assertEqual(checkpoint.partner_id, "acme")
        self.assertEqual(checkpoint.protocol, merkle.PROTOCOL)
        self.assertEqual(len(checkpoint.log_id), 32)
        # 旧检查点不因新收件改变
        self.assertEqual(self.checkpoints[3].as_dict()["tree_size"], 3)
        current = read_checkpoint(self.db_path, "acme")
        self.assertEqual(current.tree_size, 9)
        self.assertNotEqual(current.root_hash, checkpoint.root_hash)

    def test_inclusion_for_every_position_and_prefix(self):
        for size in range(1, 10):
            checkpoint = self.checkpoints[size]
            for index in range(size):
                event_id = f"e{index + 1:02d}"
                proof = prove_inclusion(self.db_path, "acme", checkpoint,
                                        event_id)
                self.assertEqual(proof.leaf_index, index)
                payload = verify_inclusion(
                    checkpoint.as_dict(), proof.as_dict(), partner_id="acme",
                    event_id=event_id, source_seq=self.sequences[event_id],
                    body_sha256=hashlib.sha256(
                        self.bodies[event_id]).hexdigest())
                self.assertTrue(payload["ok"])

    def test_inclusion_errors(self):
        checkpoint = self.checkpoints[5]
        with self.assertRaises(LedgerError) as ctx:
            prove_inclusion(self.db_path, "acme", checkpoint, "missing")
        self.assertEqual(ctx.exception.code, "event_not_in_log")
        with self.assertRaises(LedgerError) as ctx:
            prove_inclusion(self.db_path, "acme", checkpoint, "e09")
        self.assertEqual(ctx.exception.code, "not_in_prefix")
        with self.assertRaises(LedgerError) as ctx:
            prove_inclusion(
                self.db_path, "acme",
                merkle.Checkpoint(checkpoint.log_id, "acme", 99, b"\x00" * 32),
                "e01")
        self.assertEqual(ctx.exception.code, "size_out_of_range")

    def test_consistency_for_all_pairs_0_to_9(self):
        empty = merkle.Checkpoint(self.checkpoints[1].log_id, "acme", 0,
                                  merkle.empty_root())
        for m in range(10):
            for n in range(m, 10):
                old = empty if m == 0 else self.checkpoints[m]
                new = empty if n == 0 else self.checkpoints[n]
                proof = prove_consistency(self.db_path, "acme", old, new)
                payload = verify_consistency(old.as_dict(), new.as_dict(),
                                              proof.as_dict())
                self.assertEqual(payload["appended_leaves"], n - m)
                # 路径与独立参考实现一致
                leaves = [ref_leaf("acme", f"e{i:02d}", self.sequences[
                    f"e{i:02d}"], self.bodies[f"e{i:02d}"])
                    for i in range(1, n + 1)]
                self.assertEqual(
                    [node.hex() for node in proof.path],
                    [node.hex() for node in _ref_consistency(leaves, m)])

    def test_consistency_rejects_regression_and_wrong_checkpoints(self):
        old = self.checkpoints[7]
        new = self.checkpoints[3]
        with self.assertRaises(LedgerError) as ctx:
            prove_consistency(self.db_path, "acme", old, new)
        self.assertEqual(ctx.exception.code, "size_regression")
        with self.assertRaises(LedgerError) as ctx:
            prove_consistency(
                self.db_path, "acme", old,
                merkle.Checkpoint(old.log_id, "acme", 9, b"\x09" * 32))
        self.assertEqual(ctx.exception.code, "checkpoint_root_mismatch")


def _ref_consistency(leaves, m):
    """C(m, D, b) 的直接递归（b 表示当前段是否完整树）。"""
    if m < 0 or m > len(leaves):
        raise ValueError("旧叶数越界")
    if m == 0 or m == len(leaves):
        return []

    def build(m_old, segment, at_boundary):
        if m_old == len(segment):
            return [] if at_boundary else [ref_root(segment)]
        k = 1 << (len(segment).bit_length() - 1)
        if k == len(segment):
            k //= 2
        if m_old <= k:
            return build(m_old, segment[:k], at_boundary) + \
                [ref_root(segment[k:])]
        return build(m_old - k, segment[k:], False) + \
            [ref_root(segment[:k])]

    return build(m, leaves, True)


class VerifyTamperTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()
        for index in range(1, 10):
            body = json.dumps({"i": index}).encode()
            self.deliver_body(f"e{index:02d}", index, body)
        self.checkpoint = read_checkpoint(self.db_path, "acme")
        self.proof = prove_inclusion(self.db_path, "acme", self.checkpoint,
                                     "e05").as_dict()
        self.event_id = "e05"
        self.body = self.bodies["e05"]

    def verify(self, proof, checkpoint=None, partner="acme", event_id=None):
        checkpoint = checkpoint or self.checkpoint
        event_id = event_id or self.event_id
        return verify_inclusion(
            checkpoint.as_dict(), proof, partner_id=partner,
            event_id=event_id, source_seq=self.sequences[event_id],
            body_sha256=hashlib.sha256(self.bodies[event_id]).hexdigest())

    def test_wrong_leaf(self):
        with self.assertRaises(VerificationFailure):
            self.verify({**self.proof, "event_id": "e06"}, event_id="e06")

    def test_wrong_position(self):
        with self.assertRaises(VerificationFailure):
            self.verify({**self.proof, "leaf_index": 6})

    def test_modified_extra_missing_path_nodes(self):
        path = list(self.proof["path"])
        for mutated in (
            {**self.proof, "path": ["f" * 64] + path[1:]},
            {**self.proof, "path": path + ["0" * 64]},
            {**self.proof, "path": path[:-1]},
        ):
            with self.assertRaises(VerificationFailure):
                self.verify(mutated)

    def test_bad_hex_and_boolean(self):
        with self.assertRaises(VerificationFailure) as ctx:
            self.verify({**self.proof,
                         "path": ["zz" + self.proof["path"][0][2:]]
                         + self.proof["path"][1:]})
        self.assertEqual(ctx.exception.code, "bad_hex")
        with self.assertRaises(VerificationFailure) as ctx:
            self.verify({**self.proof, "source_seq": True})
        self.assertEqual(ctx.exception.code, "bad_integer")

    def test_verify_rejects_path_carrying_its_own_root(self):
        # 证明声明一个更高的 tree_size 并自带「根」，不能覆盖调用方检查点
        with self.assertRaises(VerificationFailure):
            self.verify({**self.proof, "tree_size": 10,
                         "path": self.proof["path"] + ["0" * 64]})

    def test_cross_partner_and_log_id(self):
        with self.assertRaises(VerificationFailure) as ctx:
            self.verify({**self.proof, "partner_id": "globex"})
        self.assertEqual(ctx.exception.code, "cross_partner")
        with self.assertRaises(VerificationFailure) as ctx:
            self.verify({**self.proof, "log_id": "0" * 32})
        self.assertEqual(ctx.exception.code, "cross_log_id")

    def test_consistency_tamper(self):
        old = read_checkpoint(self.db_path, "acme", tree_size=3)
        new = read_checkpoint(self.db_path, "acme")
        proof = prove_consistency(self.db_path, "acme", old, new).as_dict()
        verify_consistency(old.as_dict(), new.as_dict(), proof)
        with self.assertRaises(VerificationFailure):
            verify_consistency(old.as_dict(), new.as_dict(),
                               {**proof, "path": proof["path"][:-1]})
        with self.assertRaises(VerificationFailure):
            verify_consistency(old.as_dict(), new.as_dict(),
                               {**proof, "path": proof["path"] + ["0" * 64]})
        with self.assertRaises(VerificationFailure):
            verify_consistency(old.as_dict(), new.as_dict(),
                               {**proof, "old_size": 4})
        with self.assertRaises(VerificationFailure):
            verify_consistency(old.as_dict(), new.as_dict(),
                               {**proof, "log_id": "1" * 32})


class LedgerEncodingRejectTests(LedgerTestCase):
    """已安装账本后，超范围字段在接收事务内被整次拒绝。"""

    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()

    def test_unencodable_event_is_rejected_atomically(self):
        # 账本协议要求严格 UTF-8；不可编码的事件必须整次拒绝，接收流水、
        # accepted_events、outbox 与账本都不留记录。
        from partner_webhook import eventlog

        original = eventlog.validate_encodable

        def refuse(partner_id, event_id, source_seq, body_sha256):
            raise eventlog.LedgerError("bad_text", "模拟不可编码的身份")

        eventlog.validate_encodable = refuse
        try:
            body = b'{"x":1}'
            headers = self.signed_headers(
                partner="acme", key_version="v1", secret="acme-secret",
                event_id="ok-id", sequence=1, timestamp=self.NOW, body=body)
            result = self.service.receive(method="POST", path="/webhook/events",
                                          raw_headers=headers, body=body)
        finally:
            eventlog.validate_encodable = original
        self.assertEqual(result.result, "rejected")
        self.assertEqual(result.reason, "ledger_encoding")
        self.assertEqual(result.http_status, 400)
        self.assertEqual(self.storage.iter_all(
            "SELECT COUNT(*) FROM accepted_events")[0][0], 0)
        self.assertEqual(self.storage.iter_all(
            "SELECT COUNT(*) FROM ingest_records")[0][0], 0)
        self.assertEqual(self.storage.iter_all(
            "SELECT COUNT(*) FROM outbox")[0][0], 0)
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], 0)

    def test_source_seq_out_of_range_is_rejected_atomically(self):
        # 通过直接调用 append_leaf 覆盖范围校验；接收层不会把超范围序号
        # 送进账本（int 头解析 + 非负检查在前）。
        from partner_webhook.eventlog import append_leaf
        before = log_status(self.db_path, "acme")["tree_size"]
        with self.assertRaises(LedgerError) as ctx:
            self.storage.conn.execute("BEGIN IMMEDIATE")
            try:
                append_leaf(self.storage.conn, partner_id="acme",
                            event_id="x", source_seq=1 << 64,
                            body_sha256="0" * 64, now=self.NOW)
            finally:
                self.storage.conn.execute("ROLLBACK")
        self.assertEqual(ctx.exception.code, "integer_out_of_range")
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], before)


class ConcurrencyTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()

    def test_two_threads_do_not_duplicate_leaf_indices(self):
        results = []
        errors = []

        def worker(offset):
            try:
                for index in range(10):
                    event_id = f"t{offset}-{index}"
                    body = json.dumps({"o": offset, "i": index}).encode()
                    result = self.deliver_acme(
                        event_id, offset * 10 + index, body)
                    results.append(result.result)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        rows = self.storage.iter_all(
            "SELECT leaf_index FROM log_leaves ORDER BY leaf_index")
        self.assertEqual([r[0] for r in rows], list(range(30)))
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], 30)

    def test_failed_append_rolls_back_event(self):
        before = (
            self.storage.iter_all("SELECT COUNT(*) AS n FROM accepted_events")[0][0],
            self.storage.iter_all("SELECT COUNT(*) AS n FROM log_leaves")[0][0],
            self.storage.iter_all("SELECT root_hash FROM event_logs")[0][0],
        )
        original = self.storage.append_event_log_leaf

        def boom(**kwargs):
            original(**kwargs)
            raise RuntimeError("crash after ledger write")

        self.storage.append_event_log_leaf = boom
        with self.assertRaises(RuntimeError):
            self.deliver_acme("boom", 99, b'{"boom":1}')
        self.storage.append_event_log_leaf = original
        after = (
            self.storage.iter_all("SELECT COUNT(*) AS n FROM accepted_events")[0][0],
            self.storage.iter_all("SELECT COUNT(*) AS n FROM log_leaves")[0][0],
            self.storage.iter_all("SELECT root_hash FROM event_logs")[0][0],
        )
        self.assertEqual(after, before)
        self.assertEqual(log_status(self.db_path, "acme")["tree_size"], 0)


class ReadCostTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()

    def test_old_prefix_proofs_read_logarithmically(self):
        count = 512
        for index in range(count):
            body = f'{{"i":{index}}}'.encode()
            result = self.deliver_acme(f"e{index:04d}", index, body)
            self.assertEqual(result.result, "accepted")
        small_trace = ReadTrace()
        small = read_checkpoint(self.db_path, "acme", tree_size=8,
                                trace=small_trace)
        large_trace = ReadTrace()
        large = read_checkpoint(self.db_path, "acme", tree_size=count,
                                trace=large_trace)
        self.assertLess(small_trace.node_reads, 10)
        self.assertLess(large_trace.node_reads, 12)
        # 旧前缀的根与独立参考实现一致
        self.assertEqual(small.root_hash.hex(), ref_root(
            [ref_leaf("acme", f"e{i:04d}", i, f'{{"i":{i}}}'.encode())
             for i in range(8)]).hex())
        checkpoint = read_checkpoint(self.db_path, "acme")
        trace = ReadTrace()
        proof = prove_inclusion(self.db_path, "acme", checkpoint,
                                f"e{count - 1:04d}", trace=trace)
        self.assertLess(trace.node_reads, 4 * count.bit_length())
        verify_inclusion(checkpoint.as_dict(), proof.as_dict(),
                         partner_id="acme",
                         event_id=f"e{count - 1:04d}",
                         source_seq=count - 1,
                         body_sha256=hashlib.sha256(
                             f'{{"i":{count - 1}}}'.encode()).hexdigest())


class CliAndOfflineTests(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.setUpLedger()
        self.install()
        for index in range(1, 4):
            self.deliver_body(f"e{index}", index,
                              json.dumps({"i": index}).encode())

    def cli(self, *args):
        command = [sys.executable, "-I",
                   str(REPO_ROOT / "partner_webhook" / "cli.py"),
                   "--config", str(self.config_path), "--db", self.db_path,
                   *args]
        return subprocess.run(command, capture_output=True, text=True)

    def offline(self, *args):
        command = [sys.executable, "-I",
                   str(REPO_ROOT / "partner_webhook" / "verifylog.py"), *args]
        return subprocess.run(command, capture_output=True, text=True)

    def test_cli_roundtrip_and_offline_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            checkpoint_path = tmp / "cp.json"
            proof_path = tmp / "proof.json"
            result = self.cli("log-checkpoint", "--partner", "acme",
                              "--out", str(checkpoint_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            result = self.cli("log-prove-inclusion", "--partner", "acme",
                              "--event-id", "e2", "--out", str(proof_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            body = self.bodies["e2"]
            result = self.offline(
                "inclusion", "--checkpoint", str(checkpoint_path),
                "--proof", str(proof_path), "--event-id", "e2",
                "--source-seq", "2",
                "--body-sha256", hashlib.sha256(body).hexdigest())
            self.assertEqual(result.returncode, 0, result.stderr)
            # 篡改：非零退出码
            doc = json.loads(proof_path.read_text())
            doc["path"][0] = ("f" if doc["path"][0][0] != "f" else "0") + \
                doc["path"][0][1:]
            proof_path.write_text(json.dumps(doc))
            result = self.offline(
                "inclusion", "--checkpoint", str(checkpoint_path),
                "--proof", str(proof_path), "--event-id", "e2",
                "--source-seq", "2",
                "--body-sha256", hashlib.sha256(body).hexdigest())
            self.assertNotEqual(result.returncode, 0)

    def test_verifylog_does_not_import_sqlite3(self):
        import ast
        source = (REPO_ROOT / "partner_webhook" / "verifylog.py").read_text()
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        self.assertNotIn("sqlite3", imported)
        self.assertFalse(any("eventlog" in name for name in imported))
        # 也没有打开数据库或读取节点表的代码
        for forbidden in ("connect(", "log_nodes", "log_leaves", "event_logs"):
            self.assertNotIn(forbidden, source)

    def test_cli_errors_are_nonzero(self):
        result = self.cli("log-prove-inclusion", "--partner", "acme",
                          "--event-id", "missing")
        self.assertNotEqual(result.returncode, 0)
        result = self.cli("log-status", "--partner", "nobody")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
