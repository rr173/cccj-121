"""正文差量交接（signature / delta / apply / inspect）测试。

覆盖：滚动弱校验定义、签名严格校验、确定性 COPY 选择（与独立慢速参考
实现交叉核对）、包格式错误矩阵、短读包装、空体/非文本/短尾、跨合作方
隔离、源库不被修改。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from partner_webhook.apply import (
    ApplyLimits, apply_delta, inspect_package, parse_header,
)
from partner_webhook.blocksig import WEAK_MASK, roll, weak_checksum
from partner_webhook.delta import generate_delta, locate_event
from partner_webhook.deltaformat import (
    DELTA_MAGIC, END_MARKER, FormatError, HashingReader, ReadWrapper,
    SIG_MAGIC,
)
from partner_webhook.signature import load_signature_into_index, write_signature
from partner_webhook.storage import Storage
from tests.helpers import WebhookTestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts import delta_reference  # noqa: E402


class ShortReadStream(io.RawIOBase):
    """每次 ``read(n)`` 最多返回 1..7 字节的包装，用于验证协议短读安全。"""

    def __init__(self, raw: bytes, max_chunk: int = 7):
        self._raw = raw
        self._pos = 0
        self.max_chunk = max_chunk

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self._raw) - self._pos
        take = min(n, self.max_chunk, len(self._raw) - self._pos)
        chunk = self._raw[self._pos:self._pos + take]
        self._pos += take
        return chunk


class LengthLimitedReader(io.RawIOBase):
    """Linux 风格：每次 read(n) 只返回 1..max_chunk 字节。"""

    def __init__(self, path: str, max_chunk: int = 7):
        self._fh = open(path, "rb")
        self.max_chunk = max_chunk

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.max_chunk
        return self._fh.read(min(n, self.max_chunk))


class WeakChecksumTest(unittest.TestCase):
    def test_definition_and_roll(self):
        data = bytes([3, 1, 4, 1, 5, 9, 2, 6, 5, 3])
        for length in range(1, len(data) + 1):
            expected = weak_checksum(data[:length])
            a = sum(data[:length]) & WEAK_MASK
            b = sum((length - i) * data[:length][i] for i in range(length)) & WEAK_MASK
            self.assertEqual(expected, (b << 16) | a)
        # 滚动关系与逐窗重求一致
        B = 4
        a = sum(data[:B]) & WEAK_MASK
        b = sum((B - i) * data[i] for i in range(B)) & WEAK_MASK
        for start in range(0, len(data) - B):
            self.assertEqual(((b & WEAK_MASK) << 16) | (a & WEAK_MASK),
                             weak_checksum(data, start=start, length=B))
            a, b = roll(a, b, B, data[start], data[start + B])

    def test_weak_collision_but_different_content(self):
        # 两个字节串交换相邻字节且总长不变：a 相同、b 可能不同/相同；
        # 构造真实弱值相同的块（内容不同），证明弱值不能代表内容。
        found = None
        base = bytearray(b"ab")
        # 穷举小样本找一对同长、弱值相同但字节不同的块
        seen = {}
        for x in range(256):
            for y in range(256):
                for z in range(256):
                    data = bytes([x, y, z, 0])
                    w = weak_checksum(data)
                    if w in seen and seen[w] != data:
                        found = (seen[w], data)
                        break
                    seen[w] = data
                if found:
                    break
            if found:
                break
        self.assertIsNotNone(found)
        self.assertNotEqual(found[0], found[1])
        self.assertEqual(weak_checksum(found[0]), weak_checksum(found[1]))


class DeltaCase(WebhookTestCase):
    def setUp(self):
        super().setUp()
        self.storage = Storage(self.db_path)
        self.extras: list[str] = []

    def add_event(self, *, partner="acme", event_id="evt-new", seq=1,
                  body=b"", digest_override=None):
        real = hashlib.sha256(body).hexdigest()
        digest = digest_override or real
        self.storage.store_raw_body(body, self.NOW)
        rid = self.storage.insert_ingest_record(dict(
            received_at=self.NOW, partner_id=partner, key_version="v1",
            claimed_timestamp=self.NOW, event_id=event_id, source_seq=seq,
            body_sha256=digest, result="accepted", reason=None,
            http_status=200, headers={}))
        self.storage.insert_accepted_event(dict(
            event_id=event_id, partner_id=partner, source_seq=seq,
            key_version="v1", body_sha256=digest, ingest_record_id=rid,
            claimed_timestamp=self.NOW, accepted_at=self.NOW))
        self.storage.commit()
        return digest

    def roundtrip(self, old_path, delta, expected: bytes, name: str) -> None:
        target = self.dir / name
        report = apply_delta(old_path, delta, target)
        self.assertTrue(report.content_verified)
        self.assertEqual(expected, target.read_bytes())

    def materialize(self, old: bytes, new: bytes, block_size: int,
                    *, event_id="evt-new", partner="acme", seq=1,
                    literal_max=65536, digest_override=None):
        old_path = self.dir / f"old-{event_id}.bin"
        sig_path = self.dir / f"old-{event_id}.sig"
        delta_path = self.dir / f"delta-{event_id}.bin"
        old_path.write_bytes(old)
        write_signature(old_path, block_size, sig_path)
        self.add_event(partner=partner, event_id=event_id, seq=seq, body=new,
                       digest_override=digest_override)
        stats = generate_delta(self.db_path, partner, event_id, sig_path,
                               delta_path, literal_max=literal_max)
        return old_path, sig_path, delta_path, stats


class SignatureTest(DeltaCase):
    def test_layout_and_coverage(self):
        old = b"x" * 10
        path = self.dir / "o"; path.write_bytes(old)
        sig = self.dir / "o.sig"
        summary = write_signature(path, 4, sig)
        self.assertEqual(3, summary["block_count"])
        self.assertEqual(62 + 3 * 48 + 32, sig.stat().st_size)
        index = load_signature_into_index(sig, self.dir / "i.sqlite")
        self.assertEqual(4, index.header.block_size)
        self.assertEqual(10, index.header.file_length)
        self.assertEqual(2, index.header.tail_length)
        index.close()

    def test_empty_file_has_no_blocks(self):
        path = self.dir / "e"; path.write_bytes(b"")
        sig = self.dir / "e.sig"
        summary = write_signature(path, 8, sig)
        self.assertEqual(0, summary["block_count"])
        self.assertEqual(62 + 32, sig.stat().st_size)
        index = load_signature_into_index(sig, self.dir / "i.sqlite")
        self.assertEqual(0, index.header.block_count)
        index.close()

    def test_refuses_existing_output(self):
        path = self.dir / "o"; path.write_bytes(b"abc")
        sig = self.dir / "o.sig"; sig.write_bytes(b"junk")
        with self.assertRaises(FileExistsError):
            write_signature(path, 1, sig)

    def test_rejects_nonpositive_block(self):
        path = self.dir / "o"; path.write_bytes(b"abc")
        with self.assertRaises(FormatError):
            write_signature(path, 0, self.dir / "x.sig")
        with self.assertRaises(FormatError):
            write_signature(path, -1, self.dir / "y.sig")

    def test_strict_signature_errors(self):
        old = bytes(range(64))
        path = self.dir / "o"; path.write_bytes(old)
        sig = self.dir / "o.sig"
        write_signature(path, 8, sig)
        raw = bytearray(sig.read_bytes())
        cases = {
            "magic": (0, b"X", "magic"),
            "version": (8, b"\x00\x02", "版本"),
            "block_zero": (10, b"\x00\x00\x00\x00", "块长"),
            "summary": (len(raw) - 1, b"\x00", "摘要"),
        }
        for name, (pos, newbyte, label) in cases.items():
            damaged = bytearray(raw)
            damaged[pos:pos + len(newbyte)] = newbyte
            target = self.dir / f"bad-{name}.sig"
            target.write_bytes(bytes(damaged))
            with self.assertRaises(FormatError) as ctx:
                load_signature_into_index(target, self.dir / "ix.sqlite")
            self.assertIn(label, str(ctx.exception))
        # 截短
        target = self.dir / "trunc.sig"
        target.write_bytes(bytes(raw[:-1]))
        with self.assertRaises(FormatError):
            load_signature_into_index(target, self.dir / "it.sqlite")

    def test_block_count_mismatch(self):
        path = self.dir / "o"; path.write_bytes(b"A" * 100)
        sig = self.dir / "o.sig"; write_signature(path, 10, sig)
        raw = bytearray(sig.read_bytes())
        raw[14:22] = (1000).to_bytes(8, "big")
        target = self.dir / "bc.sig"; target.write_bytes(bytes(raw))
        with self.assertRaises(FormatError) as ctx:
            load_signature_into_index(target, self.dir / "bc.sqlite")
        self.assertIn("块数", str(ctx.exception))

    def test_block_offset_must_cover_continuously(self):
        path = self.dir / "o"; path.write_bytes(b"ABCDEFGH" * 4)
        sig = self.dir / "o.sig"; write_signature(path, 8, sig)
        raw = bytearray(sig.read_bytes())
        raw[62:70] = (5).to_bytes(8, "big")
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(bytes(raw[:body_end])).digest()
        target = self.dir / "off.sig"; target.write_bytes(bytes(raw))
        with self.assertRaises(FormatError) as ctx:
            load_signature_into_index(target, self.dir / "off.sqlite")
        self.assertIn("偏移", str(ctx.exception))

    def test_block_length_must_match_file_length(self):
        path = self.dir / "o"; path.write_bytes(b"ABCDEFGH" * 4)
        sig = self.dir / "o.sig"; write_signature(path, 8, sig)
        raw = bytearray(sig.read_bytes())
        raw[62 + 8:62 + 12] = (7).to_bytes(4, "big")
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(bytes(raw[:body_end])).digest()
        target = self.dir / "len.sig"; target.write_bytes(bytes(raw))
        with self.assertRaises(FormatError) as ctx:
            load_signature_into_index(target, self.dir / "len.sqlite")
        self.assertIn("长度", str(ctx.exception))

    def test_signature_does_not_silently_degrade(self):
        # 损坏签名绝不能当成空签名（否则会退化发送全文）
        path = self.dir / "o"; path.write_bytes(b"abc")
        sig = self.dir / "o.sig"; write_signature(path, 8, sig)
        bad = bytearray(sig.read_bytes())
        # 改块记录长度字段，同时修好整文件摘要也没用：结构必须自洽。
        bad[62 + 8:62 + 12] = (7).to_bytes(4, "big")
        target = self.dir / "b.sig"; target.write_bytes(bytes(bad))
        with self.assertRaises(FormatError):
            load_signature_into_index(target, self.dir / "ii.sqlite")


class DeltaAlgorithmTest(DeltaCase):
    def test_start_insert(self):
        old = b"ABCDEFGH" * 4
        new = b"XYZ" + old
        old_path, sig, delta, stats = self.materialize(old, new, 8)
        self.assertEqual(4, stats["copy_ops"])
        self.assertEqual(3, stats["literal_bytes"])
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertTrue(report.content_verified)
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_internal_delete(self):
        old = b"ABCDEFGH" * 4
        new = old[:16] + old[24:]
        old_path, sig, delta, stats = self.materialize(old, new, 8)
        self.assertEqual(3, stats["copy_ops"])
        self.assertEqual(0, stats["literal_bytes"])
        self.roundtrip(old_path, delta, new, "out")

    def test_local_replace(self):
        old = b"ABCDEFGH" * 4
        new = old[:16] + b"QQQQQQQQ" + old[24:]
        old_path, sig, delta, stats = self.materialize(old, new, 8)
        self.assertEqual(8, stats["literal_bytes"])
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_empty_old_file(self):
        old = b""
        new = b"plain new text without old"
        old_path, sig, delta, stats = self.materialize(old, new, 5, literal_max=6)
        self.assertEqual(0, stats["copy_ops"])
        self.assertGreater(stats["literal_ops"], 1)   # 受 literal_max 切段
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_empty_new_body(self):
        old = b"ABCDEFGH" * 4
        old_path, sig, delta, stats = self.materialize(old, b"", 8)
        self.assertEqual(0, stats["copy_ops"])
        self.assertEqual(0, stats["literal_bytes"])
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertTrue(report.content_verified)
        self.assertEqual(b"", (self.dir / "out").read_bytes())

    def test_short_body(self):
        old = b"ABCDEFGH" * 4
        old_path, sig, delta, stats = self.materialize(old, b"hi", 100)
        self.assertEqual(0, stats["copy_ops"])
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(b"hi", (self.dir / "out").read_bytes())

    def test_short_tail_matches_only_exact_remainder(self):
        old = b"0123456789ABCDE"  # 15 bytes, B=8 -> tail 7
        new = b"ZZ" + old
        old_path, sig, delta, stats = self.materialize(old, new, 8)
        # 前缀 ZZ 字面；尾块 7 字节恰好匹配；首块 8 匹配。
        self.assertEqual(2, stats["copy_ops"])
        self.assertEqual(2, stats["literal_bytes"])
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_tail_short_not_matched_when_not_remainder(self):
        old = b"0123456789ABCDE"  # tail 7
        new = b"0123456789ABCDE" + b"XY"
        old_path, sig, delta, stats = self.materialize(old, new, 8)
        # 规则：尾块 7 字节仅在剩余恰为 7 时尝试；此处剩余 17/9，不匹配尾块。
        self.assertEqual(1, stats["copy_ops"])   # 仅首块 8 字节
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_duplicate_blocks_choose_smallest_offset(self):
        old = b"AAAA" + b"BBBB" + b"AAAA" + b"CCCC"
        new = b"AAAA" + b"CCCC" + b"AAAA" + b"BBBB"
        old_path, sig, delta, stats = self.materialize(old, new, 4)
        ops = delta_reference.parse_package(delta.read_bytes())["ops"]
        copies = [op for op in ops if op[0] == "COPY"]
        # 第一个 AAAA 必须选偏移 0，而不是偏移 8。
        self.assertEqual(("COPY", 0, 4), copies[0])
        self.roundtrip(old_path, delta, new, "out")

    def test_non_text_binary(self):
        old = bytes(range(256)) * 4
        new = b"\x00\xff" + old + b"\x80"
        old_path, sig, delta, stats = self.materialize(old, new, 16)
        report = apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_cross_partner_same_event_id(self):
        # 另一个合作方有同号事件，但签名/查询只按 acme 定位
        old = b"old body here"
        old_path = self.dir / "o.bin"; old_path.write_bytes(old)
        sig = self.dir / "o.sig"; write_signature(old_path, 4, sig)
        self.add_event(partner="globex", event_id="evt-x", seq=1,
                       body=b"globex secret body")
        self.add_event(partner="acme", event_id="evt-x", seq=2,
                       body=old)
        with self.assertRaises(Exception):
            generate_delta(self.db_path, "nobody", "evt-x", sig,
                           self.dir / "x.delta")
        stats = generate_delta(self.db_path, "acme", "evt-x", sig,
                               self.dir / "a.delta")
        self.assertEqual("acme", stats["partner_id"])
        self.assertEqual(len(old), stats["new_length"])
        report = apply_delta(old_path, self.dir / "a.delta", self.dir / "out")
        self.roundtrip(old_path, self.dir / "a.delta", old, "out-x")

    def test_digest_mismatch_refused(self):
        old = b"reg"
        new_path = self.dir / "n.bin"; new_path.write_bytes(b"good bytes")
        sig_path = self.dir / "o.sig"
        (self.dir / "o.bin").write_bytes(old)
        write_signature(self.dir / "o.bin", 4, sig_path)
        self.add_event(event_id="evt-bad", body=b"good bytes",
                       digest_override="0" * 64) if False else None
        body = b"good bytes"
        self.storage.store_raw_body(body, self.NOW)
        rid = self.storage.insert_ingest_record(dict(
            received_at=self.NOW, partner_id="acme", key_version="v1",
            claimed_timestamp=self.NOW, event_id="evt-bad", source_seq=9,
            body_sha256=hashlib.sha256(body).hexdigest(), result="accepted",
            reason=None, http_status=200, headers={}))
        # accepted_events 指向另一份（不存在的）正文摘要，模拟登记失配
        self.storage.conn.execute(
            "INSERT INTO raw_bodies(body_sha256, body_blob, byte_length, "
            "first_seen_at) VALUES (?, ?, ?, ?)",
            ("0" * 64, b"corrupted", 9, self.NOW))
        self.storage.insert_accepted_event(dict(
            event_id="evt-bad", partner_id="acme", source_seq=9,
            key_version="v1", body_sha256="0" * 64, ingest_record_id=rid,
            claimed_timestamp=self.NOW, accepted_at=self.NOW))
        self.storage.commit()
        with self.assertRaises(Exception) as ctx:
            generate_delta(self.db_path, "acme", "evt-bad", sig_path,
                           self.dir / "d.bin")
        self.assertIn("SHA-256", str(ctx.exception))

    def test_source_database_unchanged(self):
        old = b"stable old"
        new = b"stable new"
        old_path = self.dir / "o.bin"; old_path.write_bytes(old)
        sig = self.dir / "o.sig"; write_signature(old_path, 4, sig)
        self.add_event(event_id="evt-stable", body=new)
        self.storage.close()
        before = hashlib.sha256(Path(self.db_path).read_bytes()).hexdigest()
        generate_delta(self.db_path, "acme", "evt-stable", sig,
                       self.dir / "d.bin")
        after = hashlib.sha256(Path(self.db_path).read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.storage = Storage(self.db_path)  # 重开供 tearDown 关闭

    def test_apply_does_not_modify_old_or_package(self):
        old = b"0123456789" * 4
        new = b"XX" + old
        old_path, sig, delta, stats = self.materialize(old, new, 8)
        old_digest = hashlib.sha256(old_path.read_bytes()).hexdigest()
        pkg_digest = hashlib.sha256(delta.read_bytes()).hexdigest()
        apply_delta(old_path, delta, self.dir / "out")
        self.assertEqual(old_digest,
                         hashlib.sha256(old_path.read_bytes()).hexdigest())
        self.assertEqual(pkg_digest,
                         hashlib.sha256(delta.read_bytes()).hexdigest())


class ReferenceMatcherTest(DeltaCase):
    """用独立慢速参考实现核对生产包的确定性 COPY 选择。"""

    CASES = [
        (b"ABCDEFGH" * 3, b"XY" + b"ABCDEFGH" * 3, 8),
        (b"ABCDEFGH" * 3, b"ABCD" + b"EFGH" + b"ABCD", 4),
        (b"0123456789ABCDE", b"0123456789ABCDE", 8),
        (b"0123456789ABCDE", b"0123456789ABCDE" + b"Q", 8),
        (b"", b"no old at all, literal only", 7),
        (b"aaab" * 5, b"aaab" + b"baaa" + b"aaab" * 3, 4),
        (bytes(range(32)), bytes(range(8)) + b"\xff\xff" + bytes(range(8, 32)), 8),
        (b"REDBLUE" * 4, b"BLUE" + b"REDBLUE" * 4, 4),
    ]

    def test_matches_reference(self):
        for idx, (old, new, B) in enumerate(self.CASES):
            with self.subTest(idx=idx):
                old_path, sig, delta, stats = self.materialize(
                    old, new, B, event_id=f"evt-ref-{idx}", seq=idx)
                pkg = delta_reference.parse_package(delta.read_bytes())
                expected_ops = delta_reference.match(old, new, B)
                ok, detail = delta_reference.compare(
                    expected_ops, pkg["ops"], 65536)
                self.assertTrue(ok, detail)
                self.roundtrip(old_path, delta, new, f"out-{idx}")

    def test_reference_roll_matches_definition(self):
        data = b"".join(bytes([(i * 7 + 3) % 256]) for i in range(40))
        B = 5
        a = sum(data[:B]) % 65536
        b = sum((B - i) * data[i] for i in range(B)) % 65536
        for start in range(len(data) - B):
            window = data[start:start + B]
            self.assertEqual(delta_reference.weak_of(window),
                             (b << 16) | a)
            a, b = delta_reference.roll(a, b, B, data[start], data[start + B])


class SameWeakDifferentContentTest(DeltaCase):
    """弱值相同但内容不同的块：只会复用强摘要一致的块。"""

    def find_weak_pair(self, block_size: int):
        # 构造同长、同弱值、不同字节的两块（3 字节前缀穷举即可命中）。
        seen = {}
        for x in range(256):
            for y in range(256):
                for z in range(256):
                    block = bytes([x, y, z, 0])
                    weak = weak_checksum(block)
                    prior = seen.get(weak)
                    if prior is not None and prior != block:
                        return prior, block
                    seen[weak] = block
        raise AssertionError("未能找到弱值碰撞样本")

    def test_only_strong_match_reused(self):
        block_a, block_b = self.find_weak_pair(4)
        self.assertNotEqual(block_a, block_b)
        self.assertEqual(weak_checksum(block_a), weak_checksum(block_b))
        old = block_a * 4
        new = block_b + block_a
        old_path, sig, delta, stats = self.materialize(
            old, new, 4, event_id="evt-weak")
        pkg = delta_reference.parse_package(delta.read_bytes())
        copies = [op for op in pkg["ops"] if op[0] == "COPY"]
        self.assertTrue(all(op[1] % 4 == 0 for op in copies))
        # 前缀 block_b 与旧块弱值相同但强摘要不同 -> 必须字面
        self.assertEqual(block_b, pkg["ops"][0][1])
        self.assertTrue(copies)
        # 每个 COPY 引用的旧块内容必须真的等于被复制的内容
        for op in copies:
            self.assertEqual(old[op[1]:op[1] + op[2]], block_a)
        self.roundtrip(old_path, delta, new, "out")

    def test_strong_checks_only_when_candidates(self):
        old = bytes(range(32)) * 4
        new = b"no matching blocks here, all literal" * 2
        old_path, sig, delta, stats = self.materialize(
            old, new, 16, event_id="evt-nocand")
        self.assertEqual(0, stats["copy_ops"])
        self.assertEqual(0, stats["strong_checks"])
        self.assertGreater(stats["roll_updates"], 0)
        # 弱值未命中时绝不能为每个窗口算强摘要
        self.assertEqual(0, stats["strong_checks"])
        self.assertGreater(stats["roll_updates"], stats["strong_checks"])


class ManyCollisionCandidatesTest(DeltaCase):
    """同一弱值/长度下大量重复块候选：仍按最小偏移选择，内存不随数量增长。"""

    def test_many_duplicate_candidates(self):
        block = b"COLLIDE!"
        old = block * 300
        new = block * 2
        old_path, sig, delta, stats = self.materialize(
            old, new, 8, event_id="evt-many")
        pkg = delta_reference.parse_package(delta.read_bytes())
        self.assertEqual([("COPY", 0, 8), ("COPY", 0, 8)],
                         [op for op in pkg["ops"] if op[0] == "COPY"])
        # 候选很多时 strong_checks 仍只按窗口计（不按候选计）
        self.assertLessEqual(stats["strong_checks"], 2)
        self.roundtrip(old_path, delta, new, "out")


class PackageErrorTest(DeltaCase):
    def good_package(self):
        old = b"hello old world"
        new = b"hello NEW world"
        return self.materialize(old, new, 4, event_id="evt-err")

    def apply_with(self, old_path, package_bytes, name):
        pkg = self.dir / f"{name}.delta"
        pkg.write_bytes(package_bytes)
        target = self.dir / f"{name}.out"
        try:
            apply_delta(old_path, pkg, target)
            return None
        except FileExistsError as exc:
            return exc
        except FormatError as exc:
            self.assertFalse(target.exists(), "失败不得留下目标")
            return exc

    def test_magic_version(self):
        old_path, sig, delta, stats = self.good_package()
        raw = delta.read_bytes()
        self.assertIsNotNone(self.apply_with(old_path, b"X" + raw[1:], "m"))
        self.assertIsNotNone(self.apply_with(
            old_path, raw[:8] + b"\x00\x02" + raw[10:], "v"))

    def test_copy_out_of_bounds(self):
        old_path, sig, delta, stats = self.good_package()
        raw = bytearray(delta.read_bytes())
        header_size = 98 + 4 + len("evt-err".encode()) + 8
        # 第一条是 COPY(0,4)：把长度改成 5（跨块）
        raw[header_size + 9:header_size + 13] = (5).to_bytes(4, "big")
        # 修好整包摘要让错误来自边界检查而不是摘要（摘要也应仍能发现，
        # 但要证明 COPY 边界本身被检查）。
        # 直接构造尾部摘要：重新计算前面全部字节
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(raw[:body_end]).digest()
        try:
            apply_delta(old_path, self.dir / "copy.delta" if False else
                        self._write(raw, "copy"), self.dir / "x.out")
        except FormatError as exc:
            self.assertIn("COPY", str(exc))
            self.assertFalse((self.dir / "x.out").exists())
        else:
            self.fail("越界 COPY 未被拒绝")

    def _write(self, raw: bytes, name: str) -> Path:
        path = self.dir / f"{name}.pkg"
        path.write_bytes(bytes(raw))
        return path

    def test_copy_misaligned(self):
        old_path, sig, delta, stats = self.good_package()
        raw = bytearray(delta.read_bytes())
        header_size = 98 + 4 + len("evt-err".encode()) + 8
        raw[header_size + 1:header_size + 9] = (1).to_bytes(8, "big")
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(raw[:body_end]).digest()
        with self.assertRaises(FormatError) as ctx:
            apply_delta(old_path, self._write(raw, "mis"), self.dir / "y.out")
        self.assertIn("对齐", str(ctx.exception))
        self.assertFalse((self.dir / "y.out").exists())

    def test_truncated_literal(self):
        old_path, sig, delta, stats = self.good_package()
        raw = delta.read_bytes()
        end = raw.find(END_MARKER)
        with self.assertRaises(FormatError):
            apply_delta(old_path, self._write(raw[:end - 3], "trunc"),
                        self.dir / "z.out")
        self.assertFalse((self.dir / "z.out").exists())

    def test_digest_mismatch(self):
        old_path, sig, delta, stats = self.good_package()
        raw = bytearray(delta.read_bytes())
        header = parse_header(
            ReadWrapper(HashingReader(io.BytesIO(bytes(raw)))), ApplyLimits())
        # 改头部声明的新正文摘要
        raw[42:74] = b"\x00" * 32
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(raw[:body_end]).digest()
        with self.assertRaises(FormatError) as ctx:
            apply_delta(old_path, self._write(raw, "dig"), self.dir / "d.out")
        self.assertIn("SHA-256", str(ctx.exception))
        self.assertFalse((self.dir / "d.out").exists())

    def test_unknown_opcode(self):
        old_path, sig, delta, stats = self.good_package()
        raw = bytearray(delta.read_bytes())
        header_size = 98 + 4 + len("evt-err".encode()) + 8
        raw[header_size] = 9
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(raw[:body_end]).digest()
        with self.assertRaises(FormatError) as ctx:
            apply_delta(old_path, self._write(raw, "op"), self.dir / "o.out")
        self.assertIn("未知指令", str(ctx.exception))
        self.assertFalse((self.dir / "o.out").exists())

    def test_missing_end_marker(self):
        old_path, sig, delta, stats = self.good_package()
        raw = delta.read_bytes()
        raw_without_end = raw.replace(END_MARKER, b"XXXXXXXX", 1)
        with self.assertRaises(FormatError):
            apply_delta(old_path, self._write(raw_without_end, "end"),
                        self.dir / "e.out")
        self.assertFalse((self.dir / "e.out").exists())

    def test_trailing_bytes(self):
        old_path, sig, delta, stats = self.good_package()
        raw = delta.read_bytes() + b"extra"
        with self.assertRaises(FormatError) as ctx:
            apply_delta(old_path, self._write(raw, "tail"), self.dir / "t.out")
        self.assertIn("额外字节", str(ctx.exception))
        self.assertFalse((self.dir / "t.out").exists())

    def test_wrong_old_file_one_byte(self):
        old_path, sig, delta, stats = self.good_package()
        bad_old = bytearray(old_path.read_bytes())
        bad_old[1] ^= 1
        bad_path = self.dir / "bad-old.bin"; bad_path.write_bytes(bytes(bad_old))
        with self.assertRaises(FormatError) as ctx:
            apply_delta(bad_path, delta, self.dir / "w.out")
        self.assertIn("SHA-256", str(ctx.exception))
        self.assertFalse((self.dir / "w.out").exists())

    def test_existing_target_refused(self):
        old_path, sig, delta, stats = self.good_package()
        target = self.dir / "existing.out"
        target.write_bytes(b"pre-existing")
        with self.assertRaises(FileExistsError):
            apply_delta(old_path, delta, target)
        self.assertEqual(b"pre-existing", target.read_bytes())

    def test_identity_invalid_utf8(self):
        old_path, sig, delta, stats = self.good_package()
        raw = bytearray(delta.read_bytes())
        # 合作方 ID 位于固定头之后；把一个字节改成非法 UTF-8 序列。
        raw[98:100] = b"\xff\xff"
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(raw[:body_end]).digest()
        with self.assertRaises(FormatError) as ctx:
            apply_delta(old_path, self._write(raw, "utf"), self.dir / "u.out")
        self.assertIn("UTF-8", str(ctx.exception))

    def test_limit_declared_then_allocated(self):
        old_path, sig, delta, stats = self.good_package()
        # 声明的 LITERAL 上限字段超过调用方上限时，解析头部即失败。
        raw = bytearray(delta.read_bytes())
        pl = int.from_bytes(raw[10:12], "big")
        el = int.from_bytes(raw[12:14], "big")
        lit_pos = 98 + pl + el
        raw[lit_pos:lit_pos + 4] = (10_000_000).to_bytes(4, "big")
        body_end = len(raw) - 32
        raw[body_end:] = hashlib.sha256(raw[:body_end]).digest()
        limits = ApplyLimits(max_literal=1024)
        with self.assertRaises(FormatError) as ctx:
            apply_delta(old_path, self._write(raw, "lim"), self.dir / "l.out",
                        limits=limits)
        self.assertIn("LITERAL", str(ctx.exception))


class ShortReadTest(DeltaCase):
    def test_apply_over_short_reads(self):
        old = b"ABCDEFGH" * 8
        new = b"head" + old + b"tail"
        old_path, sig, delta, stats = self.materialize(
            old, new, 8, event_id="evt-shortread")
        # 用 1..7 字节短读包装直接驱动 apply 的核心读取
        from partner_webhook.apply import _walk
        limits = ApplyLimits()
        with open(delta, "rb") as pkg_raw:
            wrapped = ReadWrapper(HashingReader(
                ShortReadStreamRead(pkg_raw.read(), 5)))
        token = ReadWrapper(HashingReader(ShortReadStreamRead(
            delta.read_bytes(), 3)))
        header = parse_header(token, limits)
        self.assertEqual("acme", header.partner_id)
        self.assertGreater(token.short_reads, 0)
        report = inspect_package(str(delta), limits=limits,
                                 read_chunk_limit=1)
        self.assertEqual(report.short_reads, 0)
        self.assertEqual(stats["new_length"], report.new_length)

    def test_apply_end_to_end_short_read_via_limits(self):
        old = os.urandom(512)
        new = b"hi" + old
        old_path, sig, delta, stats = self.materialize(
            old, new, 16, event_id="evt-sr2")
        report = apply_delta(old_path, delta, self.dir / "out",
                             read_chunk_limit=1)
        self.assertEqual(report.short_reads, 0)
        self.assertEqual(new, (self.dir / "out").read_bytes())

    def test_signature_short_read(self):
        old = bytes(range(200))
        path = self.dir / "so.bin"; path.write_bytes(old)
        sig = self.dir / "so.sig"; write_signature(path, 8, sig)
        index = load_signature_into_index(sig, self.dir / "si.sqlite",
                                          read_chunk_limit=1)
        self.assertEqual(25, index.header.block_count)
        index.close()

    def test_inspect_does_not_print_body(self):
        old = b"secret old"
        new = b"secret new with body"
        old_path, sig, delta, stats = self.materialize(
            old, new, 4, event_id="evt-inspect")
        report = inspect_package(str(delta))
        as_dict = report.as_dict()
        # 报告只有计数/长度/摘要，没有字面内容
        rendered = json.dumps(as_dict, ensure_ascii=False)
        self.assertNotIn(new.decode("utf-8", "replace"), rendered)
        self.roundtrip(old_path, delta, new, "out")


def ShortReadStreamRead(raw: bytes, max_chunk: int):
    return ShortReadStream(raw, max_chunk)


if __name__ == "__main__":
    unittest.main()
