"""Acceptance tests for the seekable gzip index and custom DEFLATE decoder.

Reference expectations always come from the standard library's gzip/zlib
implementations.  The production package never imports zlib.decompress or
gzip.decompress; those calls are confined to this test module.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import random
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from partner_webhook.deflate_codec import (
    WINDOW_SIZE,
    DeflateError,
    HuffmanTable,
    TruncatedStream,
)
from partner_webhook.gzip_index import (
    PAGE_SIZE,
    Config,
    GzipIndexError,
    build_index,
    extract_range,
    verify_index,
)

ROOT = Path(__file__).resolve().parent.parent


class BitWriter:
    def __init__(self):
        self.bits = []

    def write(self, value: int, count: int) -> None:
        for i in range(count):
            self.bits.append((value >> i) & 1)

    def bytes(self, align: bool = True) -> bytes:
        bits = list(self.bits)
        if align and len(bits) % 8:
            bits.extend([0] * (8 - len(bits) % 8))
        out = bytearray()
        for i in range(0, len(bits), 8):
            out.append(sum(bits[i + j] << j for j in range(min(8, len(bits) - i))))
        return bytes(out)


def make_raw_deflate(data: bytes, block_type: int, bfinal: bool = True) -> bytes:
    w = BitWriter()
    w.write(1 if bfinal else 0, 1)
    w.write(block_type, 2)
    if block_type == 0:
        body = w.bytes(align=True)
        return body + len(data).to_bytes(2, "little") + \
            (len(data) ^ 0xffff).to_bytes(2, "little") + data
    if block_type == 1:
        def fixed_code(symbol: int) -> tuple[int, int]:
            if symbol < 144:
                return 0b00110000 + symbol, 8
            if symbol < 256:
                return 0b110010000 + symbol - 144, 9
            if symbol < 280:
                return symbol - 256, 7
            return 0b11000000 + symbol - 280, 8
        for value in data:
            code, length = fixed_code(value)
            # Reverse canonical code because bytes are read LSB-first.
            w.write(int(f"{code:0{length}b}"[::-1], 2), length)
        code, length = fixed_code(256)
        w.write(int(f"{code:0{length}b}"[::-1], 2), length)
        return w.bytes()
    raise AssertionError("dynamic manual streams use make_dynamic_block")


def gzip_wrap(deflate: bytes, *, flags: int = 0, extra: bytes = b"",
              name: bytes = b"", comment: bytes = b"", mtime: int = 0) -> bytes:
    header = bytes([31, 139, 8, flags, *mtime.to_bytes(4, "little"), 0, 3])
    if flags & 4:
        header += len(extra).to_bytes(2, "little") + extra
    if flags & 8:
        header += name + b"\x00"
    if flags & 16:
        header += comment + b"\x00"
    if flags & 2:
        crc = zlib.crc32(header) & 0xffff
        header += crc.to_bytes(2, "little")
    return header + deflate


def gzip_member(data: bytes, block_type: int = 1, flags: int = 0,
                **kwargs) -> bytes:
    raw = make_raw_deflate(data, block_type)
    body = gzip_wrap(raw, flags=flags, **kwargs)
    body += zlib.crc32(data).to_bytes(4, "little")
    body += (len(data) & 0xffffffff).to_bytes(4, "little")
    return body


def make_source_db(path: Path, bodies: dict[tuple[str, str], bytes]) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE raw_bodies (body_sha256 TEXT PRIMARY KEY, body_blob BLOB, "
        "byte_length INTEGER, first_seen_at INTEGER)"
    )
    conn.execute(
        "CREATE TABLE accepted_events (event_id TEXT, partner_id TEXT, "
        "source_seq INTEGER, key_version TEXT, body_sha256 TEXT, "
        "ingest_record_id INTEGER, claimed_timestamp INTEGER, accepted_at INTEGER, "
        "PRIMARY KEY(partner_id, event_id))"
    )
    for index, ((partner, event), body) in enumerate(bodies.items()):
        digest = hashlib.sha256(body).hexdigest()
        conn.execute("INSERT OR IGNORE INTO raw_bodies VALUES(?,?,?,?)",
                     (digest, body, len(body), 1))
        conn.execute("INSERT INTO accepted_events VALUES(?,?,?,?,?,?,?,?)",
                     (event, partner, index + 1, "v1", digest, index + 1, 1, 1))
    conn.commit()
    conn.close()


class GzipIndexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = self.dir / "source.db"
        self.index = self.dir / "index.sqlite"
        self.config = Config.create(
            spacing=128, max_output=10_000_000,
            max_optional_header=4096, tmp_dir=self.dir,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, body: bytes, partner="p", event="e"):
        make_source_db(self.db, {(partner, event): body})
        return build_index(self.db, partner, event, self.index, self.config)

    def extract(self, start: int, length: int, name="out.bin",
                partner="p", event="e", index=None, db=None):
        out = self.dir / name
        stats = extract_range(db or self.db, partner, event,
                              index or self.index, start, length, out)
        return out.read_bytes(), stats

    def test_config_validation(self):
        for kwargs in (
            dict(spacing=0, max_output=1, max_optional_header=1, tmp_dir=self.dir),
            dict(spacing=1, max_output=0, max_optional_header=1, tmp_dir=self.dir),
            dict(spacing=1, max_output=1, max_optional_header=0, tmp_dir=self.dir),
        ):
            with self.assertRaises(GzipIndexError):
                Config.create(**kwargs)
        with self.assertRaises(GzipIndexError):
            Config.create(spacing=1, max_output=1, max_optional_header=1,
                          tmp_dir=self.dir / "missing")

    def test_huffman_rejects_illegal_and_accepts_degenerate_tables(self):
        with self.assertRaises(DeflateError):
            HuffmanTable.from_lengths([16])  # exceeds permitted 15-bit prefix
        with self.assertRaises(DeflateError):
            # Two complete one-bit codes consume the same code space.
            HuffmanTable.from_lengths([1, 1, 1])
        one_bit = HuffmanTable.from_lengths([1])
        self.assertEqual(one_bit.count, 1)
        max_code = HuffmanTable.from_lengths([15])
        self.assertEqual(max_code.max_bits, 15)
        incomplete = HuffmanTable.from_lengths([2, 0, 0, 0])
        self.assertEqual(incomplete.count, 4)

    def test_stored_fixed_dynamic_empty_and_optional_headers(self):
        plain = b"abcABC\x00\xff\x10" * 20
        dynamic_plain = b"dddd" * 40
        dynamic_co = zlib.compressobj(9, zlib.DEFLATED, -15)
        dynamic_raw = dynamic_co.compress(dynamic_plain) + dynamic_co.flush()
        dynamic_body = gzip_wrap(dynamic_raw) + \
            zlib.crc32(dynamic_plain).to_bytes(4, "little") + \
            len(dynamic_plain).to_bytes(4, "little")
        cases = [
            gzip_member(plain, 0),
            gzip_member(plain, 1),
            dynamic_body,
            gzip_member(b"", 0),
            gzip_member(plain, 1, flags=4, extra=b"x" * 17),
            gzip_member(plain, 1, flags=8, name="中文名称".encode("utf-8")),
            gzip_member(plain, 1, flags=16, comment=b"note"),
            gzip_member(plain, 1, flags=2),
        ]
        for number, body in enumerate(cases):
            with self.subTest(number=number):
                idx = self.dir / f"i{number}.sqlite"
                build_index(self.db if self.db.exists() else self.db, "p",
                            f"e{number}", idx, self.config) if False else None
        make_source_db(self.db, {
            ("p", f"e{number}"): body for number, body in enumerate(cases)
        })
        for number, body in enumerate(cases):
            expected = gzip.decompress(body)
            idx = self.dir / f"i{number}.sqlite"
            build_index(self.db, "p", f"e{number}", idx, self.config)
            if number == 0:
                stored_rows = sqlite3.connect(idx).execute(
                    "SELECT state_json FROM checkpoints WHERE output_offset > 0"
                ).fetchall()
                stored_states = [json.loads(row[0]) for row in stored_rows]
                self.assertTrue(stored_states)
                self.assertTrue(all(s["block_type"] == 0 for s in stored_states))
                self.assertTrue(
                    any(s["stored_bytes_remaining"] > 0 for s in stored_states)
                )
            verify_index(self.db, idx)
            out = self.dir / f"o{number}.bin"
            stats = extract_range(
                self.db, "p", f"e{number}", idx, 0, len(expected), out,
            )
            got = out.read_bytes()
            self.assertEqual(got, expected)
            self.assertEqual(stats["resume_checkpoint"], 0)

    def test_multi_member_cross_member_and_cross_block(self):
        first = b"first-member-" * 50
        second = ("中文第二成员-" * 60).encode("utf-8") + bytes(range(256)) * 4
        third = gzip_member(b"third-stored-block" * 10, 0)
        body = gzip_member(first, 0) + gzip.compress(second, compresslevel=9,
                                                      mtime=0) + third
        expected = gzip.decompress(body)
        stats = self.build(body)
        self.assertEqual(stats["member_count"], 3)
        verify_index(self.db, self.index)
        # End exactly on a member boundary, then start at the same boundary.
        boundary = len(first)
        out = self.dir / "boundary-end.bin"
        extract_range(self.db, "p", "e", self.index, boundary - 10, 10, out)
        self.assertEqual(out.read_bytes(), expected[boundary - 10:boundary])
        out = self.dir / "boundary-start.bin"
        extract_range(self.db, "p", "e", self.index, boundary, 10, out)
        self.assertEqual(out.read_bytes(), expected[boundary:boundary + 10])
        third_start = len(first) + len(second)
        out = self.dir / "third-boundary.bin"
        extract_range(
            self.db, "p", "e", self.index, third_start - 12, 24, out
        )
        self.assertEqual(out.read_bytes(),
                         expected[third_start - 12:third_start + 12])
        start = len(first) + 20
        got, extract_stats = self.extract(start, 80, "cross.bin")
        self.assertEqual(got, expected[start:start + 80])
        self.assertLessEqual(extract_stats["resume_checkpoint"], start)
        self.assertLessEqual(extract_stats["resume_checkpoint"], len(first))
        self.assertLessEqual(extract_stats["bytes_decoded"],
                             self.config.spacing + 80 + 514)

    def test_overlapping_back_references_and_window_wrap(self):
        pattern = bytes((i * 37 + 11) & 0xff for i in range(512))
        plain = pattern + pattern[:100] + b"Z" * (WINDOW_SIZE * 2 + 100)
        body = gzip.compress(plain, compresslevel=9, mtime=0)
        # The reference decoder is the source of expected bytes.
        self.assertEqual(gzip.decompress(body), plain)
        self.build(body)
        for start in (0, 1, WINDOW_SIZE - 3, WINDOW_SIZE,
                      len(plain) - 50):
            for length in (1, 7, 100):
                if start + length > len(plain):
                    continue
                out = self.dir / f"o-{start}-{length}"
                extract_range(self.db, "p", "e", self.index, start,
                              length, out)
                got = out.read_bytes()
                self.assertEqual(got, plain[start:start + length])
        # Explicit boundaries inside overlapping length/distance copies:
        # the long Z run is emitted as repeated overlapping back-references.
        z_start = len(pattern) + 100
        for start, length in (
            (z_start + 1, 1),
            (z_start + 10, 5),
            (z_start + WINDOW_SIZE, 3),
            (z_start + WINDOW_SIZE + 7, 11),
        ):
            out = self.dir / f"copy-{start}-{length}"
            extract_range(self.db, "p", "e", self.index, start, length, out)
            self.assertEqual(out.read_bytes(), plain[start:start + length])

    def test_range_endpoints_zero_and_rejections(self):
        plain = b"0123456789" * 100
        self.build(gzip_member(plain, 1))
        got, stats = self.extract(0, 0, "zero.bin")
        self.assertEqual(got, b"")
        self.assertEqual(stats["output_bytes"], 0)
        got, _ = self.extract(len(plain), 0, "end.bin")
        self.assertEqual(got, b"")
        for start, length in ((-1, 1), (0, -1), (len(plain) + 1, 0),
                              (len(plain), 1), (0, len(plain) + 1)):
            with self.assertRaises(GzipIndexError):
                extract_range(self.db, "p", "e", self.index, start, length,
                              self.dir / f"bad-{start}-{length}")

    def test_source_database_remains_unchanged(self):
        body = gzip_member(b"read-only source" * 100, 1)
        make_source_db(self.db, {("p", "e"): body})
        before = self.db.read_bytes()
        build_index(self.db, "p", "e", self.index, self.config)
        out = self.dir / "range.bin"
        extract_range(self.db, "p", "e", self.index, 10, 20, out)
        verify_index(self.db, self.index)
        self.assertEqual(self.db.read_bytes(), before)

    def test_partner_event_identity_and_no_overwrite(self):
        body = gzip_member(b"same event id", 1)
        make_source_db(self.db, {("p1", "same"): body, ("p2", "same"): body})
        idx1 = self.dir / "p1.sqlite"
        build_index(self.db, "p1", "same", idx1, self.config)
        with self.assertRaises(GzipIndexError):
            extract_range(self.db, "p2", "same", idx1, 0, 1,
                          self.dir / "wrong.bin")
        with self.assertRaises(GzipIndexError):
            build_index(self.db, "p1", "same", idx1, self.config)
        failed_out = self.dir / "failed-extract.bin"
        with self.assertRaises(GzipIndexError):
            extract_range(self.db, "p1", "same", idx1,
                          len(b"same event id") + 1, 1, failed_out)
        self.assertFalse(failed_out.exists())
        with self.assertRaises(GzipIndexError):
            extract_range(self.db, "p1", "same", idx1, 0, 1,
                          self.dir / "missing-dir" / "x.bin")
        out = self.dir / "exists.bin"
        out.write_bytes(b"x")
        with self.assertRaises(GzipIndexError):
            extract_range(self.db, "p1", "same", idx1, 0, 1, out)

    def test_invalid_gzip_framing_and_trailers(self):
        plain = b"hello" * 20
        good = bytearray(gzip_member(plain, 1))
        corruptions = {
            "magic": (0, 0),
            "reserved_flags": (3, 0xe0),
            "crc": (len(good) - 8, 0xff),
            "isize": (len(good) - 1, 0xff),
        }
        for label, mutation in corruptions.items():
            bad = bytearray(good)
            if mutation is None and label == "truncated":
                bad = bad[:-1]
            elif mutation is None:
                bad += b"extra"
            else:
                bad[mutation[0]] = mutation[1]
            db = self.dir / f"{label}.db"
            idx = self.dir / f"{label}.idx"
            make_source_db(db, {("p", "e"): bytes(bad)})
            with self.assertRaises((GzipIndexError, DeflateError)):
                build_index(db, "p", "e", idx, self.config)
            self.assertFalse(idx.exists())
        for label, bad in (
            ("truncated", bytes(good)[:-1]),
            ("trailing", bytes(good) + b"extra"),
        ):
            db = self.dir / f"{label}.db"
            idx = self.dir / f"{label}.idx"
            make_source_db(db, {("p", "e"): bad})
            with self.assertRaises((GzipIndexError, DeflateError)):
                build_index(db, "p", "e", idx, self.config)
            self.assertFalse(idx.exists())
        bad_fhcrc = bytearray(gzip_member(plain, 1, flags=2))
        bad_fhcrc[10] ^= 0xff  # first FHCRC byte
        db = self.dir / "fhcrc.db"
        make_source_db(db, {("p", "e"): bytes(bad_fhcrc)})
        with self.assertRaises(GzipIndexError):
            build_index(db, "p", "e", self.dir / "fhcrc.idx", self.config)
        with self.assertRaises(GzipIndexError):
            make_source_db(self.dir / "zero.db", {("p", "e"): b""})
            build_index(self.dir / "zero.db", "p", "e",
                        self.dir / "zero.idx", self.config)

    def test_truncated_bit_stream_is_rejected(self):
        w = BitWriter()
        w.write(1, 1)
        w.write(1, 2)  # BFINAL fixed block with no literals and no EOB
        body = gzip_wrap(w.bytes()) + b"\x00" * 8
        db = self.dir / "truncated-bit.db"
        make_source_db(db, {("p", "e"): body})
        with self.assertRaises((TruncatedStream, DeflateError)):
            build_index(db, "p", "e", self.dir / "truncated-bit.idx",
                        self.config)

    def test_illegal_dynamic_code_table_is_rejected(self):
        # BFINAL dynamic block, HLIT=257, HDIST=1, HCLEN=4, then four
        # over-subscribed 7-bit code-length alphabet entries.
        w = BitWriter()
        w.write(1, 1)
        w.write(2, 2)
        w.write(0, 5)
        w.write(0, 5)
        w.write(0, 4)  # HCLEN = 4
        for _ in range(4):
            w.write(7, 3)
        body = gzip_wrap(w.bytes()) + b"\x00" * 8
        db = self.dir / "bad-dynamic.db"
        make_source_db(db, {("p", "e"): body})
        with self.assertRaises(DeflateError):
            build_index(db, "p", "e", self.dir / "bad-dynamic.idx",
                        self.config)

    def test_illegal_deflate_streams(self):
        # Reserved block type 3.
        w = BitWriter()
        w.write(1, 1)
        w.write(3, 2)
        body = gzip_member(b"", 1)
        reserved = gzip_wrap(w.bytes()) + b"\x00" * 8
        db = self.dir / "reserved.db"
        make_source_db(db, {("p", "e"): reserved})
        with self.assertRaises(DeflateError):
            build_index(db, "p", "e", self.dir / "reserved.idx", self.config)
        # Distance with no history: fixed block symbol 257 then distance 0.
        w = BitWriter()
        w.write(1, 1)
        w.write(1, 2)
        # Fixed canonical code for length symbol 257 is binary 0000001 (7 bits).
        # Bytes are consumed LSB-first, so transmit its reversal 1000000.
        w.write(0b1000000, 7)
        w.write(0, 5)  # distance code 0 means distance 1, but no history exists
        no_history = gzip_wrap(w.bytes()) + b"\x00" * 8
        db = self.dir / "distance.db"
        make_source_db(db, {("p", "e"): no_history})
        with self.assertRaises(DeflateError):
            build_index(db, "p", "e", self.dir / "distance.idx", self.config)

    def test_long_single_dynamic_block_internal_checkpoints(self):
        # A highly repetitive payload gives zlib one long dynamic block.
        plain = (b"dynamic-block-pattern-" * 5000) + b"TAIL-1234567890"
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = compressor.compress(plain) + compressor.flush()
        self.assertEqual(raw[0] & 1, 1)  # one BFINAL DEFLATE block
        body = gzip_wrap(raw) + zlib.crc32(plain).to_bytes(4, "little") + \
            len(plain).to_bytes(4, "little")
        stats = self.build(body)
        rows = sqlite3.connect(self.index).execute(
            "SELECT state_json FROM checkpoints ORDER BY output_offset"
        ).fetchall()
        internal = [
            row for row, in rows
            if json.loads(row)["block_type"] == 2
        ]
        self.assertGreater(len(internal), 3)
        for offset in (1000, 5000, 20000, len(plain) - 40):
            got, extracted = self.extract(offset, 37, f"dyn-{offset}")
            self.assertEqual(got, plain[offset:offset + 37])
            self.assertLessEqual(
                extracted["bytes_decoded"],
                self.config.spacing + 37 + 514,
            )

    def test_random_ranges_fixed_seeds(self):
        rng = random.Random(20261115)
        for seed in range(8):
            data = bytes(rng.randrange(256) for _ in range(2000 + seed * 977))
            level = rng.choice((1, 6, 9))
            body = gzip.compress(data, compresslevel=level, mtime=seed)
            db = self.dir / f"rand-{seed}.db"
            idx = self.dir / f"rand-{seed}.idx"
            make_source_db(db, {("p", "e"): body})
            build_index(db, "p", "e", idx, Config.create(
                spacing=257 + seed * 31, max_output=10_000_000,
                max_optional_header=4096, tmp_dir=self.dir,
            ))
            for _ in range(12):
                start = rng.randrange(len(data) + 1)
                length = rng.randrange(len(data) - start + 1)
                out = self.dir / f"rand-{seed}-{start}-{length}.bin"
                got, stats = self.extract(
                    start, length,
                    name=f"rand-{seed}-{start}-{length}.bin",
                    index=idx,
                    db=db,
                )
                self.assertEqual(got, data[start:start + length])
                self.assertLessEqual(
                    stats["bytes_decoded"],
                    (257 + seed * 31) + length + 514,
                )

    def test_corrupt_page_local_vs_full_verify_evidence_boundary(self):
        rng = random.Random(99)
        plain = bytes(rng.randrange(256) for _ in range(200_000))
        body = gzip.compress(plain, 1, mtime=0)
        self.build(body)
        good_out = self.dir / "good.bin"
        stats = extract_range(self.db, "p", "e", self.index, 0, 20, good_out)
        self.assertEqual(good_out.read_bytes(), plain[:20])
        touched_page = next(iter(range(stats["pages_read"])))
        if len(body) <= PAGE_SIZE:
            self.skipTest("evidence-boundary case requires multiple pages")
        far_page = max(0, (len(body) // PAGE_SIZE) - 1)
        self.assertNotEqual(touched_page, far_page)

        corrupted = self.dir / "corrupt.db"
        import shutil
        shutil.copy(self.db, corrupted)
        conn = sqlite3.connect(corrupted)
        rowid = conn.execute(
            "SELECT rowid FROM raw_bodies WHERE body_sha256=?",
            (hashlib.sha256(body).hexdigest(),),
        ).fetchone()[0]
        blob_holder = conn.blobopen("raw_bodies", "body_blob", rowid)
        blob = bytearray(blob_holder.read())
        blob_holder.close()
        blob[far_page * PAGE_SIZE + 1] ^= 0x5a
        conn.execute("UPDATE raw_bodies SET body_blob=?", (bytes(blob),))
        conn.commit()
        conn.close()
        # Untouched local extraction still succeeds against the untouched page.
        local = self.dir / "local-after-corrupt.bin"
        extract_range(corrupted, "p", "e", self.index, 0, 20, local)
        got = local.read_bytes()
        self.assertEqual(got, plain[:20])
        with self.assertRaises(GzipIndexError):
            verify_index(corrupted, self.index)

    def test_checkpoint_corruption_fails_extract(self):
        self.build(gzip_member(b"x" * 1000, 1))
        corrupted = self.dir / "corrupt-index.sqlite"
        import shutil
        shutil.copy(self.index, corrupted)
        conn = sqlite3.connect(corrupted)
        row = conn.execute(
            "SELECT output_offset, state_json FROM checkpoints "
            "ORDER BY output_offset DESC LIMIT 1"
        ).fetchone()
        state = json.loads(row[1])
        state["bit_pos"] += 1
        conn.execute("UPDATE checkpoints SET state_json=? WHERE output_offset=?",
                     (json.dumps(state), row[0]))
        conn.commit()
        conn.close()
        with self.assertRaises(GzipIndexError):
            extract_range(self.db, "p", "e", corrupted, 900, 10,
                          self.dir / "should-not-exist")

    def test_cli_subprocess_new_process_and_stats(self):
        plain = "中文-zero-\x00-二进制".encode("utf-8") + bytes(range(256)) + b"TAIL"
        body = gzip.compress(plain * 100, 9, mtime=0)
        make_source_db(self.db, {("p", "e"): body})
        idx = self.dir / "cli.idx"
        out = self.dir / "cli.out"
        module = str(ROOT / "partner_webhook" / "gzip_index.py")
        commands = [
            [sys.executable, "-I", module, "build",
             "--source-db", str(self.db), "--partner-id", "p", "--event-id", "e",
             "--index", str(idx), "--spacing", "128"],
            [sys.executable, "-I", module, "extract",
             "--source-db", str(self.db), "--partner-id", "p", "--event-id", "e",
             "--index", str(idx), "--start", str(len(plain) * 100 - 32),
             "--length", "32", "--output", str(out)],
            [sys.executable, "-I", module, "verify",
             "--source-db", str(self.db), "--index", str(idx)],
        ]
        bad = [sys.executable, "-I", module, "extract",
               "--source-db", str(self.db), "--partner-id", "p", "--event-id", "e",
               "--index", str(idx), "--start", "-1", "--length", "1",
               "--output", str(self.dir / "bad-cli.out")]
        bad_proc = subprocess.run(bad, text=True, capture_output=True)
        self.assertNotEqual(bad_proc.returncode, 0)
        self.assertFalse((self.dir / "bad-cli.out").exists())

        env = dict(os.environ, PYTHONPATH=str(ROOT))
        for command in commands:
            proc = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                  capture_output=True, check=True)
            stats = json.loads(proc.stdout)
            self.assertIn("pages_read", stats)
            self.assertIn("compressed_bytes_read", stats)
        full_plain = plain * 100
        self.assertEqual(out.read_bytes(), full_plain[-32:])


if __name__ == "__main__":
    unittest.main()
