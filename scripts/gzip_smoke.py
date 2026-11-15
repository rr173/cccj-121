"""Development smoke fixtures for the production seekable gzip decoder."""
from __future__ import annotations

import gzip
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from partner_webhook.gzip_index import Config, build_index, extract_range, verify_index


def make_db(path: Path, body: bytes) -> None:
    import hashlib
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
    digest = hashlib.sha256(body).hexdigest()
    conn.execute("INSERT INTO raw_bodies VALUES(?,?,?,?)",
                 (digest, body, len(body), 1))
    conn.execute("INSERT INTO accepted_events VALUES(?,?,?,?,?,?,?,?)",
                 ("e1", "p1", 1, "v1", digest, 1, 1, 1))
    conn.commit()
    conn.close()


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    plain = (b"hello world " * 1000) + b"TAIL-BYTES-12345"
    body = gzip.compress(plain, compresslevel=1, mtime=0)
    db = root / "source.db"
    idx = root / "idx.sqlite"
    out = root / "out.bin"
    make_db(db, body)
    cfg = Config.create(spacing=512, max_output=10_000_000,
                        max_optional_header=4096, tmp_dir=root)
    print(build_index(db, "p1", "e1", idx, cfg))
    start = len(plain) - 20
    print(extract_range(db, "p1", "e1", idx, start, 20, out))
    got = out.read_bytes()
    print(got, got == plain[start:start + 20])
    print(verify_index(db, idx))
