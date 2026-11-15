"""Reproducible seekable-gzip benchmark.

Data generation and standard-library reference decompression run in a separate
process before measurement.  The measured build/extract child reports its own
peak RSS through resource.getrusage, so reference work is not charged to the
production implementation.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import resource
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from partner_webhook.gzip_index import Config, build_index, extract_range  # noqa: E402


def make_database(path: Path, body: bytes, size: int) -> None:
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
                 ("bench", "p", 1, "v1", digest, 1, 1, 1))
    conn.commit()
    conn.close()


def generate_only(args) -> None:
    rng_seed = 20261115 + args.size_mib
    # Mixed repetitive and binary content keeps back-references and literals.
    prefix = ("中文基准-zero-\x00-binary-".encode("utf-8") + bytes(range(256)))
    cycles = args.size_mib * 1024 * 1024 // len(prefix) + 1
    plain = (prefix * cycles)[:args.size_mib * 1024 * 1024]
    body = gzip.compress(plain, compresslevel=6, mtime=0)
    reference = gzip.decompress(body)
    if reference != plain:
        raise RuntimeError("standard-library reference mismatch")
    out = Path(args.artifact_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "plain.bin").write_bytes(plain)
    (out / "body.gz").write_bytes(body)
    (out / "reference.sha256").write_text(hashlib.sha256(plain).hexdigest())


def measure(args) -> None:
    out = Path(args.artifact_dir)
    plain = (out / "plain.bin").read_bytes()
    body = (out / "body.gz").read_bytes()
    db = out / f"source-{args.size_mib}m.db"
    index = out / f"index-{args.size_mib}m.sqlite"
    extracted = out / f"extract-{args.size_mib}m.bin"
    make_database(db, body, len(plain))
    config = Config.create(
        spacing=args.spacing,
        max_output=args.size_mib * 1024 * 1024 + 1024,
        max_optional_header=65536,
        tmp_dir=out,
    )
    started = time.perf_counter()
    build_stats = build_index(db, "p", "bench", index, config)
    build_elapsed = time.perf_counter() - started
    start = max(0, len(plain) - 256)
    started = time.perf_counter()
    extract_stats = extract_range(db, "p", "bench", index, start, 128,
                                  extracted)
    extract_elapsed = time.perf_counter() - started
    if extracted.read_bytes() != plain[start:start + 128]:
        raise RuntimeError("benchmark extraction mismatch")
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    report = {
        "size_mib": args.size_mib,
        "spacing": args.spacing,
        "build_seconds": round(build_elapsed, 6),
        "extract_seconds": round(extract_elapsed, 6),
        "peak_rss_kib": rusage.ru_maxrss,
        "build": build_stats,
        "extract": extract_stats,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--size-mib", type=int, required=True)
    gen.add_argument("--artifact-dir", required=True)
    gen.set_defaults(func=generate_only)
    run = sub.add_parser("measure")
    run.add_argument("--size-mib", type=int, required=True)
    run.add_argument("--artifact-dir", required=True)
    run.add_argument("--spacing", type=int, default=65536)
    run.set_defaults(func=measure)
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
