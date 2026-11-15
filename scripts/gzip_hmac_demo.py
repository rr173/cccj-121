#!/usr/bin/env python3
"""End-to-end seekable gzip demonstration.

The event enters through the normal HMAC service path.  Index build, extract
and verify then run in separate Python processes, and the extracted bytes are
compared byte-for-byte with the standard-library gzip reference output.
"""

from __future__ import annotations

import gzip
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from partner_webhook.config import load_config  # noqa: E402
from partner_webhook.crypto import decode_secret, sign  # noqa: E402
from partner_webhook.service import PROTOCOL_VERSION, WebhookService  # noqa: E402
from partner_webhook.storage import Storage  # noqa: E402
from tests.helpers import FakeClock, PATH, b64  # noqa: E402
from partner_webhook.canonical import (  # noqa: E402
    HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER, HEADER_PROTOCOL,
    HEADER_SEQUENCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_bytes,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="seekable-gzip-demo-") as td:
        root = Path(td)
        db = root / "webhook.db"
        index = root / "seekable.sqlite"
        output = root / "tail.bin"
        config_path = root / "config.json"
        config_path.write_text(Path(ROOT, "config.example.json").read_text())

        # Chinese text, NULs, arbitrary binary bytes, and a recognizable tail.
        plain = (
            "合作方批量明细：中文、零字节与二进制混合。".encode("utf-8")
            + b"\x00\x00\xff\xfe\x01\x80"
            + bytes((i * 13) & 0xff for i in range(4096))
            + b"SEEKABLE-GZIP-TAIL-2026-" + "中文尾段".encode("utf-8")
        )
        body = gzip.compress(plain, compresslevel=9, mtime=0)
        expected = gzip.decompress(body)
        if expected != plain:
            raise RuntimeError("standard-library gzip reference mismatch")

        config = load_config(config_path)
        storage = Storage(db)
        service = WebhookService(config, storage, clock=FakeClock(2_000_000_000))
        partner = config.partner("globex")
        secret = decode_secret(partner.keys["g1"].secret_b64)
        canonical = canonical_bytes(
            method="POST", path=PATH, partner_id="globex", key_version="g1",
            timestamp=2_000_000_000, event_id="seekable-demo-001",
            sequence=42, body=body,
        )
        headers = {
            HEADER_PROTOCOL: PROTOCOL_VERSION,
            HEADER_PARTNER: "globex",
            HEADER_KEY_VERSION: "g1",
            HEADER_TIMESTAMP: "2000000000",
            HEADER_EVENT_ID: "seekable-demo-001",
            HEADER_SEQUENCE: "42",
            HEADER_SIGNATURE: sign(secret, canonical),
        }
        result = service.receive(method="POST", path=PATH,
                                 raw_headers=headers, body=body)
        storage.close()
        if result.result != "accepted":
            raise RuntimeError(f"HMAC acceptance failed: {result}")

        module = str(ROOT / "partner_webhook" / "gzip_index.py")
        commands = [
            [sys.executable, "-I", module, "build", "--source-db", str(db),
             "--partner-id", "globex", "--event-id", "seekable-demo-001",
             "--index", str(index), "--spacing", "256"],
        ]
        start = len(plain) - 48
        commands.append([
            sys.executable, "-I", module, "extract", "--source-db", str(db),
            "--partner-id", "globex", "--event-id", "seekable-demo-001",
            "--index", str(index), "--start", str(start), "--length", "48",
            "--output", str(output),
        ])
        commands.append([
            sys.executable, "-I", module, "verify", "--source-db", str(db),
            "--index", str(index),
        ])
        stats = []
        for command in commands:
            proc = subprocess.run(command, text=True, capture_output=True,
                                  check=True)
            stats.append(json.loads(proc.stdout))
        got = output.read_bytes()
        if got != plain[start:start + 48]:
            raise RuntimeError("extracted bytes do not match reference plaintext")
        print(json.dumps({
            "hmac_receive": {
                "result": result.result,
                "reason": result.reason,
                "http_status": result.http_status,
                "event_id": result.event_id,
            },
            "decompressed_size": len(plain),
            "range_start": start,
            "range_length": 48,
            "reference_match": got == expected[start:start + 48],
            "extracted_hex": got.hex(),
            "stats": stats,
        }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
