"""测试公共辅助：临时配置、固定时钟、签名投递。"""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from partner_webhook.canonical import (
    HEADER_EVENT_ID,
    HEADER_KEY_VERSION,
    HEADER_PARTNER,
    HEADER_PROTOCOL,
    HEADER_SEQUENCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_bytes,
)
from partner_webhook.config import load_config
from partner_webhook.crypto import decode_secret, sign
from partner_webhook.service import PROTOCOL_VERSION, WebhookService
from partner_webhook.storage import Storage

PATH = "/webhook/events"


class FakeClock:
    def __init__(self, value: int):
        self.value = value

    def __call__(self) -> float:
        return float(self.value)


def b64(raw: str) -> str:
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


class WebhookTestCase(unittest.TestCase):
    NOW = 2_000_000_000  # 固定的“当前时间”，避免依赖墙钟

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db_path = str(self.dir / "test.db")
        self.config_path = self.dir / "config.json"
        self.clock = FakeClock(self.NOW)

    def tearDown(self):
        if hasattr(self, "storage"):
            self.storage.close()
        self.tmp.cleanup()

    def write_config(self, partners: list[dict], default_skew: int = 300) -> str:
        doc = {"max_skew_seconds": default_skew, "partners": partners}
        self.config_path.write_text(
            json.dumps(doc, ensure_ascii=False), encoding="utf-8"
        )
        return str(self.config_path)

    def make_service(self) -> WebhookService:
        config = load_config(self.config_path)
        self.storage = Storage(self.db_path)
        return WebhookService(config, self.storage, clock=self.clock)

    def reopen_service(self) -> WebhookService:
        """模拟进程重启：关闭后重新打开同一数据库。"""
        self.storage.close()
        config = load_config(self.config_path)
        self.storage = Storage(self.db_path)
        return WebhookService(config, self.storage, clock=self.clock)

    def signed_headers(self, *, partner: str, key_version: str, secret: str,
                       event_id: str, sequence: int, timestamp: int,
                       body: bytes, bad_signature: bool = False,
                       shuffle: bool = False) -> dict[str, str]:
        canonical = canonical_bytes(
            method="POST", path=PATH, partner_id=partner,
            key_version=key_version, timestamp=timestamp,
            event_id=event_id, sequence=sequence, body=body,
        )
        signature = "0" * 64 if bad_signature else sign(
            decode_secret(b64(secret)), canonical
        )
        headers = {
            HEADER_PROTOCOL: PROTOCOL_VERSION,
            HEADER_PARTNER: partner,
            HEADER_KEY_VERSION: key_version,
            HEADER_TIMESTAMP: str(timestamp),
            HEADER_EVENT_ID: event_id,
            HEADER_SEQUENCE: str(sequence),
            HEADER_SIGNATURE: signature,
        }
        if shuffle:  # 故意打乱头的传输顺序与大小写
            items = list(headers.items())
            items.reverse()
            return {k.lower(): v for k, v in items}
        return headers

    def deliver(self, service: WebhookService, *, partner="acme",
                key_version="v1", secret="old-secret", event_id="evt-1",
                sequence=1, timestamp=None, body=b'{"a":1}',
                bad_signature=False, shuffle=False, method="POST", path=PATH):
        ts = self.NOW if timestamp is None else timestamp
        headers = self.signed_headers(
            partner=partner, key_version=key_version, secret=secret,
            event_id=event_id, sequence=sequence, timestamp=ts, body=body,
            bad_signature=bad_signature, shuffle=shuffle,
        )
        return service.receive(
            method=method, path=path, raw_headers=headers, body=body
        )
