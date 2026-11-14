"""规范化字节差异与 HMAC 验证测试。"""

from __future__ import annotations

import unittest

from partner_webhook import PROTOCOL_VERSION
from partner_webhook.canonical import body_digest, canonical_bytes
from partner_webhook.crypto import decode_secret, sign, verify

from .helpers import b64


def make_canonical(body: bytes, *, path="/webhook/events", method="POST",
                   timestamp=100, sequence=5):
    return canonical_bytes(
        method=method, path=path, partner_id="acme", key_version="v1",
        timestamp=timestamp, event_id="evt-1", sequence=sequence, body=body,
    )


class CanonicalBytesTest(unittest.TestCase):

    def test_canonical_layout_matches_protocol(self):
        body = b'{"a":1}'
        canonical = make_canonical(body)
        text = canonical.decode("utf-8")
        lines = text.split("\n")
        self.assertEqual(lines, [
            PROTOCOL_VERSION,
            "POST",
            "/webhook/events",
            "acme",
            "v1",
            "100",
            "evt-1",
            "5",
            "sha256=" + body_digest(body),
        ])
        self.assertFalse(text.endswith("\n"))

    def test_body_whitespace_change_changes_canonical_bytes(self):
        # 语义相同但字节不同的两个 JSON 载荷，规范化结果必须不同
        c1 = make_canonical(b'{"a": 1}')
        c2 = make_canonical(b'{"a":1}')
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(body_digest(b'{"a": 1}'),
                            body_digest(b'{"a":1}'))

    def test_each_field_change_changes_canonical_bytes(self):
        base = make_canonical(b"x")
        variants = [
            make_canonical(b"x", path="/webhook/other"),
            make_canonical(b"x", method="PUT"),
            make_canonical(b"x", timestamp=101),
            make_canonical(b"x", sequence=6),
        ]
        for variant in variants:
            self.assertNotEqual(base, variant)

    def test_signature_roundtrip(self):
        canonical = make_canonical(b"hello")
        secret = decode_secret(b64("s3cret"))
        signature = sign(secret, canonical)
        self.assertTrue(verify(secret, canonical, signature))

    def test_tampered_signature_and_non_hex_rejected(self):
        canonical = make_canonical(b"hello")
        secret = decode_secret(b64("s3cret"))
        self.assertFalse(verify(secret, canonical, "0" * 64))
        self.assertFalse(verify(secret, canonical, "not-hex"))
        self.assertFalse(verify(secret, canonical, ""))

    def test_wrong_secret_fails(self):
        canonical = make_canonical(b"hello")
        signature = sign(decode_secret(b64("right")), canonical)
        self.assertFalse(verify(decode_secret(b64("wrong")), canonical,
                                signature))

    def test_secret_base64_roundtrip(self):
        self.assertEqual(decode_secret(b64("raw-bytes")), b"raw-bytes")
        # 非 base64 配置退化为原始字节
        self.assertEqual(decode_secret("plain"), b"plain")
