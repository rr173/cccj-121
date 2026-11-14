"""HMAC-SHA256 签名计算与恒定时间比较。"""

from __future__ import annotations

import base64
import hmac
import hashlib


def decode_secret(secret_b64: str) -> bytes:
    """解码配置中的 base64 密钥；若本身不是 base64 则按原始 UTF-8 字节处理。"""
    try:
        return base64.b64decode(secret_b64, validate=True)
    except (ValueError, TypeError):
        return secret_b64.encode("utf-8")


def sign(secret: bytes, canonical: bytes) -> str:
    """对规范化字节串计算 HMAC-SHA256，返回十六进制摘要。"""
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def verify(secret: bytes, canonical: bytes, signature_hex: str) -> bool:
    """使用 hmac.compare_digest 做恒定时间比较，防止时序侧信道。"""
    try:
        provided = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    expected = hmac.new(secret, canonical, hashlib.sha256).digest()
    return hmac.compare_digest(provided, expected)
