"""签名内容规范化（canonicalization）。

协议版本 webhook-v1 规定被签名内容为以下 9 个字段，以 ``\\n`` 拼接，
字段顺序固定，与 HTTP 头的传输顺序无关：

    webhook-v1
    <HTTP 方法，大写>
    <请求路径，不含 query string>
    <合作方 ID>
    <密钥版本>
    <Unix 秒级时间戳>
    <事件 ID>
    <合作方源序号>
    sha256=<原始字节体的 SHA-256 十六进制摘要>

关键点：签名覆盖的是**原始字节体**的哈希，因此载荷哪怕只差一个字节
（例如 JSON 空白符变化），规范化字符串都会不同，签名随即失效。
"""

from __future__ import annotations

import hashlib
from typing import Mapping

from . import PROTOCOL_VERSION

# 协议要求的请求头（规范化时从中取值）
HEADER_PROTOCOL = "X-Webhook-Protocol"
HEADER_PARTNER = "X-Partner-Id"
HEADER_KEY_VERSION = "X-Key-Version"
HEADER_TIMESTAMP = "X-Timestamp"
HEADER_EVENT_ID = "X-Event-Id"
HEADER_SEQUENCE = "X-Sequence"
HEADER_SIGNATURE = "X-Signature"

REQUIRED_HEADERS = (
    HEADER_PROTOCOL,
    HEADER_PARTNER,
    HEADER_KEY_VERSION,
    HEADER_TIMESTAMP,
    HEADER_EVENT_ID,
    HEADER_SEQUENCE,
    HEADER_SIGNATURE,
)


def body_digest(body: bytes) -> str:
    """计算原始字节体的 SHA-256 十六进制摘要。"""
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body 必须是原始字节 bytes")
    return hashlib.sha256(body).hexdigest()


def canonical_bytes(
    *,
    method: str,
    path: str,
    partner_id: str,
    key_version: str,
    timestamp: int,
    event_id: str,
    sequence: int,
    body: bytes,
) -> bytes:
    """按协议构造被签名的规范化字节串。

    所有入参先转成字符串再以 UTF-8 编码，保证合作方与本服务在不同
    语言/运行时下得到完全一致的字节序列。
    """
    fields = [
        PROTOCOL_VERSION,
        method.upper(),
        path,
        partner_id,
        key_version,
        str(int(timestamp)),
        event_id,
        str(int(sequence)),
        f"sha256={body_digest(body)}",
    ]
    return "\n".join(fields).encode("utf-8")


def headers_lower(headers: Mapping[str, str]) -> dict[str, str]:
    """把 HTTP 头统一成首字母大写形式，消除传输顺序/大小写差异。"""
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        normalized["-".join(part.capitalize() for part in name.split("-"))] = value
    return normalized
