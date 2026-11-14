"""本地请求生成器：模拟合作方按各自密钥签名并投递。

不连接真实外网，只做环回请求或直接在进程内调用服务，便于自动化测试。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping
from urllib import request as urlrequest
from urllib.error import HTTPError

from . import PROTOCOL_VERSION
from .canonical import (
    HEADER_EVENT_ID,
    HEADER_KEY_VERSION,
    HEADER_PARTNER,
    HEADER_PROTOCOL,
    HEADER_SEQUENCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_bytes,
)
from .crypto import decode_secret, sign

DEFAULT_PATH = "/webhook/events"


@dataclass
class SignedRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes


def build_signed_request(
    *,
    base_url: str,
    partner_id: str,
    key_version: str,
    secret_b64: str,
    event_id: str,
    sequence: int,
    timestamp: int,
    body: bytes,
    path: str = DEFAULT_PATH,
    method: str = "POST",
    extra_headers: Mapping[str, str] | None = None,
) -> SignedRequest:
    """按协议规范化被签名内容并计算 HMAC，返回完整请求对象。"""
    canonical = canonical_bytes(
        method=method, path=path, partner_id=partner_id,
        key_version=key_version, timestamp=timestamp,
        event_id=event_id, sequence=sequence, body=body,
    )
    signature = sign(decode_secret(secret_b64), canonical)
    headers = {
        HEADER_PROTOCOL: PROTOCOL_VERSION,
        HEADER_PARTNER: partner_id,
        HEADER_KEY_VERSION: key_version,
        HEADER_TIMESTAMP: str(timestamp),
        HEADER_EVENT_ID: event_id,
        HEADER_SEQUENCE: str(sequence),
        HEADER_SIGNATURE: signature,
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    return SignedRequest(method, base_url.rstrip("/") + path, headers, body)


def send(signed: SignedRequest, timeout: float = 5.0) -> tuple[int, bytes]:
    """通过环回 HTTP 发送请求，返回 (状态码, 响应体)。"""
    req = urlrequest.Request(
        signed.url, data=signed.body, headers=signed.headers,
        method=signed.method,
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except HTTPError as exc:  # 4xx/409 也作为正常结果返回
        return exc.code, exc.read()


def json_body(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
