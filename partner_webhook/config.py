"""合作方与密钥配置。

配置为 JSON 文件，每个合作方可同时配置多个版本的密钥，密钥带
``not_before`` / ``not_after`` 生效时间窗，切换时让两个窗口重叠，
即可保证合法在途请求不丢失。

时间字段支持：
- 整数 Unix 秒；
- ISO-8601 UTC 字符串（``2026-11-14T00:00:00Z``，``Z`` 或 +00:00 结尾）；
- ``null`` 表示不限制对应边界。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value) -> int | None:
    """把配置里的时间值统一转成 Unix 秒；``None`` 原样返回。"""
    if value is None:
        return None
    if isinstance(value, bool):  # bool 是 int 的子类，显式拒绝
        raise ValueError("时间字段不能是布尔值")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    raise ValueError(f"无法解析时间值: {value!r}")


@dataclass(frozen=True)
class KeySpec:
    """一个密钥版本。"""

    version: str
    secret_b64: str
    not_before: int | None
    not_after: int | None

    def active_at(self, ts: int) -> bool:
        """该密钥在给定 Unix 秒是否处于生效窗口（边界包含）。"""
        if self.not_before is not None and ts < self.not_before:
            return False
        if self.not_after is not None and ts > self.not_after:
            return False
        return True


@dataclass(frozen=True)
class PartnerConfig:
    partner_id: str
    max_skew_seconds: int
    keys: dict[str, KeySpec] = field(default_factory=dict)

    def find_key(self, version: str, claimed_ts: int,
                 now_ts: int | None = None) -> tuple[KeySpec | None, str | None]:
        """按版本查找密钥，并检查生效窗口。

        双重检查，缺一不可：
        - 密钥在请求**声称时间** ``claimed_ts`` 已生效（覆盖在途请求：
          签名发生在切换瞬间，到达略晚也合法）；
        - 密钥在**当前验证时间** ``now_ts`` 仍未退役（防止过期签名被
          重新投递——密钥一旦过了 ``not_after``，旧签名一律拒绝）。

        返回 (密钥, 拒绝原因)；成功时拒绝原因为 None。
        """
        key = self.keys.get(version)
        if key is None:
            return None, "unknown_key_version"
        if not key.active_at(claimed_ts):
            return None, "key_expired"
        if now_ts is not None and not key.active_at(now_ts):
            return None, "key_expired"
        return key, None


@dataclass(frozen=True)
class AppConfig:
    path: str
    max_skew_seconds: int
    partners: dict[str, PartnerConfig]

    def partner(self, partner_id: str) -> PartnerConfig | None:
        return self.partners.get(partner_id)


def load_config(path: str | Path) -> AppConfig:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    default_skew = int(raw.get("max_skew_seconds", 300))
    partners: dict[str, PartnerConfig] = {}

    for item in raw.get("partners", []):
        pid = str(item["id"])
        keys: dict[str, KeySpec] = {}
        for key_item in item.get("keys", []):
            version = str(key_item["version"])
            if version in keys:
                raise ValueError(f"合作方 {pid} 的密钥版本 {version} 重复")
            keys[version] = KeySpec(
                version=version,
                secret_b64=str(key_item["secret_b64"]),
                not_before=parse_time(key_item.get("not_before")),
                not_after=parse_time(key_item.get("not_after")),
            )
        if not keys:
            raise ValueError(f"合作方 {pid} 至少需要一个密钥")
        partners[pid] = PartnerConfig(
            partner_id=pid,
            max_skew_seconds=int(item.get("max_skew_seconds", default_skew)),
            keys=keys,
        )

    if not partners:
        raise ValueError("配置中至少需要一个合作方")
    return AppConfig(
        path=str(path),
        max_skew_seconds=default_skew,
        partners=partners,
    )
