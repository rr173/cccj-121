"""离线合作方事件 Webhook 接入服务。

仅依赖 Python 标准库，包含：
- 协议规范化与 HMAC-SHA256 签名验证
- 多版本密钥（含生效/失效时间）管理
- SQLite 持久化（接收记录、事件去重/冲突隔离、投递 outbox、原始体）
- 本地 HTTP 收件服务、请求生成器与命令行查询接口
"""

__version__ = "1.0.0"
PROTOCOL_VERSION = "webhook-v1"
