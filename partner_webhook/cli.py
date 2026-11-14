"""命令行入口。

子命令：
  init-db        建库并执行迁移
  serve          启动本地环回 HTTP 收件服务
  send           本地请求生成器：签名并投递一个事件
  query          按合作方与时间段查询接收流水（含拒绝原因）
  events         查询已接受事件（按合作方源序号排序）
  record         查看单条接收记录
  body           按记录导出可重放的原始字节体
  replay-event   用保存的原始体与头重新投递（支持模拟时间）
  drain-outbox   把待投递 outbox 标记为已投递（下游占位实现）
  stats          汇总统计
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# 支持直接以脚本路径运行（python /path/to/cli.py）：把仓库根目录加入
# sys.path 后退回绝对导入；作为包模块运行时走正常相对导入。
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from partner_webhook.canonical import (  # noqa: E402
        HEADER_SIGNATURE, HEADER_TIMESTAMP, headers_lower,
    )
    from partner_webhook.config import load_config  # noqa: E402
    from partner_webhook.generator import (  # noqa: E402
        DEFAULT_PATH, build_signed_request, send,
    )
    from partner_webhook.server import LocalWebhookServer  # noqa: E402
    from partner_webhook.service import WebhookService  # noqa: E402
    from partner_webhook.storage import Storage  # noqa: E402
else:
    from .canonical import HEADER_SIGNATURE, HEADER_TIMESTAMP, headers_lower
    from .config import load_config
    from .generator import DEFAULT_PATH, build_signed_request, send
    from .server import LocalWebhookServer
    from .service import WebhookService
    from .storage import Storage


def _print_json(obj) -> None:
    json.dump(obj, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")


def _row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


def _parse_bound(value: str | None) -> int | None:
    if value is None:
        return None
    if value.lstrip("-").isdigit():
        return int(value)
    from partner_webhook.config import parse_time
    return parse_time(value)


def cmd_init_db(args) -> int:
    Storage(args.db)  # 构造时自动迁移
    print(f"数据库已初始化并完成迁移: {args.db}")
    return 0


def _build_service(args, clock=None) -> tuple[WebhookService, Storage]:
    config = load_config(args.config)
    storage = Storage(args.db)
    return WebhookService(config, storage, clock=clock), storage


def cmd_serve(args) -> int:
    service, storage = _build_service(args)
    server = LocalWebhookServer(service, host=args.host, port=args.port,
                                path=args.path)
    address = server.start()
    print(f"Webhook 收件服务已启动: {address}{args.path}")
    print("按 Ctrl+C 停止")
    try:
        server.thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        storage.close()
    return 0


def cmd_send(args) -> int:
    config = load_config(args.config)
    partner = config.partner(args.partner)
    if partner is None:
        print(f"未知合作方: {args.partner}", file=sys.stderr)
        return 2
    key = partner.keys.get(args.key_version)
    if key is None:
        print(f"未知密钥版本: {args.key_version}", file=sys.stderr)
        return 2

    if args.body_file:
        body = Path(args.body_file).read_bytes()
    elif args.body:
        body = args.body.encode("utf-8")
    else:
        body = json.dumps({"demo": True}, ensure_ascii=False).encode("utf-8")

    ts = args.timestamp if args.timestamp is not None else int(time.time())
    ts += args.ts_offset
    signed = build_signed_request(
        base_url=args.url, partner_id=args.partner,
        key_version=args.key_version, secret_b64=key.secret_b64,
        event_id=args.event_id, sequence=args.sequence, timestamp=ts,
        body=body, path=args.path,
    )
    if args.badge:  # 演示篡改：故意破坏签名
        signed.headers[HEADER_SIGNATURE] = "0" * 64
    if args.print_canonical:
        from partner_webhook.canonical import canonical_bytes
        canonical = canonical_bytes(
            method="POST", path=args.path, partner_id=args.partner,
            key_version=args.key_version, timestamp=ts,
            event_id=args.event_id, sequence=args.sequence, body=body,
        )
        sys.stderr.write("---- 规范化被签名内容 ----\n")
        sys.stderr.write(canonical.decode("utf-8") + "\n")
        sys.stderr.write("--------------------------\n")
    status, resp = send(signed)
    print(f"HTTP {status}")
    print(resp.decode("utf-8", errors="replace"))
    return 0 if status < 500 else 1


def cmd_query(args) -> int:
    _, storage = _build_service(args)
    try:
        rows = storage.query_records(
            partner_id=args.partner,
            start_ts=_parse_bound(args.start),
            end_ts=_parse_bound(args.end),
            result=args.result,
            limit=args.limit,
        )
        _print_json([_row_to_dict(r) for r in rows])
    finally:
        storage.close()
    return 0


def cmd_events(args) -> int:
    _, storage = _build_service(args)
    try:
        rows = storage.list_events(
            partner_id=args.partner,
            start_ts=_parse_bound(args.start),
            end_ts=_parse_bound(args.end),
            limit=args.limit,
        )
        _print_json([_row_to_dict(r) for r in rows])
    finally:
        storage.close()
    return 0


def cmd_record(args) -> int:
    _, storage = _build_service(args)
    try:
        row = storage.get_record(args.record_id)
        if row is None:
            print(f"记录不存在: {args.record_id}", file=sys.stderr)
            return 1
        data = _row_to_dict(row)
        data["headers"] = json.loads(data["headers_json"])
        _print_json(data)
    finally:
        storage.close()
    return 0


def cmd_body(args) -> int:
    _, storage = _build_service(args)
    try:
        row = storage.get_record(args.record_id)
        if row is None:
            print(f"记录不存在: {args.record_id}", file=sys.stderr)
            return 1
        if not row["body_sha256"]:
            print("该记录没有保存原始体", file=sys.stderr)
            return 1
        body = storage.get_raw_body(row["body_sha256"])
        if args.output:
            Path(args.output).write_bytes(body)
            print(f"已导出 {len(body)} 字节 -> {args.output}")
        else:
            sys.stdout.buffer.write(body)
        return 0
    finally:
        storage.close()


def cmd_replay(args) -> int:
    config = load_config(args.config)
    storage = Storage(args.db)
    try:
        row = storage.get_record(args.record_id)
        if row is None:
            print(f"记录不存在: {args.record_id}", file=sys.stderr)
            return 1
        body = storage.get_raw_body(row["body_sha256"])
        headers = headers_lower(json.loads(row["headers_json"]))
        headers.pop("_detail", None)

        # 重放时钟（验证时刻）：
        # - --now 显式指定当前 Unix 秒（测试/时间模拟用），优先级最高；
        # - --at claimed 把验证时刻固定为原请求声称时间；
        # - 否则使用真实墙钟。
        if args.now is not None:
            verify_now = args.now
        elif args.at == "claimed":
            verify_now = row["claimed_timestamp"]
        else:
            verify_now = int(time.time())
        clock = lambda: verify_now  # noqa: E731
        service = WebhookService(config, storage, clock=clock)

        # 计算重放使用的有效时间戳：
        # - --refresh-timestamp：刷新为验证时刻（密钥交接后重放的标准做法）；
        # - --ts-offset：在原声称时间上叠加偏移（时间窗边界测试）；
        # - 默认沿用原声称时间（纯原始重放）。
        if args.refresh_timestamp:
            effective_ts = verify_now
        elif args.ts_offset:
            effective_ts = row["claimed_timestamp"] + args.ts_offset
        else:
            effective_ts = row["claimed_timestamp"]

        # 重新签名（密钥轮换后可用 --key-version 切换到新密钥）
        partner_id = row["partner_id"]
        partner = config.partner(partner_id)
        key_version = args.key_version or row["key_version"]
        key = partner.keys[key_version]
        from partner_webhook.canonical import canonical_bytes
        from partner_webhook.crypto import decode_secret, sign
        canonical = canonical_bytes(
            method="POST", path=args.path, partner_id=partner_id,
            key_version=key_version, timestamp=effective_ts,
            event_id=row["event_id"], sequence=row["source_seq"], body=body,
        )
        headers["X-Key-Version"] = key_version
        headers[HEADER_TIMESTAMP] = str(effective_ts)
        headers["X-Signature"] = sign(decode_secret(key.secret_b64), canonical)

        result = service.receive(
            method="POST", path=args.path, raw_headers=headers, body=body
        )
        _print_json({
            "result": result.result, "reason": result.reason,
            "http_status": result.http_status, "record_id": result.record_id,
        })
        return 0
    finally:
        storage.close()


def cmd_drain(args) -> int:
    _, storage = _build_service(args)
    try:
        delivered = []
        while True:
            pending = storage.pending_outbox(limit=args.batch)
            if not pending:
                break
            now = int(time.time())
            for item in pending:
                # 下游占位：真实部署时在此处把 body 投递给下游系统。
                # 按 source_seq 排序取出，乱序接收也能按源序号顺序下发。
                storage.mark_delivered(item["id"], now)
                delivered.append({"id": item["id"],
                                  "partner_id": item["partner_id"],
                                  "event_id": item["event_id"],
                                  "source_seq": item["source_seq"]})
        _print_json({"delivered": delivered, "count": len(delivered)})
    finally:
        storage.close()
    return 0


def cmd_stats(args) -> int:
    _, storage = _build_service(args)
    try:
        _print_json(storage.stats())
    finally:
        storage.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="partner-webhook",
        description="离线合作方事件 Webhook 接入服务",
    )
    parser.add_argument("--config", default="config.example.json",
                        help="合作方与密钥配置 JSON")
    parser.add_argument("--db", default="webhook.db", help="SQLite 数据库路径")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="建库并执行迁移").set_defaults(func=cmd_init_db)

    p_serve = sub.add_parser("serve", help="启动 HTTP 收件服务")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--path", default=DEFAULT_PATH)
    p_serve.set_defaults(func=cmd_serve)

    p_send = sub.add_parser("send", help="生成并发送一个签名事件")
    p_send.add_argument("--url", default="http://127.0.0.1:8080")
    p_send.add_argument("--partner", required=True)
    p_send.add_argument("--key-version", required=True)
    p_send.add_argument("--event-id", required=True)
    p_send.add_argument("--sequence", type=int, required=True)
    p_send.add_argument("--timestamp", type=int, default=None,
                        help="Unix 秒，默认当前时间")
    p_send.add_argument("--ts-offset", type=int, default=0,
                        help="在时间戳上叠加的偏移秒数（测时间窗用）")
    p_send.add_argument("--body", help="原始字符串载荷")
    p_send.add_argument("--body-file", help="从文件读取原始字节体")
    p_send.add_argument("--path", default=DEFAULT_PATH)
    p_send.add_argument("--badge", action="store_true",
                        help="故意发送错误签名（验证拒绝路径）")
    p_send.add_argument("--print-canonical", action="store_true",
                        help="把规范化被签名内容打印到 stderr")
    p_send.set_defaults(func=cmd_send)

    def add_query_args(p, with_result=False):
        p.add_argument("--partner", default=None)
        p.add_argument("--start", default=None, help="起始时间（Unix 秒或 ISO8601）")
        p.add_argument("--end", default=None, help="结束时间（Unix 秒或 ISO8601）")
        p.add_argument("--limit", type=int, default=100)
        if with_result:
            p.add_argument("--result", default=None,
                           choices=["accepted", "duplicate", "conflict", "rejected"])

    p_query = sub.add_parser("query", help="按合作方/时间段查询接收流水")
    add_query_args(p_query, with_result=True)
    p_query.set_defaults(func=cmd_query)

    p_events = sub.add_parser("events", help="查询已接受事件")
    add_query_args(p_events)
    p_events.set_defaults(func=cmd_events)

    p_record = sub.add_parser("record", help="查看单条接收记录")
    p_record.add_argument("record_id", type=int)
    p_record.set_defaults(func=cmd_record)

    p_body = sub.add_parser("body", help="导出记录保存的原始字节体")
    p_body.add_argument("record_id", type=int)
    p_body.add_argument("--output", default=None)
    p_body.set_defaults(func=cmd_body)

    p_replay = sub.add_parser("replay-event", help="用保存的原始体重放投递")
    p_replay.add_argument("record_id", type=int)
    p_replay.add_argument("--key-version", default=None,
                          help="重放时改用的密钥版本（验证密钥交接）")
    p_replay.add_argument("--at", choices=["now", "claimed"], default="now",
                          help="验证时钟：当前时间或原请求声称时间")
    p_replay.add_argument("--now", type=int, default=None,
                          help="显式指定当前 Unix 秒（测试/时间模拟用）")
    p_replay.add_argument("--refresh-timestamp", action="store_true",
                          help="把签名时间戳刷新为验证时刻（密钥交接后重放用）")
    p_replay.add_argument("--ts-offset", type=int, default=0)
    p_replay.add_argument("--path", default=DEFAULT_PATH)
    p_replay.set_defaults(func=cmd_replay)

    p_drain = sub.add_parser("drain-outbox", help="投递并清空待处理 outbox")
    p_drain.add_argument("--batch", type=int, default=100)
    p_drain.set_defaults(func=cmd_drain)

    sub.add_parser("stats", help="汇总统计").set_defaults(func=cmd_stats)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
