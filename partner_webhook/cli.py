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
  outbox-endpoint   登记/查看合作方固定接收地址（登记后不可原地更换）
  outbox-run        向已登记接收地址发送一轮 outbox（真实 HTTP，至少一次）
  outbox-queue      查看某合作方的投递队列与队首状态
  outbox-attempts   查看某事件的逐次尝试、人工重试与迟到回执记录
  outbox-retry      人工重试某永久失败事件（重新开始该轮退避计数）
  drain-outbox      已停用：旧入口会在未经远端确认时虚报成功，请用 outbox-run
  stats          汇总统计
  index-sync     从接收库（只读）同步本地 JSON 正文索引
  index-status   查看当前已发布索引代与跳过原因
  index-query    用 JSON 表达式在索引上查询（必填合作方）
  archive-sync   从接收库（只读）导入 seed/patch 来件并重算档案版本
  archive-document      查看一份档案的当前公布内容与采用事件链
  archive-dispositions  查看每条来件的处置（等待/分支/失败/阻断等）
  archive-revisions     查看一份档案的修订处置、分支候选与人工选择
  archive-select        按合作方/档案/修订号选择要采用的源事件
  archive-deselect      撤销某修订的人工选择
  log-install          为合作方安装可验证追加账本（纳入已有已接受事件）
  log-status           查看账本当前树长、根与叶数
  log-checkpoint       读取检查点（可指定旧 tree_size 重建旧前缀根）
  log-prove-inclusion  为指定检查点下的一条事件生成在账证明
  log-prove-consistency 为旧/新检查点生成前后追加关系证明
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
    """旧入口已停用：不得在未经远端确认时把积压标成 delivered。"""
    print(
        "drain-outbox 已停用：旧实现只改本地状态、不向远端发送，会虚报成功。\n"
        "请改用新入口：\n"
        "  1) partner-webhook outbox-endpoint --partner <合作方> --register <URL>\n"
        "  2) partner-webhook outbox-run --partner <合作方>\n"
        "  3) partner-webhook outbox-queue / outbox-attempts 查看结果\n"
        "  4) partner-webhook outbox-retry 人工重试永久失败事件",
        file=sys.stderr,
    )
    return 2


# --------------------------------------------------------------------- #
# 下游 HTTP 投递（真实发送工人）
# --------------------------------------------------------------------- #
def _delivery_clock(now: int | None):
    if now is None:
        return None
    return lambda: float(now)


def _open_delivery(args):
    """打开会执行迁移的 Storage（确保投递表存在），再建投递存储。"""
    from partner_webhook.outbound import DeliveryError, DeliveryWorker

    # Storage 构造函数执行迁移；随后关闭其连接，投递工人用自己的连接。
    storage = Storage(args.db)
    storage.close()
    try:
        return DeliveryWorker(
            args.db, clock=_delivery_clock(args.now),
            timeout=args.timeout, lease_seconds=args.lease_seconds,
            worker_id=args.worker_id,
        )
    except DeliveryError as exc:
        print(f"投递存储不可用: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


def cmd_outbox_endpoint(args) -> int:
    from partner_webhook.outbound import DeliveryError, DeliveryStore, validate_endpoint_url

    storage = Storage(args.db)
    storage.close()
    store = DeliveryStore(args.db)
    try:
        if args.register:
            now = args.now if args.now is not None else int(time.time())
            result = store.register_endpoint(args.partner, args.register, now)
            _print_json(result)
        elif args.list:
            endpoint = store.endpoint(args.partner)
            if endpoint is None:
                print(f"合作方 {args.partner} 尚未登记接收地址", file=sys.stderr)
                return 1
            _print_json(endpoint)
        else:
            print("请用 --register <URL> 或 --list", file=sys.stderr)
            return 2
    except DeliveryError as exc:
        print(f"接收地址操作被拒绝: {exc}", file=sys.stderr)
        return 2
    finally:
        store.close()
    return 0


def cmd_outbox_run(args) -> int:
    from partner_webhook.outbound import DeliveryError

    worker = _open_delivery(args)
    try:
        partners = [args.partner] if args.partner else worker.store.known_partners()
        if not partners:
            _print_json({"worker_id": worker.worker_id, "now": worker.now(),
                         "reports": []})
            print("没有未送达的 outbox 记录", file=sys.stderr)
            return 0
        reports = [worker.run_partner(p, max_attempts=args.max_attempts).as_dict()
                   for p in partners]
        _print_json({"worker_id": worker.worker_id,
                     "now": worker.now(), "reports": reports})
        return 0
    except DeliveryError as exc:
        print(f"投递运行失败: {exc}", file=sys.stderr)
        return 1
    finally:
        worker.close()


def cmd_outbox_queue(args) -> int:
    from partner_webhook.outbound import DeliveryError, DeliveryStore

    storage = Storage(args.db)
    storage.close()
    store = DeliveryStore(args.db)
    try:
        endpoint = store.endpoint(args.partner)
        rows = store.partner_queue(args.partner, limit=args.limit,
                                   now=args.now)
        _print_json({"partner_id": args.partner,
                     "endpoint": endpoint, "queue": rows})
    except DeliveryError as exc:
        print(f"队列读取失败: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


def cmd_outbox_attempts(args) -> int:
    from partner_webhook.outbound import DeliveryError, DeliveryStore

    storage = Storage(args.db)
    storage.close()
    store = DeliveryStore(args.db)
    try:
        result = store.event_attempts(args.partner, args.event_id)
        _print_json(result)
    except DeliveryError as exc:
        print(f"尝试记录读取失败: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


def cmd_outbox_retry(args) -> int:
    from partner_webhook.outbound import DeliveryError, DeliveryStore

    storage = Storage(args.db)
    storage.close()
    store = DeliveryStore(args.db)
    try:
        result = store.retry_permanent(
            args.partner, args.event_id,
            args.now if args.now is not None else int(time.time()),
            operator=args.operator,
        )
        _print_json(result)
    except DeliveryError as exc:
        print(f"人工重试被拒绝: {exc}", file=sys.stderr)
        return 2
    finally:
        store.close()
    return 0


def cmd_stats(args) -> int:
    _, storage = _build_service(args)
    try:
        _print_json(storage.stats())
    finally:
        storage.close()
    return 0


# --------------------------------------------------------------------- #
# 可验证追加账本
# --------------------------------------------------------------------- #
def _open_ledger(args):
    from partner_webhook.storage import Storage

    # 打开一次会执行迁移（确保账本表存在）；证明读取使用独立只读连接。
    storage = Storage(args.db)
    storage.close()


def _write_doc(path: str | None, doc: dict) -> None:
    from partner_webhook.merkle import dump_document

    text = dump_document(doc)
    if path:
        Path(path).write_text(text, encoding="utf-8")
        print(f"已写入 {path}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def _ledger_error(exc, code: str = "操作失败") -> int:
    print(f"{code}: {exc}", file=sys.stderr)
    return 2


def cmd_log_install(args) -> int:
    from partner_webhook.eventlog import LedgerError, install

    _open_ledger(args)
    try:
        result = install(db_path=args.db, partner_id=args.partner)
    except LedgerError as exc:
        return _ledger_error(exc, "安装被拒绝")
    except Exception as exc:
        return _ledger_error(exc, "安装失败")
    _print_json(result)
    return 0


def cmd_log_status(args) -> int:
    from partner_webhook.eventlog import LedgerError, log_status

    _open_ledger(args)
    try:
        _print_json(log_status(args.db, args.partner))
    except LedgerError as exc:
        return _ledger_error(exc, "账本不可用")
    except Exception as exc:
        return _ledger_error(exc, "账本不可用")
    return 0


def cmd_log_checkpoint(args) -> int:
    from partner_webhook.eventlog import LedgerError, read_checkpoint
    import partner_webhook.eventlog as eventlog

    _open_ledger(args)
    trace = eventlog.ReadTrace()
    try:
        checkpoint = read_checkpoint(args.db, args.partner,
                                     tree_size=args.tree_size, trace=trace)
    except LedgerError as exc:
        return _ledger_error(exc, "检查点不可用")
    _write_doc(args.out, checkpoint.as_dict())
    if args.show_reads:
        _print_json({"reads": trace.as_dict()})
    return 0


def cmd_log_prove_inclusion(args) -> int:
    import partner_webhook.eventlog as eventlog
    from partner_webhook.eventlog import LedgerError, prove_inclusion
    from partner_webhook.merkle import MerkleError

    _open_ledger(args)
    trace = eventlog.ReadTrace()
    try:
        checkpoint = eventlog.read_checkpoint(
            args.db, args.partner, tree_size=args.tree_size, trace=trace)
        proof = prove_inclusion(
            args.db, args.partner, checkpoint, args.event_id, trace=trace)
    except (MerkleError, LedgerError) as exc:
        return _ledger_error(exc, "在账证明不可用")
    except Exception as exc:
        return _ledger_error(exc, "在账证明失败")
    _write_doc(args.out, proof.as_dict())
    if args.show_reads:
        _print_json({"reads": trace.as_dict(),
                     "checkpoint": checkpoint.as_dict()})
    return 0


def cmd_log_prove_consistency(args) -> int:
    import partner_webhook.eventlog as eventlog
    from partner_webhook.eventlog import LedgerError, prove_consistency
    from partner_webhook.merkle import (
        MerkleError, load_json_document, parse_checkpoint,
    )

    _open_ledger(args)
    trace = eventlog.ReadTrace()
    try:
        old_doc = load_json_document(args.old_checkpoint, "旧检查点")
        new_doc = load_json_document(args.new_checkpoint, "新检查点")
        old = parse_checkpoint(old_doc, "旧检查点")
        new = parse_checkpoint(new_doc, "新检查点")
        proof = prove_consistency(args.db, args.partner, old, new,
                                  trace=trace)
    except (MerkleError, LedgerError) as exc:
        return _ledger_error(exc, "一致性证明不可用")
    except Exception as exc:
        return _ledger_error(exc, "一致性证明失败")
    _write_doc(args.out, proof.as_dict())
    if args.show_reads:
        _print_json({"reads": trace.as_dict()})
    return 0


# --------------------------------------------------------------------- #
# 本地 JSON 正文索引
# --------------------------------------------------------------------- #
def cmd_index_sync(args) -> int:
    from partner_webhook.indexstore import IndexError_, sync_index

    try:
        report = sync_index(
            source_db=args.db, index_db=args.index_db,
            simulate_crash_after_nodes=args.simulate_crash_after_nodes,
        )
    except IndexError_ as exc:
        print(f"索引同步失败: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # 同步失败：整代回滚，不输出半份报告
        print(f"索引同步失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_json(report.as_dict())
    return 0


def cmd_index_status(args) -> int:
    from partner_webhook.indexstore import IndexError_, index_status

    try:
        _print_json(index_status(args.index_db))
    except IndexError_ as exc:
        print(f"索引不可用: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"索引不可用: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


def _read_expression(args) -> str:
    if args.expr_file:
        return Path(args.expr_file).read_text(encoding="utf-8")
    if args.expr:
        return args.expr
    print("必须用 --expr 或 --expr-file 提供 JSON 查询表达式", file=sys.stderr)
    return None


def cmd_index_query(args) -> int:
    from partner_webhook.indexstore import IndexError_, connect_index
    from partner_webhook.query import (
        QueryError, parse_expression_text, run_query,
    )

    text = _read_expression(args)
    if text is None:
        return 2
    try:
        expr = parse_expression_text(text)
    except QueryError as exc:
        print(f"查询表达式非法: {exc}", file=sys.stderr)
        return 2
    try:
        conn = connect_index(args.index_db, read_only=True)
    except Exception as exc:
        print(f"索引库无法打开: {exc}", file=sys.stderr)
        return 1
    try:
        result = run_query(
            conn, partner_id=args.partner, expr=expr,
            limit=args.limit, offset=args.offset,
        )
        _print_json({
            "partner_id": result.partner_id,
            "generation": result.generation,
            "total": result.total,
            "limit": result.limit,
            "offset": result.offset,
            "events": result.events,
        })
    except (QueryError, IndexError_) as exc:
        print(f"查询失败: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # 任何异常都不输出半份结果
        print(f"查询失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0


# --------------------------------------------------------------------- #
# 设备档案加工管线（独立 SQLite 加工库）
# --------------------------------------------------------------------- #
def _print_archive(obj) -> None:
    from partner_webhook.docarchive import ExactNumber, dumps_plain

    def walk(node):
        if isinstance(node, ExactNumber):
            return node
        if isinstance(node, dict):
            return {key: walk(item) for key, item in node.items()}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    sys.stdout.write(dumps_plain(walk(obj)))
    sys.stdout.write("\n")


def cmd_archive_sync(args) -> int:
    from partner_webhook.docarchive import sync_archive

    try:
        report = sync_archive(
            source_db=args.db, archive_db=args.archive_db,
            simulate_crash_before_commit=args.simulate_crash_before_commit,
        )
    except Exception as exc:  # 同步失败整体回滚，不输出半份报告
        print(f"档案同步失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_json(report.as_dict())
    return 0


def cmd_archive_document(args) -> int:
    from partner_webhook.docarchive import get_current_document

    try:
        result = get_current_document(args.archive_db, args.partner,
                                      args.document_id)
    except Exception as exc:
        print(f"档案读取失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_archive(result)
    return 0


def cmd_archive_dispositions(args) -> int:
    from partner_webhook.docarchive import list_dispositions

    try:
        rows = list_dispositions(args.archive_db,
                                 partner_id=args.partner,
                                 document_id=args.document_id)
    except Exception as exc:
        print(f"处置读取失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_json(rows)
    return 0


def cmd_archive_revisions(args) -> int:
    from partner_webhook.docarchive import list_revisions

    try:
        result = list_revisions(args.archive_db, args.partner, args.document_id)
    except Exception as exc:
        print(f"修订读取失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_json(result)
    return 0


def cmd_archive_select(args) -> int:
    from partner_webhook.docarchive import ArchiveError, select_revision

    try:
        result = select_revision(
            archive_db=args.archive_db, partner_id=args.partner,
            document_id=args.document_id, revision=args.revision,
            event_id=args.event_id,
        )
    except ArchiveError as exc:
        # 错误选择不改任何状态：退出码 2，原因写 stderr。
        print(f"选择被拒绝: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"选择失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_json(result)
    return 0


def cmd_archive_deselect(args) -> int:
    from partner_webhook.docarchive import ArchiveError, deselect_revision

    try:
        result = deselect_revision(
            archive_db=args.archive_db, partner_id=args.partner,
            document_id=args.document_id, revision=args.revision,
        )
    except ArchiveError as exc:
        print(f"撤销被拒绝: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"撤销失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    _print_json(result)
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

    p_drain = sub.add_parser("drain-outbox",
                             help="已停用（不向远端发送，会虚报成功；请用 outbox-run）")
    p_drain.add_argument("--batch", type=int, default=100,
                         help="已停用，参数仅为兼容而保留")
    p_drain.set_defaults(func=cmd_drain)

    p_ep = sub.add_parser("outbox-endpoint",
                          help="登记/查看合作方固定接收地址（不可原地更换）")
    p_ep.add_argument("--partner", required=True)
    p_ep.add_argument("--register", default=None, help="登记接收地址 URL")
    p_ep.add_argument("--list", action="store_true", help="查看已登记地址")
    p_ep.add_argument("--now", type=int, default=None,
                      help="显式当前 Unix 秒（测试用）")
    p_ep.set_defaults(func=cmd_outbox_endpoint)

    p_run = sub.add_parser("outbox-run", help="向已登记地址发送一轮 outbox")
    p_run.add_argument("--partner", default=None,
                       help="只处理该合作方；省略则处理所有有积压的合作方")
    p_run.add_argument("--max-attempts", type=int, default=20,
                       help="本轮该合作方的最大网络尝试数")
    p_run.add_argument("--timeout", type=float, default=10.0,
                       help="单请求超时秒数")
    p_run.add_argument("--lease-seconds", type=int, default=60,
                       help="持久占用到期秒数")
    p_run.add_argument("--worker-id", default=None,
                       help="工人标识（默认进程+随机）；两个进程可并发运行")
    p_run.add_argument("--now", type=int, default=None,
                       help="显式当前 Unix 秒（测试退避/占用用）")
    p_run.set_defaults(func=cmd_outbox_run)

    p_oq = sub.add_parser("outbox-queue", help="查看某合作方投递队列与队首状态")
    p_oq.add_argument("--partner", required=True)
    p_oq.add_argument("--limit", type=int, default=100)
    p_oq.add_argument("--now", type=int, default=None,
                      help="显式当前 Unix 秒（判断退避/占用是否到期）")
    p_oq.set_defaults(func=cmd_outbox_queue)

    p_oa = sub.add_parser("outbox-attempts", help="查看某事件的尝试与人工重试记录")
    p_oa.add_argument("--partner", required=True)
    p_oa.add_argument("--event-id", required=True)
    p_oa.set_defaults(func=cmd_outbox_attempts)

    p_or = sub.add_parser("outbox-retry", help="人工重试永久失败事件")
    p_or.add_argument("--partner", required=True)
    p_or.add_argument("--event-id", required=True)
    p_or.add_argument("--operator", default=None, help="操作者标识（审计留痕）")
    p_or.add_argument("--now", type=int, default=None)
    p_or.set_defaults(func=cmd_outbox_retry)

    sub.add_parser("stats", help="汇总统计").set_defaults(func=cmd_stats)

    # ---- 可验证追加账本 ----
    p_li = sub.add_parser(
        "log-install", help="为合作方安装/复核可验证追加账本")
    p_li.add_argument("--partner", required=True)
    p_li.set_defaults(func=cmd_log_install)

    p_ls = sub.add_parser("log-status", help="查看账本树长、根与叶数")
    p_ls.add_argument("--partner", default=None,
                      help="省略时列出所有已安装账本")
    p_ls.set_defaults(func=cmd_log_status)

    p_lc = sub.add_parser("log-checkpoint", help="读取检查点")
    p_lc.add_argument("--partner", required=True)
    p_lc.add_argument("--tree-size", type=int, default=None,
                      help="旧 tree_size；省略则读取当前检查点")
    p_lc.add_argument("--out", default=None, help="写入文件（省略输出到 stdout）")
    p_lc.add_argument("--show-reads", action="store_true",
                      help="额外输出节点读取计数")
    p_lc.set_defaults(func=cmd_log_checkpoint)

    p_lpi = sub.add_parser("log-prove-inclusion",
                           help="为指定检查点下的一条事件生成在账证明")
    p_lpi.add_argument("--partner", required=True)
    p_lpi.add_argument("--event-id", required=True)
    p_lpi.add_argument("--tree-size", type=int, default=None,
                       help="证明所用的旧 tree_size；省略则用当前树长")
    p_lpi.add_argument("--out", default=None)
    p_lpi.add_argument("--show-reads", action="store_true")
    p_lpi.set_defaults(func=cmd_log_prove_inclusion)

    p_lpc = sub.add_parser(
        "log-prove-consistency", help="为旧/新检查点生成一致性证明")
    p_lpc.add_argument("--partner", required=True)
    p_lpc.add_argument("--old-checkpoint", required=True)
    p_lpc.add_argument("--new-checkpoint", required=True)
    p_lpc.add_argument("--out", default=None)
    p_lpc.add_argument("--show-reads", action="store_true")
    p_lpc.set_defaults(func=cmd_log_prove_consistency)

    p_isync = sub.add_parser("index-sync", help="从接收库同步本地 JSON 正文索引")
    p_isync.add_argument("--index-db", required=True, help="索引库路径（与接收库分离）")
    p_isync.add_argument("--simulate-crash-after-nodes", action="store_true",
                         help="测试专用：节点已写入但未提交时强制结束进程")
    p_isync.set_defaults(func=cmd_index_sync)

    p_istatus = sub.add_parser("index-status", help="查看索引代与跳过原因")
    p_istatus.add_argument("--index-db", required=True)
    p_istatus.set_defaults(func=cmd_index_status)

    p_iquery = sub.add_parser("index-query", help="用 JSON 表达式查询正文索引")
    p_iquery.add_argument("--index-db", required=True)
    p_iquery.add_argument("--partner", required=True,
                          help="合作方筛选（必填，防止跨合作方泄露）")
    p_iquery.add_argument("--expr", default=None, help="JSON 查询表达式")
    p_iquery.add_argument("--expr-file", default=None,
                          help="从文件读取 JSON 查询表达式")
    p_iquery.add_argument("--limit", type=int, default=100)
    p_iquery.add_argument("--offset", type=int, default=0)
    p_iquery.set_defaults(func=cmd_index_query)

    # ---- 设备档案加工管线（加工库与接收库、正文索引完全分离） ----
    p_async = sub.add_parser(
        "archive-sync",
        help="从接收库（只读）导入 seed/patch 来件并重算档案版本")
    p_async.add_argument("--archive-db", required=True, help="档案加工库路径")
    p_async.add_argument("--simulate-crash-before-commit", action="store_true",
                         help="测试专用：档案已写入但未提交时强制结束进程")
    p_async.set_defaults(func=cmd_archive_sync)

    p_adoc = sub.add_parser("archive-document", help="查看一份档案的当前公布内容")
    p_adoc.add_argument("--archive-db", required=True)
    p_adoc.add_argument("--partner", required=True)
    p_adoc.add_argument("--document-id", required=True)
    p_adoc.set_defaults(func=cmd_archive_document)

    p_adisp = sub.add_parser("archive-dispositions", help="查看来件处置与原因")
    p_adisp.add_argument("--archive-db", required=True)
    p_adisp.add_argument("--partner", default=None)
    p_adisp.add_argument("--document-id", default=None)
    p_adisp.set_defaults(func=cmd_archive_dispositions)

    p_arev = sub.add_parser("archive-revisions",
                            help="查看一份档案的修订处置、分支与人工选择")
    p_arev.add_argument("--archive-db", required=True)
    p_arev.add_argument("--partner", required=True)
    p_arev.add_argument("--document-id", required=True)
    p_arev.set_defaults(func=cmd_archive_revisions)

    p_asel = sub.add_parser("archive-select",
                            help="按合作方/档案/修订号选择要采用的源事件")
    p_asel.add_argument("--archive-db", required=True)
    p_asel.add_argument("--partner", required=True)
    p_asel.add_argument("--document-id", required=True)
    p_asel.add_argument("--revision", type=int, required=True)
    p_asel.add_argument("--event-id", required=True)
    p_asel.set_defaults(func=cmd_archive_select)

    p_adesel = sub.add_parser("archive-deselect", help="撤销某修订的人工选择")
    p_adesel.add_argument("--archive-db", required=True)
    p_adesel.add_argument("--partner", required=True)
    p_adesel.add_argument("--document-id", required=True)
    p_adesel.add_argument("--revision", type=int, required=True)
    p_adesel.set_defaults(func=cmd_archive_deselect)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
