"""可控下游接收器（标准库 http.server，仅监听本机）。

用于演练与验收：按手写计划对每个事件返回不同行为，并在接收端持久化
收到的原始字节、请求头和自己已落地的 ``delivery_key``。

行为计划（JSON）::

    {
      "default": [{"kind": "ok"}],
      "events": {
        "acme/evt-1": [{"kind": "429", "retry_after": "3"},
                       {"kind": "ok"}],
        "acme/evt-2": [{"kind": "disconnect_after_save"}, {"kind": "ok"}]
      }
    }

同一事件第 n 次请求使用列表第 n 项，超出后沿用最后一项。
``hold`` / ``disconnect_after_save`` 可用 ``wait_seconds`` 指定门控等待上限
（默认 3600 秒；测试里会显式设为很短的值，避免长时间睡眠）。

支持的行为：

- ``ok``                   保存业务记录并返回匹配回执
- ``ok_wrong_sha``         200 + 回执中的 body_sha256 错误
- ``empty``                200 + 空响应体
- ``not_json``             200 + 非 JSON 文本
- ``duplicate_key``        200 + 回执含重复字段
- ``huge``                 200 + 超过 64KiB 的响应体
- ``429`` / ``status``     指定状态码（``retry_after`` 可选）
- ``redirect``             3xx + Location
- ``disconnect_after_save`` 先落地业务记录，再主动断开连接（不回 HTTP）
- ``hold``                 先落地业务记录，等待控制接口放行后才回执

重复 ``delivery_key``：若已存在业务记录，一律返回**已有记录**的回执，
不新增业务记录（模拟下游按稳定键去重）。

控制接口（仅本机）::

    POST /__control/release  {"gate": "名称"}  放行等待中的请求
    POST /__control/release  {"gate": "*"}     放行全部
    GET  /__control/state                      查看计数/记录/等待门

用法::

    python3 -I partner_webhook/receiver.py --port 0 --dir 输出目录 [--plan 计划.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

HEADER_PARTNER = "X-Partner-Id"
HEADER_EVENT_ID = "X-Event-Id"
HEADER_SOURCE_SEQ = "X-Source-Seq"
HEADER_BODY_SHA256 = "X-Body-Sha256"
HEADER_DELIVERY_KEY = "X-Delivery-Key"


class ReceiverState:
    """接收端状态：请求日志、业务记录、门控。线程安全。"""

    def __init__(self, workdir: Path, plan: dict | None = None):
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        (self.workdir / "bodies").mkdir(exist_ok=True)
        self.plan = plan or {"default": [{"kind": "ok"}], "events": {}}
        self.lock = threading.RLock()
        self.gates: dict[str, threading.Event] = {}
        self.records: dict[str, dict] = {}
        self.request_counts: dict[str, int] = {}
        self.request_log: list[dict] = []
        self.next_record_id = 1
        # 测试可在接收器内部注入自己的假时间（生产默认真实墙钟）
        self.clock: Callable[[], float] = time.time
        self._log_file = (self.workdir / "requests.jsonl").open("a",
                                                                encoding="utf-8")
        self._load_records()

    # ------------------------------------------------------------------ #
    def _load_records(self) -> None:
        """重开进程时沿用已落地记录与键（同键仍返回已有结果）。"""
        path = self.workdir / "receiver_state.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.records = data.get("records", {})
            self.next_record_id = data.get("next_record_id", 1)

    def _persist(self) -> None:
        path = self.workdir / "receiver_state.json"
        tmp = path.with_suffix(".tmp")
        body = {
            "records": self.records,
            "next_record_id": self.next_record_id,
            "saved_at": time.time(),
        }
        tmp.write_text(json.dumps(body, ensure_ascii=False, indent=2,
                                  sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)

    # ------------------------------------------------------------------ #
    def behavior_for(self, partner_id: str, event_id: str) -> dict:
        events = self.plan.get("events", {})
        seq = events.get(f"{partner_id}/{event_id}")
        if seq is None:
            seq = self.plan.get("default", [{"kind": "ok"}])
        if not seq:
            seq = [{"kind": "ok"}]
        key = f"{partner_id}/{event_id}"
        with self.lock:
            index = self.request_counts.get(key, 0)
            self.request_counts[key] = index + 1
        return dict(seq[min(index, len(seq) - 1)])

    def gate(self, name: str) -> threading.Event:
        with self.lock:
            event = self.gates.get(name)
            if event is None:
                event = threading.Event()
                self.gates[name] = event
            return event

    def release(self, name: str) -> list[str]:
        with self.lock:
            names = list(self.gates) if name == "*" else [name]
            for n in names:
                self.gate(n).set()
            return names

    # ------------------------------------------------------------------ #
    def save_body(self, body: bytes) -> str:
        digest = hashlib.sha256(body).hexdigest()
        path = self.workdir / "bodies" / f"{digest}.bin"
        if not path.exists():
            path.write_bytes(body)
        return digest

    def save_record(self, delivery_key: str, *, partner_id: str,
                    event_id: str, source_seq: str, body_sha256: str,
                    byte_length: int) -> dict:
        """按稳定键去重：已存在就返回已有记录，不新建业务记录。"""
        with self.lock:
            existing = self.records.get(delivery_key)
            if existing is not None:
                return existing
            record = {
                "delivery_key": delivery_key,
                "partner_id": partner_id,
                "event_id": event_id,
                "source_seq": source_seq,
                "body_sha256": body_sha256,
                "byte_length": byte_length,
                "record_id": self.next_record_id,
                "first_received_at": self.clock(),
                "receipt": {
                    "delivery_key": delivery_key,
                    "body_sha256": body_sha256,
                    "record_id": self.next_record_id,
                    "result": "accepted",
                },
            }
            self.records[delivery_key] = record
            self.next_record_id += 1
            self._persist()
            return record

    def note_request(self, entry: dict) -> None:
        """请求一到就登记（响应状态稍后补全），便于并发演练观察在途请求。"""
        with self.lock:
            self.request_log.append(entry)
            self._log_file.write(json.dumps(
                {"event": "received", **entry}, ensure_ascii=False,
                sort_keys=True) + "\n")
            self._log_file.flush()

    def complete_request(self, entry: dict) -> None:
        with self.lock:
            self._log_file.write(json.dumps(
                {"event": "completed", **entry}, ensure_ascii=False,
                sort_keys=True) + "\n")
            self._log_file.flush()

    def log_request(self, entry: dict) -> None:
        self.complete_request(entry)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "records": {k: dict(v) for k, v in self.records.items()},
                "request_counts": dict(self.request_counts),
                "requests": list(self.request_log),
                "gates": {name: event.is_set()
                          for name, event in self.gates.items()},
            }

    def close(self) -> None:
        with self.lock:
            try:
                self._log_file.flush()
                self._log_file.close()
            except Exception:
                pass


def _wait_seconds(behavior: dict) -> float:
    """门控等待上限：测试可设很短；生产操作者通常手动放行。"""
    return float(behavior.get("wait_seconds", 3600))


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静音访问日志
        return

    # 主动断开时屏蔽 flush/close 的二次异常
    def finish(self):
        try:
            super().finish()
        except Exception:
            try:
                self.wfile.close()
            except Exception:
                pass

    def handle_error(self, *args):  # 断开/超时属于演练预期，不打印堆栈
        return

    # ------------------------------------------------------------------ #
    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/healthz":
            self._send_json(200, {"status": "ok"})
        elif parts.path == "/__control/state":
            self._send_json(200, self.server.state.snapshot())
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        state: ReceiverState = self.server.state

        if parts.path == "/__control/release":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except ValueError:
                self._send_json(400, {"error": "bad_json"})
                return
            released = state.release(str(payload.get("gate", "*")))
            self._send_json(200, {"released": released})
            return

        headers = {name: value for name, value in self.headers.items()}
        partner = headers.get(HEADER_PARTNER, "")
        event_id = headers.get(HEADER_EVENT_ID, "")
        seq = headers.get(HEADER_SOURCE_SEQ, "")
        claimed_sha = headers.get(HEADER_BODY_SHA256, "").lower()
        delivery_key = headers.get(HEADER_DELIVERY_KEY, "")
        actual_sha = hashlib.sha256(body).hexdigest()

        behavior = state.behavior_for(partner, event_id)
        kind = behavior.get("kind", "ok")

        body_file = state.save_body(body)
        entry = {
            "received_at": state.clock(),
            "path": parts.path,
            "headers": headers,
            "body_sha256_actual": actual_sha,
            "body_sha256_header": claimed_sha,
            "byte_length": len(body),
            "body_file": str(Path("bodies") / f"{body_file}.bin"),
            "partner_id": partner,
            "event_id": event_id,
            "source_seq": seq,
            "delivery_key": delivery_key,
            "behavior": kind,
            "response_status": None,
            "business_record_id": None,
            "duplicate_delivery": delivery_key in state.records,
        }
        state.note_request(entry)

        logged = {"done": False}

        def done(status=None, record=None, note=None):
            if logged["done"]:
                return
            logged["done"] = True
            entry["response_status"] = status
            if record is not None:
                entry["business_record_id"] = record["record_id"]
            if note:
                entry["note"] = note
            state.log_request(entry)

        try:
            if kind == "disconnect_after_save":
                record = state.save_record(
                    delivery_key, partner_id=partner, event_id=event_id,
                    source_seq=seq, body_sha256=actual_sha,
                    byte_length=len(body),
                )
                entry["gate"] = "disconnect"
                gate = state.gate("disconnect")
                released = gate.wait(timeout=float(
                    _wait_seconds(behavior)))
                done(None, record,
                     "saved then disconnected before HTTP response"
                     if released else "disconnect gate timed out; closed")
                # 放行即视为对端网络故障：不发送任何 HTTP 响应，直接切断
                self._abort_connection()
                return

            if kind == "hold":
                record = state.save_record(
                    delivery_key, partner_id=partner, event_id=event_id,
                    source_seq=seq, body_sha256=actual_sha,
                    byte_length=len(body),
                )
                gate_name = str(behavior.get("gate", "default"))
                entry["gate"] = gate_name
                gate = state.gate(gate_name)
                if not gate.wait(timeout=float(
                        _wait_seconds(behavior))):
                    done(500, record, "hold gate timed out")
                    self._send_json(500, {"error": "hold_timeout"})
                    return
                receipt = self._receipt_for(record, behavior)
                data = json.dumps(receipt, ensure_ascii=False,
                                  sort_keys=True).encode("utf-8")
                done(200, record, "receipt returned after release")
                self._send_bytes(200, data, extra={"Content-Type":
                                                   "application/json"})
                return

            if kind == "ok":
                record = state.save_record(
                    delivery_key, partner_id=partner, event_id=event_id,
                    source_seq=seq, body_sha256=actual_sha,
                    byte_length=len(body),
                )
                receipt = self._receipt_for(record, behavior)
                data = json.dumps(receipt, ensure_ascii=False,
                                  sort_keys=True).encode("utf-8")
                done(200, record, "receipt returned")
                self._send_bytes(200, data, extra={"Content-Type":
                                                   "application/json"})
                return

            if kind == "ok_wrong_sha":
                record = state.save_record(
                    delivery_key, partner_id=partner, event_id=event_id,
                    source_seq=seq, body_sha256=actual_sha,
                    byte_length=len(body))
                receipt = {
                    "delivery_key": delivery_key,
                    "body_sha256": "0" * 64,
                    "record_id": record["record_id"],
                    "result": "accepted",
                }
                done(200, record, "wrong body_sha256 in receipt")
                self._send_json(200, receipt)
            elif kind == "empty":
                done(200, None, "empty response body")
                self._send_bytes(200, b"")
            elif kind == "not_json":
                done(200, None, "non-JSON receipt")
                self._send_bytes(200, b"not json at all")
            elif kind == "duplicate_key":
                done(200, None, "duplicate receipt field")
                self._send_bytes(
                    200,
                    (b'{"delivery_key":"' + delivery_key.encode("ascii", "replace")
                     + b'","delivery_key":"x","body_sha256":"'
                     + actual_sha.encode("ascii", "replace") + b'"}'))
            elif kind == "huge":
                # 合法 JSON 前缀 + 超过 64KiB 的填充
                padding = "x" * (70 * 1024)
                data = json.dumps({"delivery_key": delivery_key,
                                   "body_sha256": actual_sha,
                                   "padding": padding}).encode("utf-8")
                done(200, None, "response larger than 64KiB")
                self._send_bytes(200, data)
            elif kind == "redirect":
                status = int(behavior.get("status", 302))
                done(status, None, "redirect not followed")
                self._send_bytes(status, b"redirect", extra={
                    "Location": str(behavior.get("location",
                                                 "http://127.0.0.1:1/elsewhere")),
                    "Content-Type": "text/plain",
                })
            elif kind == "429":
                retry_after = behavior.get("retry_after")
                done(429, None, f"retry_after={retry_after}")
                extra = {"Content-Type": "application/json"}
                if retry_after is not None:
                    extra["Retry-After"] = str(retry_after)
                self._send_bytes(429, b'{"error":"rate_limited"}', extra=extra)
            elif kind == "status":
                status = int(behavior.get("status", 400))
                done(status, None, "configured status")
                self._send_bytes(status, b'{"error":"configured"}',
                                 extra={"Content-Type": "application/json"})
            else:
                done(500, None, f"unknown behavior {kind!r}")
                self._send_bytes(500, b'{"error":"unknown_behavior"}')
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            entry["note"] = f"client went away: {exc}"
            done(entry.get("response_status"), None, entry["note"])

    # ------------------------------------------------------------------ #
    @staticmethod
    def _receipt_for(record: dict, behavior: dict) -> dict:
        receipt = dict(record["receipt"])
        extra = behavior.get("extra_receipt_field")
        if extra is not None:
            receipt["operator_note"] = extra  # 额外字段应被发送方忽略
        return receipt

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self._send_bytes(status, data, extra={
            "Content-Type": "application/json; charset=utf-8"})

    def _send_bytes(self, status: int, data: bytes, *,
                    extra: dict | None = None) -> None:
        self.send_response(status)
        headers = {"Content-Length": str(len(data))}
        if extra:
            headers.update(extra)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if data:
            self.wfile.write(data)
            self.wfile.flush()

    def _abort_connection(self) -> None:
        """主动断开：先落地记录，再切断连接且不发送任何 HTTP 响应。"""
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass


class Receiver:
    def __init__(self, workdir: str | Path, *, plan: dict | None = None,
                 host: str = "127.0.0.1", port: int = 0):
        self.state = ReceiverState(Path(workdir), plan)
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.state = self.state
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       name="receiver-http", daemon=True)

    @property
    def address(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def start(self) -> str:
        self.thread.start()
        return self.address

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        self.state.close()

    # 便捷查询
    def request_count(self, delivery_key: str | None = None) -> int:
        with self.state.lock:
            if delivery_key is None:
                return len(self.state.request_log)
            return sum(1 for e in self.state.request_log
                       if e.get("delivery_key") == delivery_key)

    def requests_for(self, delivery_key: str) -> list[dict]:
        with self.state.lock:
            return [dict(e) for e in self.state.request_log
                    if e.get("delivery_key") == delivery_key]

    def records(self) -> dict[str, dict]:
        with self.state.lock:
            return {k: dict(v) for k, v in self.state.records.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="可控下游接收器（本机）")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--dir", required=True, help="保存字节/头部/状态的目录")
    parser.add_argument("--plan", default=None, help="行为计划 JSON 文件")
    args = parser.parse_args(argv)

    plan = None
    if args.plan:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    receiver = Receiver(args.dir, plan=plan, host=args.host, port=args.port)
    address = receiver.start()
    print(f"接收器已启动: {address}", flush=True)
    print(f"日志目录: {args.dir}", flush=True)
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        receiver.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
