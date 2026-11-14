"""基于标准库 http.server 的本地环回 Webhook 收件服务。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .generator import DEFAULT_PATH
from .service import WebhookService


def _make_handler(service: WebhookService, path: str):
    class WebhookHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # 静音默认访问日志
            return

        def do_POST(self):  # noqa: N802 (标准库命名)
            parts = urlsplit(self.path)
            if parts.path != path:
                self._respond(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            result = service.receive(
                method="POST",
                path=parts.path,
                # BaseHTTPRequestHandler 的 headers 支持不区分大小写取值
                raw_headers={k: v for k, v in self.headers.items()},
                body=body,
            )
            payload = {
                "result": result.result,
                "reason": result.reason,
                "record_id": result.record_id,
                "event_id": result.event_id,
            }
            self._respond(result.http_status, payload)

        def do_GET(self):  # 健康检查，不入库
            parts = urlsplit(self.path)
            if parts.path == "/healthz":
                self._respond(200, {"status": "ok"})
            else:
                self._respond(404, {"error": "not_found"})

        def _respond(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return WebhookHandler


class LocalWebhookServer:
    def __init__(self, service: WebhookService, host: str = "127.0.0.1",
                 port: int = 0, path: str = DEFAULT_PATH):
        self.httpd = ThreadingHTTPServer(
            (host, port), _make_handler(service, path)
        )
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, name="webhook-http", daemon=True
        )

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
