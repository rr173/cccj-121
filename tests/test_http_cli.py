"""HTTP 端到端与命令行接口测试（全部走本地环回，不连外网）。"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from partner_webhook import cli
from partner_webhook.config import load_config
from partner_webhook.generator import build_signed_request, send
from partner_webhook.server import LocalWebhookServer
from partner_webhook.service import ACCEPTED, CONFLICT, DUPLICATE, REJECTED, WebhookService
from partner_webhook.storage import Storage

from .helpers import PATH, WebhookTestCase, b64


def two_overlapping_keys() -> list[dict]:
    return [{
        "id": "acme",
        "max_skew_seconds": 300,
        "keys": [
            {"version": "v1", "secret_b64": b64("old-secret"),
             "not_before": 1_999_999_000, "not_after": 2_000_000_600},
            {"version": "v2", "secret_b64": b64("new-secret"),
             "not_before": 2_000_000_000, "not_after": 2_000_001_000},
        ],
    }]


class HttpEndToEndTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        config = load_config(self.config_path)
        self.storage = Storage(self.db_path)
        service = WebhookService(config, self.storage, clock=self.clock)
        self.server = LocalWebhookServer(service, path=PATH)
        self.base_url = self.server.start()

    def tearDown(self):
        self.server.stop()
        super().tearDown()

    def test_signed_event_accepted_over_http(self):
        signed = build_signed_request(
            base_url=self.base_url, partner_id="acme", key_version="v1",
            secret_b64=b64("old-secret"), event_id="evt-http",
            sequence=1, timestamp=self.NOW, body=b'{"k":"v"}', path=PATH,
        )
        status, raw = send(signed)
        self.assertEqual(status, 200)
        payload = json.loads(raw)
        self.assertEqual(payload["result"], ACCEPTED)

        # 同样的请求重投一次 -> 幂等
        status2, raw2 = send(signed)
        self.assertEqual(status2, 200)
        self.assertEqual(json.loads(raw2)["result"], DUPLICATE)

    def test_tampered_body_rejected_over_http(self):
        signed = build_signed_request(
            base_url=self.base_url, partner_id="acme", key_version="v1",
            secret_b64=b64("old-secret"), event_id="evt-tamper",
            sequence=1, timestamp=self.NOW, body=b'{"k":"v"}', path=PATH,
        )
        signed.body = b'{"k":"x"}'  # 字节被改动，签名不再匹配
        status, raw = send(signed)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(raw)["reason"], "bad_signature")

    def test_conflict_returns_409_over_http(self):
        kw = dict(base_url=self.base_url, partner_id="acme",
                  key_version="v1", secret_b64=b64("old-secret"),
                  event_id="evt-conflict", timestamp=self.NOW, path=PATH)
        s1 = build_signed_request(sequence=1, body=b'{"v":1}', **kw)
        s2 = build_signed_request(sequence=1, body=b'{"v":2}', **kw)
        self.assertEqual(send(s1)[0], 200)
        status, raw = send(s2)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(raw)["result"], CONFLICT)

    def test_health_check(self):
        from urllib.request import urlopen
        with urlopen(self.base_url + "/healthz", timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read())["status"], "ok")


class CliTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()
        # 预置一条已接受事件和一条拒绝流水
        self.deliver(self.service, event_id="evt-cli", sequence=10)
        self.deliver(self.service, event_id="evt-bad", sequence=11,
                     bad_signature=True)

    def _args(self, *extra) -> list[str]:
        return ["--config", str(self.config_path),
                "--db", self.db_path, *extra]

    def _run_cli(self, *extra) -> str:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(self._args(*extra))
        self.assertEqual(code, 0)
        return buf.getvalue()

    def test_init_db_is_idempotent(self):
        self.storage.close()
        out = self._run_cli("init-db")
        self.assertIn("迁移", out)
        # 再执行一次不报错
        self._run_cli("init-db")

    def test_query_command_filters_by_partner_and_result(self):
        out = self._run_cli("query", "--partner", "acme",
                            "--result", REJECTED)
        rows = json.loads(out)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reason"], "bad_signature")

    def test_events_command_orders_by_source_sequence(self):
        # 再乱序插入两条
        self.deliver(self.service, event_id="evt-seq-30", sequence=30)
        self.deliver(self.service, event_id="evt-seq-20", sequence=20)
        out = self._run_cli("events", "--partner", "acme")
        events = json.loads(out)
        self.assertEqual([e["source_seq"] for e in events],
                         [10, 20, 30])

    def test_record_and_body_export_roundtrip(self):
        rows = json.loads(self._run_cli("query", "--partner", "acme"))
        accepted = next(r for r in rows if r["result"] == ACCEPTED)
        record_id = accepted["id"]

        detail = json.loads(self._run_cli("record", str(record_id)))
        self.assertEqual(detail["event_id"], "evt-cli")
        self.assertIn("X-Signature", detail["headers"])

        out_file = self.dir / "replayed.bin"
        self._run_cli("body", str(record_id), "--output", str(out_file))
        self.assertEqual(out_file.read_bytes(), b'{"a":1}')

    def test_stats_command(self):
        stats = json.loads(self._run_cli("stats"))
        self.assertEqual(stats["ingest"][ACCEPTED], 1)
        self.assertEqual(stats["ingest"][REJECTED], 1)
        self.assertEqual(stats["accepted_events"], 1)

    def test_drain_outbox_is_disabled_and_does_not_fake_success(self):
        self.deliver(self.service, event_id="evt-30", sequence=30)
        self.deliver(self.service, event_id="evt-20", sequence=20)
        before = len(self.storage.pending_outbox())
        self.assertGreater(before, 0)
        # 旧入口已停用：退出码 2，明确提示新命令，且不改变任何状态
        buf, err = io.StringIO(), io.StringIO()
        from contextlib import redirect_stderr
        with redirect_stdout(buf), redirect_stderr(err):
            code = cli.main(self._args("drain-outbox"))
        self.assertEqual(code, 2)
        self.assertIn("outbox-run", err.getvalue())
        self.assertEqual(len(self.storage.pending_outbox()), before)


class CliReplayTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()
        r = self.deliver(self.service, event_id="evt-replay", sequence=4,
                         body=b'{"order":42}')
        self.record_id = r.record_id

    def _args(self, *extra) -> list[str]:
        return ["--config", str(self.config_path),
                "--db", self.db_path, *extra]

    def test_replay_now_is_duplicate_and_does_not_reenqueue(self):
        before = len(self.storage.pending_outbox())
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(self._args(
                "replay-event", str(self.record_id),
                "--at", "now", "--now", str(self.NOW)))
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["result"], DUPLICATE)
        self.assertEqual(len(self.storage.pending_outbox()), before)

    def test_replay_with_rotated_key_at_claimed_time(self):
        # 验证时刻推进到旧密钥退役之后；用保存的原始体、当前时间与新密钥
        # v2（该时刻仍生效）重新签名，验证密钥切换后在途/重放请求不丢失
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(self._args(
                "replay-event", str(self.record_id),
                "--now", "2000000700", "--refresh-timestamp",
                "--key-version", "v2"))
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        # 签名/密钥/时间窗全部通过，仅因幂等被识别为重复
        self.assertEqual(payload["result"], DUPLICATE)

    def test_replay_expired_signature_cannot_reenter(self):
        # 时钟推进到旧密钥失效后，仍用旧密钥与旧时间戳重放 -> 拒绝
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(self._args(
                "replay-event", str(self.record_id),
                "--at", "claimed", "--now", "2000000700",
                "--key-version", "v1"))
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["result"], REJECTED)
        self.assertEqual(payload["reason"], "key_expired")

    def test_replay_outside_time_window_rejected(self):
        # 时间戳偏移到时间窗（300s）之外、但仍在 v1 密钥窗口内，
        # 因此先命中时间窗拒绝，而不是密钥失效
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(self._args(
                "replay-event", str(self.record_id),
                "--at", "now", "--now", str(self.NOW),
                "--ts-offset", "-301"))
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["reason"], "timestamp_outside_window")


if __name__ == "__main__":
    unittest.main()
