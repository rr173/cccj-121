"""下游 HTTP 发送工人测试（本地环回，可控接收器，不靠长睡眠）。

覆盖：
- 投递契约纯函数（delivery_key 稳定性/跨合作方隔离、头值无歧义、退避、
  回执校验、64KiB 上限）；
- 按合作方队首排队、退避期间不越过、其他合作方不受影响；
- 永久失败需人工重试、重试重置轮次；
- 200 但回执缺失/摘要错/空体/非 JSON/超大 均不算送达；
- 连接断开后重试用相同键，接收端只产生一份业务记录；
- 两个进程并发：占用未到期不能抢、过期接手、旧回执迟到不覆盖；
- 迁移前已 delivered 不重发、源正文失配不出网、旧 drain 停用；
- 注入时钟推进时间（无长睡眠）。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from partner_webhook import cli
from partner_webhook.outbound import (
    HEADER_BODY_SHA256,
    HEADER_DELIVERY_KEY,
    HEADER_EVENT_ID,
    HEADER_PARTNER,
    HEADER_SOURCE_SEQ,
    MAX_RESPONSE_BYTES,
    DeliveryError,
    DeliveryStore,
    DeliveryWorker,
    SendOutcome,
    backoff_seconds,
    build_headers,
    delivery_key,
    header_value,
    parse_receipt,
    validate_receipt,
)
from partner_webhook.receiver import Receiver
from partner_webhook.storage import Storage

from .helpers import PATH, WebhookTestCase, b64


def config_two_partners() -> list[dict]:
    return [
        {"id": "acme", "max_skew_seconds": 300, "keys": [
            {"version": "v1", "secret_b64": b64("acme-secret"),
             "not_before": None, "not_after": None}]},
        {"id": "globex", "max_skew_seconds": 300, "keys": [
            {"version": "g1", "secret_b64": b64("globex-secret"),
             "not_before": None, "not_after": None}]},
    ]


# --------------------------------------------------------------------- #
# 纯函数
# --------------------------------------------------------------------- #
class ContractTest(unittest.TestCase):

    def test_delivery_key_is_stable_and_partner_scoped(self):
        sha = "a" * 64
        k1 = delivery_key("acme", "evt-1", sha)
        k2 = delivery_key("acme", "evt-1", sha)
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, delivery_key("globex", "evt-1", sha))
        self.assertNotEqual(k1, delivery_key("acme", "evt-1", "b" * 64))
        # 拼接歧义：不同字段组合不得相撞
        self.assertNotEqual(delivery_key("ab", "c", sha),
                            delivery_key("a", "bc", sha))

    def test_header_value_rejects_newlines_and_non_ascii(self):
        self.assertEqual(header_value("evt-1"), "evt-1")
        for bad in ("a\r\nb", "a\nb", "事件", "a\tb", " a", "a ", ""):
            with self.assertRaises(DeliveryError):
                header_value(bad)

    def test_backoff_formula_and_retry_after(self):
        self.assertEqual([backoff_seconds(n) for n in (1, 2, 3, 4, 7)],
                         [1, 2, 4, 8, 60])
        # 仅纯十进制数字的 Retry-After 被采纳，取较大值
        self.assertEqual(backoff_seconds(2, "30"), 30)
        self.assertEqual(backoff_seconds(6, "3"), 32)
        for invalid in ("1.5", " 3", "3s", "Wed, 21 Oct 2015 07:28:00 GMT",
                        "-3", "+3", "٣"):
            self.assertEqual(backoff_seconds(2, invalid), 2, invalid)

    def test_receipt_validation(self):
        key, sha = "dk1_abc", "b" * 64
        good = json.dumps({"delivery_key": key, "body_sha256": sha,
                           "extra": 1}).encode()
        self.assertEqual(validate_receipt(good, key, sha), (True, None))
        cases = {
            b"": "empty_response",
            b"not json": "response_not_json",
            b"[]": "response_not_object",
            b"\xff": "response_not_utf8",
            json.dumps({"delivery_key": key, "body_sha256": "c" * 64}).encode():
                "receipt_field_mismatch: body_sha256",
            json.dumps({"delivery_key": "x", "body_sha256": sha}).encode():
                "receipt_field_mismatch: delivery_key",
            json.dumps({"delivery_key": key}).encode():
                "receipt_field_missing: body_sha256",
            ('{"delivery_key": "a", "delivery_key": "b", "body_sha256": "'
             + sha + '"}').encode(): "duplicate_receipt_field: delivery_key",
        }
        for body, reason in cases.items():
            ok, why = validate_receipt(body, key, sha)
            self.assertFalse(ok, body)
            self.assertIn(reason.split(":")[0], why)

    def test_receipt_size_cap(self):
        payload = json.dumps({"delivery_key": "k", "body_sha256": "s",
                              "pad": "x" * (MAX_RESPONSE_BYTES + 10)}).encode()
        with self.assertRaises(ValueError) as ctx:
            parse_receipt(payload)
        self.assertIn("response_too_large", str(ctx.exception))

    def test_headers_roundtrip_unambiguously(self):
        h = build_headers("acme", "evt-1", 7, "d" * 64, "dk1_x")
        self.assertEqual(h[HEADER_PARTNER], "acme")
        self.assertEqual(h[HEADER_EVENT_ID], "evt-1")
        self.assertEqual(h[HEADER_SOURCE_SEQ], "7")
        self.assertEqual(h[HEADER_BODY_SHA256], "d" * 64)
        self.assertEqual(h[HEADER_DELIVERY_KEY], "dk1_x")
        # 不转发入站签名
        self.assertNotIn("X-Signature", h)


# --------------------------------------------------------------------- #
# 实际投递（环回 + 可控接收器 + 注入时钟）
# --------------------------------------------------------------------- #
class DeliveryTestCase(WebhookTestCase):
    NOW = 2_000_000_000

    def setUp(self):
        super().setUp()
        self.write_config(config_two_partners())
        self.service = self.make_service()
        self.receiver = Receiver(self.dir / "receiver")
        self.receiver.state.clock = lambda: float(self.NOW)
        self.base_url = self.receiver.start()
        self.store = DeliveryStore(self.db_path)

    def tearDown(self):
        self.receiver.stop()
        self.store.close()
        super().tearDown()

    # -- helpers ----------------------------------------------------
    def register(self, partner: str, event_id: str, behavior=None, *,
                 sequence=None, body=b'{"a":1}', timestamp=None):
        """真实签名收件，产生 outbox；登记接收地址。"""
        seq = sequence if sequence is not None else 1
        if behavior is not None:
            plan = self.receiver.state.plan.setdefault("events", {})
            item = plan.setdefault(f"{partner}/{event_id}", [])
            item.extend(behavior if isinstance(behavior, list) else [behavior])
        if self.store.endpoint(partner) is None:
            self.store.register_endpoint(partner, self.base_url + "/ingest",
                                         self.NOW)
        secret = "acme-secret" if partner == "acme" else "globex-secret"
        key = "v1" if partner == "acme" else "g1"
        result = self.deliver(self.service, partner=partner,
                              key_version=key, secret=secret,
                              event_id=event_id, sequence=seq,
                              timestamp=timestamp, body=body)
        assert result.result == "accepted", result
        return result

    def worker(self, now: int | None = None, **kwargs) -> DeliveryWorker:
        return DeliveryWorker(self.db_path,
                              clock=(lambda: float(now)) if now is not None
                              else None, **kwargs)

    def run_once(self, partner: str, now: int, max_attempts=10, **kwargs):
        w = self.worker(now, **kwargs)
        try:
            return w.run_partner(partner, max_attempts=max_attempts)
        finally:
            w.close()

    def state(self, partner, event_id):
        return self.store.event_attempts(partner, event_id)

    # -- queue / retry ----------------------------------------------
    def test_ok_delivery_sets_outbox_delivered_with_remote_receipt(self):
        self.register("acme", "evt-1")
        report = self.run_once("acme", self.NOW)
        self.assertEqual(report.delivered, ["evt-1"])
        reqs = self.receiver.requests_for(
            delivery_key("acme", "evt-1",
                         hashlib.sha256(b'{"a":1}').hexdigest()))
        self.assertEqual(len(reqs), 1)
        self.assertEqual(reqs[0]["body_sha256_actual"],
                         hashlib.sha256(b'{"a":1}').hexdigest())
        data = self.state("acme", "evt-1")
        self.assertEqual(data["outbox"]["status"], "delivered")
        self.assertIsNotNone(data["outbox"]["delivered_at"])
        self.assertEqual(data["attempts"][0]["outcome"], "success")
        self.assertEqual(data["attempts"][0]["http_status"], 200)

    def test_queue_head_blocks_followers_and_429_backoff_then_same_key(self):
        self.register("acme", "evt-a", sequence=1,
                      behavior={"kind": "429", "retry_after": "3"})
        self.register("acme", "evt-b", sequence=2)
        self.register("globex", "g-1", sequence=1)

        # 第一轮：甲队首 429 可重试；乙正常送达；甲的下一条不得越过
        report = self.run_once("acme", self.NOW)
        self.assertEqual(report.retry_wait[0]["event_id"], "evt-a")
        self.assertEqual(report.retry_wait[0]["next_attempt_at"], self.NOW + 3)
        self.assertEqual(report.delivered, [])
        self.assertEqual(self.state("acme", "evt-a")["delivery"]["status"],
                         "retry_wait")
        self.assertEqual(self.state("acme", "evt-b")["outbox"]["status"],
                         "pending")
        # 其他合作方照常
        globe = self.run_once("globex", self.NOW)
        self.assertEqual(globe.delivered, ["g-1"])

        # 提前运行：没有请求发出（不忙循环、不越过）
        count_before = self.receiver.request_count()
        early = self.run_once("acme", self.NOW + 2)
        self.assertEqual(early.attempts, 0)
        self.assertEqual(early.deferred_head is not None
                         or early.stopped_reason == "head_not_ready", True)
        self.assertEqual(self.receiver.request_count(), count_before)

        # 到期后重送（此时接收端只回一次 429，之后按默认 ok），delivery_key 不变
        plan = self.receiver.state.plan["events"]["acme/evt-a"]
        plan.append({"kind": "ok"})
        later = self.run_once("acme", self.NOW + 3,
                              max_attempts=2)
        self.assertEqual([x for x in later.delivered], ["evt-a", "evt-b"])
        key_a = delivery_key("acme", "evt-a",
                             hashlib.sha256(b'{"a":1}').hexdigest())
        self.assertEqual(len(self.receiver.requests_for(key_a)), 2)
        for req in self.receiver.requests_for(key_a):
            self.assertEqual(req["delivery_key"], key_a)
        data = self.state("acme", "evt-a")
        self.assertEqual([a["outcome"] for a in data["attempts"]],
                         ["retryable_failure", "success"])
        self.assertEqual(data["attempts"][0]["http_status"], 429)

    def test_permanent_failure_requires_operator_retry_and_resets_round(self):
        self.register("acme", "evt-400", sequence=1,
                      behavior={"kind": "status", "status": 400})
        self.register("acme", "evt-next", sequence=2)
        report = self.run_once("acme", self.NOW)
        self.assertEqual(report.permanent_failure[0]["event_id"], "evt-400")
        self.assertEqual(report.permanent_failure[0]["http_status"], 400)
        self.assertEqual(self.state("acme", "evt-400")["delivery"]["status"],
                         "permanent_failure")
        # 后续不越过
        self.assertEqual(self.state("acme", "evt-next")["outbox"]["status"],
                         "pending")
        # 再次运行仍不自动发
        again = self.run_once("acme", self.NOW + 999)
        self.assertEqual(again.attempts, 0)
        # 非永久失败不能人工重试
        with self.assertRaises(DeliveryError):
            self.store.retry_permanent("acme", "evt-next", self.NOW)
        # 人工重试：回到 pending，轮次清零，保留此前尝试
        retried = self.store.retry_permanent("acme", "evt-400", self.NOW,
                                             operator="ops-1")
        self.assertEqual(retried["status"], "pending")
        self.assertEqual(retried["attempt_no"], 0)
        data = self.state("acme", "evt-400")
        self.assertEqual(len(data["attempts"]), 1)
        self.assertEqual(len(data["operator_actions"]), 1)
        plan = self.receiver.state.plan["events"]["acme/evt-400"]
        plan.append({"kind": "429", "retry_after": "2"})
        plan.append({"kind": "ok"})
        r = self.run_once("acme", self.NOW + 1000)
        self.assertEqual(r.retry_wait[0]["reason"], "http_429_rate_limited")
        self.assertEqual(r.retry_wait[0]["next_attempt_at"],
                         self.NOW + 1002)
        r2 = self.run_once("acme", self.NOW + 1002)
        self.assertEqual(r2.delivered, ["evt-400", "evt-next"])
        data = self.state("acme", "evt-400")
        self.assertEqual([a["outcome"] for a in data["attempts"]],
                         ["permanent_failure", "retryable_failure", "success"])
        # 人工重试后第 1 次失败等 2 秒（Retry-After 覆盖默认 1 秒）
        self.assertEqual(data["attempts"][1]["attempt_no"], 1)
        self.assertEqual(data["delivery"]["attempt_no"], 2)

    def test_200_with_bad_receipts_are_not_delivery(self):
        cases = [
            ("empty", "invalid_receipt: empty_response"),
            ("not_json", "invalid_receipt: response_not_json"),
            ("ok_wrong_sha", "invalid_receipt: receipt_field_mismatch: body_sha256"),
            ("duplicate_key", "invalid_receipt: duplicate_receipt_field: delivery_key"),
            ("huge", "invalid_receipt: response_too_large"),
        ]
        for index, (kind, reason) in enumerate(cases):
            event_id = f"evt-{kind}"
            self.register("acme", event_id, sequence=index + 1,
                          behavior={"kind": kind})
        # 队首是 evt-empty，其余事件被队首挡住；逐条用人工绕过的方式无法
        # 自动推进，因此改用一个合作方一个事件，独立观察每种坏回执。
        for index, (kind, reason) in enumerate(cases):
            partner = f"p-{kind}"
            self.write_config(config_two_partners() + [{
                "id": partner, "max_skew_seconds": 300,
                "keys": [{"version": "k", "secret_b64": b64("s-" + kind),
                          "not_before": None, "not_after": None}]}])
            self.service = self.make_service()
            self.deliver(self.service, partner=partner, key_version="k",
                         secret="s-" + kind, event_id="e", sequence=1,
                         body=b'{"a":1}')
            self.store.register_endpoint(partner, self.base_url + "/ingest",
                                         self.NOW)
            self.receiver.state.plan.setdefault("events", {})[
                f"{partner}/e"] = [{"kind": kind}]
            report = self.run_once(partner, self.NOW)
            self.assertEqual(report.retry_wait[0]["reason"], reason, kind)
            data = self.store.event_attempts(partner, "e")
            self.assertEqual(data["outbox"]["status"], "pending")
            self.assertEqual(data["attempts"][0]["http_status"], 200)
            self.assertEqual(data["attempts"][0]["outcome"],
                             "retryable_failure")
            self.assertIsNone(data["outbox"]["delivered_at"])

    def test_redirect_is_permanent_and_not_followed(self):
        self.register("acme", "evt-302", sequence=1,
                      behavior={"kind": "redirect", "status": 302})
        report = self.run_once("acme", self.NOW)
        self.assertEqual(report.permanent_failure[0]["http_status"], 302)
        self.assertEqual(report.permanent_failure[0]["reason"],
                         "http_redirect_not_followed")
        # 接收端没有收到第二个请求（未跟随）
        self.assertEqual(self.receiver.request_count(), 1)

    def test_disconnect_then_retry_same_key_one_business_record(self):
        self.register("acme", "evt-cut",
                      behavior=[{"kind": "disconnect_after_save",
                                 "wait_seconds": 0.2}, {"kind": "ok"}])
        first = self.run_once("acme", self.NOW)
        self.assertEqual(first.retry_wait[0]["event_id"], "evt-cut")
        # 主动断开后 http.client 对响应体读取表现为超时/连接中断，均可重试
        self.assertIn(first.retry_wait[0]["reason"],
                      ("timeout", "connection_reset", "bad_response"))
        # 接收端已落地一条业务记录，但发送方未确认
        records = self.receiver.records()
        self.assertEqual(len(records), 1)
        key = next(iter(records))
        self.assertEqual(self.state("acme", "evt-cut")["outbox"]["status"],
                         "pending")
        self.receiver.state.release("disconnect")
        time.sleep(0.1)
        second = self.run_once("acme", self.NOW + 1)
        self.assertEqual(second.delivered, ["evt-cut"])
        # 同键重试：接收端只保留一份业务记录
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(len(self.receiver.requests_for(key)), 2)
        for req in self.receiver.requests_for(key):
            self.assertEqual(req["delivery_key"], key)
        self.assertEqual(self.state("acme", "evt-cut")["outbox"]["status"],
                         "delivered")

    def test_binary_and_empty_bodies_delivered_byte_exact(self):
        self.store.register_endpoint("acme", self.base_url + "/ingest", self.NOW)
        bodies = {
            "evt-empty": b"",
            "evt-bin": bytes(range(256)) + b"\xff\x00\xfe",
            "evt-utf8ish": "温度".encode("utf-8"),
        }
        now = self.NOW
        for idx, (event_id, body) in enumerate(bodies.items(), start=1):
            now += 1  # 每条的签名时间戳不同（规范化串覆盖时间戳）
            self.register("acme", event_id, sequence=idx, body=body,
                          timestamp=now)
        for now in range(self.NOW + 2, self.NOW + 10):
            report = self.run_once("acme", now, max_attempts=1)
            if not report.delivered and report.stopped_reason:
                break
            if all(self.state("acme", e)["outbox"]["status"] == "delivered"
                   for e in bodies):
                break
        for event_id, body in bodies.items():
            data = self.state("acme", event_id)
            self.assertEqual(data["outbox"]["status"], "delivered", event_id)
            sha = hashlib.sha256(body).hexdigest()
            reqs = self.receiver.requests_for(
                delivery_key("acme", event_id, sha))
            self.assertEqual(len(reqs), 1)
            saved = Path(reqs[0]["body_file"])
            sent = (self.dir / "receiver" / saved).read_bytes()
            self.assertEqual(sent, body)
            self.assertEqual(reqs[0]["body_sha256_actual"], sha)
            self.assertEqual(reqs[0]["byte_length"], len(body))

    def test_missing_body_is_local_error_and_never_sent(self):
        self.register("acme", "evt-missing", sequence=1)
        sha = hashlib.sha256(b'{"a":1}').hexdigest()
        # 模拟迁移前已有行、正文文件丢失：先清掉引用该正文的 accept 记录
        conn = self.storage.conn
        conn.execute("DELETE FROM outbox WHERE event_id = 'evt-missing'")
        conn.execute("DELETE FROM accepted_events WHERE event_id = 'evt-missing'")
        conn.execute("DELETE FROM ingest_records WHERE event_id = 'evt-missing'")
        conn.execute("DELETE FROM raw_bodies WHERE body_sha256 = ?", (sha,))
        conn.execute(
            "INSERT INTO outbox (partner_id, event_id, source_seq, body_sha256,"
            " created_at, status) VALUES ('acme', 'evt-missing', 1, ?, ?,"
            " 'pending')", (sha, self.NOW))
        conn.commit()
        report = self.run_once("acme", self.NOW)
        self.assertEqual(report.local_error[0]["reason"], "body_missing")
        self.assertEqual(self.receiver.request_count(), 0)
        data = self.state("acme", "evt-missing")
        self.assertEqual(data["delivery"]["status"], "permanent_failure")
        self.assertEqual(data["attempts"][0]["outcome"], "local_error")
        self.assertEqual(data["outbox"]["status"], "pending")

    def test_body_digest_mismatch_is_local_error_and_never_sent(self):
        self.register("acme", "evt-badsha", sequence=1)
        sha = hashlib.sha256(b'{"a":1}').hexdigest()
        # 篡改正文但保留原摘要/长度登记
        self.storage.conn.execute(
            "UPDATE raw_bodies SET body_blob = ? WHERE body_sha256 = ?",
            (b'{"a":2}', sha))
        self.storage.conn.commit()
        report = self.run_once("acme", self.NOW)
        self.assertIn("body_sha256_mismatch", report.local_error[0]["reason"])
        self.assertEqual(self.receiver.request_count(), 0)
        self.assertEqual(self.state("acme", "evt-badsha")
                         ["delivery"]["status"], "permanent_failure")

    def test_historical_delivered_rows_not_resent(self):
        # 模拟迁移前已 delivered 的记录：没有 outbox_delivery 状态行
        self.register("acme", "evt-old", sequence=1)
        self.storage.conn.execute(
            "UPDATE outbox SET status='delivered', delivered_at=? "
            "WHERE event_id='evt-old'", (self.NOW - 100,))
        self.storage.conn.commit()
        report = self.run_once("acme", self.NOW)
        self.assertEqual(report.attempts, 0)
        self.assertEqual(self.receiver.request_count(), 0)

    def test_endpoint_immutable(self):
        self.register("acme", "evt-1")
        with self.assertRaises(DeliveryError):
            self.store.register_endpoint("acme", self.base_url + "/other",
                                         self.NOW)
        with self.assertRaises(DeliveryError):
            self.store.register_endpoint("acme", self.base_url + "/ingest",
                                         self.NOW)
        # 其他合作方可登记自己的地址
        self.store.register_endpoint("globex", self.base_url + "/g", self.NOW)

    def test_no_endpoint_is_explicit(self):
        result = self.deliver(self.service, partner="globex", key_version="g1",
                              secret="globex-secret", event_id="g-1",
                              sequence=1)
        self.assertEqual(result.result, "accepted")
        report = self.run_once("globex", self.NOW)
        self.assertTrue(report.no_endpoint)
        self.assertEqual(report.attempts, 0)


# --------------------------------------------------------------------- #
# 并发 / 占用 / 迟到回执（线程模拟两个独立进程，共享 SQLite）
# --------------------------------------------------------------------- #
class ConcurrencyTest(WebhookTestCase):
    NOW = 2_000_000_000

    def setUp(self):
        super().setUp()
        self.write_config(config_two_partners())
        self.service = self.make_service()
        self.receiver = Receiver(self.dir / "receiver")
        self.receiver.state.clock = lambda: float(self.NOW)
        self.base_url = self.receiver.start()
        store = DeliveryStore(self.db_path)
        store.register_endpoint("acme", self.base_url + "/ingest", self.NOW)
        store.close()

    def tearDown(self):
        self.receiver.stop()
        super().tearDown()

    def deliver(self, *args, **kwargs):  # noqa: D401 复用基类
        return super().deliver(*args, **kwargs)

    def state(self, partner, event_id):
        store = DeliveryStore(self.db_path)
        try:
            return store.event_attempts(partner, event_id)
        finally:
            store.close()

    def test_lease_not_stolen_until_expiry_then_late_receipt_is_ignored(self):
        self.store_event("evt-1", 1, [{"kind": "hold", "gate": "evt-1"},
                                      {"kind": "ok"}])
        self.store_event("evt-2", 2, [{"kind": "ok"}])

        key1 = delivery_key("acme", "evt-1",
                            hashlib.sha256(b'{"a":1}').hexdigest())
        first_result: dict = {}
        release_old = threading.Event()

        def worker_one():
            w = DeliveryWorker(self.db_path, clock=lambda: float(self.NOW),
                               worker_id="worker-A")
            try:
                first_result["report"] = w.run_partner("acme", max_attempts=5)
            finally:
                w.close()

        thread = threading.Thread(target=worker_one)
        thread.start()
        self._wait_for(lambda: len(self.receiver.requests_for(key1)) == 1)
        # 状态：甲持有未到期占用
        data = self.state("acme", "evt-1")
        self.assertEqual(data["delivery"]["status"], "in_flight")
        self.assertEqual(data["delivery"]["lease_owner"], "worker-A")
        old_attempt_id = data["attempts"][0]["id"]

        # 乙在占用未到期时不能抢走（注入同一时刻）
        w_b = DeliveryWorker(self.db_path, clock=lambda: float(self.NOW),
                             worker_id="worker-B")
        try:
            blocked = w_b.run_partner("acme", max_attempts=1)
        finally:
            w_b.close()
        self.assertEqual(blocked.attempts, 0)

        # 释放甲的挂起回执，但先不写回：模拟网络迟迟不返回
        # 推进到占用过期，乙接手并拿到正确回执
        later = self.NOW + 61
        w_b2 = DeliveryWorker(self.db_path, clock=lambda: float(later),
                              worker_id="worker-B2")
        try:
            report_b = w_b2.run_partner("acme", max_attempts=2)
        finally:
            w_b2.close()
        self.assertEqual(report_b.delivered, ["evt-1", "evt-2"])

        # 放行甲的旧回执；它是迟到的，不得覆盖送达时间/尝试归属
        before = self.state("acme", "evt-1")
        delivered_at = before["outbox"]["delivered_at"]
        self.receiver.state.release("evt-1")
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertFalse(thread.is_alive())

        after = self.state("acme", "evt-1")
        self.assertEqual(after["outbox"]["delivered_at"], delivered_at)
        self.assertEqual(after["delivery"]["status"], "delivered")
        first = next(a for a in after["attempts"] if a["id"] == old_attempt_id)
        self.assertEqual(first["outcome"], "lease_expired_takeover")
        self.assertEqual(first["late_outcome"], "success")
        self.assertEqual(after["attempts"][-1]["worker_id"], "worker-B2")
        # 下一条不被旧工人改变：evt-2 只由乙送达一次
        self.assertEqual(self.state("acme", "evt-2")["delivery"]["status"],
                         "delivered")
        self.assertEqual(len(self.receiver.records()), 2)
        # 甲的旧请求 + 乙接手后的重发，共两次同键请求（至少一次语义）
        self.assertEqual(len(self.receiver.requests_for(key1)), 2)

    def test_expired_claim_taken_over_by_reopened_worker_same_key(self):
        # 原工人只领取、未发出请求就消失；接手工人第一次请求即成功
        self.store_event("evt-1", 1, [{"kind": "ok"}])
        key = delivery_key("acme", "evt-1",
                           hashlib.sha256(b'{"a":1}').hexdigest())

        # 工人 A 领取后“结束”（进程消失）：不释放门，直接退出
        w = DeliveryWorker(self.db_path, clock=lambda: float(self.NOW),
                           worker_id="dying-worker")
        claim = w.store.claim_next("acme", "dying-worker", self.NOW,
                                   lease_seconds=5)
        self.assertIsNotNone(claim)
        w.close()
        # 占用未到期：谁都领不到
        probe = DeliveryWorker(self.db_path, clock=lambda: float(self.NOW + 4),
                               worker_id="probe")
        self.assertIsNone(probe.store.claim_next("acme", "probe",
                                                self.NOW + 4))
        probe.close()

        # 推进时间并“重开进程”：接手成功，delivery_key 不变
        w2 = DeliveryWorker(self.db_path, clock=lambda: float(self.NOW + 10),
                            worker_id="reopened")
        try:
            report = w2.run_partner("acme", max_attempts=2)
        finally:
            w2.close()
        self.assertEqual(report.delivered, ["evt-1"])
        data = self.state("acme", "evt-1")
        keys = {a["delivery_key"] for a in data["attempts"]}
        self.assertEqual(keys, {key})
        takeover = data["attempts"][0]
        self.assertEqual(takeover["outcome"], "lease_expired_takeover")
        self.assertEqual(data["attempts"][-1]["takeover_reason"],
                         "lease_expired")
        self.assertEqual(data["attempts"][-1]["previous_worker_id"],
                         "dying-worker")
        self.assertEqual(len(self.receiver.records()), 1)
        self.assertEqual(len(self.receiver.requests_for(key)), 1)

    # -- helpers ----------------------------------------------------
    def store_event(self, event_id: str, sequence: int, behavior):
        plan = self.receiver.state.plan.setdefault("events", {})
        plan.setdefault(f"acme/{event_id}", []).extend(behavior)
        result = super().deliver(self.service, partner="acme",
                                 key_version="v1", secret="acme-secret",
                                 event_id=event_id, sequence=sequence,
                                 body=b'{"a":1}')
        self.assertEqual(result.result, "accepted")

    def _wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("等待条件超时")


# --------------------------------------------------------------------- #
# 两个独立进程（CLI 子进程）
# --------------------------------------------------------------------- #
class TwoProcessTest(WebhookTestCase):
    NOW = 2_000_000_000

    def setUp(self):
        super().setUp()
        self.write_config(config_two_partners())
        self.service = self.make_service()
        self.receiver = Receiver(self.dir / "receiver")
        self.receiver.state.clock = lambda: float(self.NOW)
        self.base_url = self.receiver.start()

    def tearDown(self):
        self.receiver.stop()
        super().tearDown()

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        command = [sys.executable, "-I",
                   str(Path(cli.__file__).resolve()),
                   "--config", str(self.config_path), "--db", self.db_path,
                   *args]
        return subprocess.run(command, capture_output=True, text=True,
                              timeout=60)

    def test_cli_register_run_queue_attempts_retry(self):
        self.receiver.state.plan.setdefault("events", {})[
            "acme/evt-bad"] = [{"kind": "status", "status": 400}]
        for event_id, seq in (("evt-bad", 1), ("evt-ok", 2)):
            result = self.deliver(self.service, partner="acme",
                                  key_version="v1", secret="acme-secret",
                                  event_id=event_id, sequence=seq,
                                  body=b'{"a":1}')
            self.assertEqual(result.result, "accepted")
        self.storage.close()

        reg = self.cli("outbox-endpoint", "--partner", "acme",
                       "--register", self.base_url + "/ingest")
        self.assertEqual(reg.returncode, 0, reg.stderr)
        self.assertIn("ingest", json.loads(reg.stdout)["url"])
        again = self.cli("outbox-endpoint", "--partner", "acme",
                         "--register", self.base_url + "/other")
        self.assertEqual(again.returncode, 2)
        self.assertIn("不可原地更换", again.stderr)

        run = self.cli("outbox-run", "--partner", "acme",
                       "--max-attempts", "5", "--now", str(self.NOW))
        self.assertEqual(run.returncode, 0, run.stderr)
        reports = json.loads(run.stdout)["reports"]
        self.assertEqual(reports[0]["permanent_failure"][0]["event_id"],
                         "evt-bad")

        queue = json.loads(self.cli("outbox-queue", "--partner", "acme").stdout)
        self.assertEqual(queue["queue"][0]["id"], 1)
        self.assertEqual(queue["queue"][0]["status"], "permanent_failure")
        self.assertEqual(queue["queue"][1]["outbox_status"], "pending")

        attempts = json.loads(self.cli(
            "outbox-attempts", "--partner", "acme",
            "--event-id", "evt-bad").stdout)
        self.assertEqual(attempts["attempts"][0]["http_status"], 400)

        retry = self.cli("outbox-retry", "--partner", "acme",
                         "--event-id", "evt-ok")
        self.assertEqual(retry.returncode, 2)  # 未失败，不可人工重试
        self.receiver.state.plan["events"]["acme/evt-bad"].append(
            {"kind": "ok"})
        retry = self.cli("outbox-retry", "--partner", "acme",
                         "--event-id", "evt-bad", "--operator", "ops")
        self.assertEqual(retry.returncode, 0, retry.stderr)
        run2 = self.cli("outbox-run", "--partner", "acme",
                        "--max-attempts", "5", "--now", str(self.NOW + 1))
        reports2 = json.loads(run2.stdout)["reports"][0]
        self.assertEqual(reports2["delivered"], ["evt-bad", "evt-ok"])

    def test_old_drain_exits_2_and_does_not_deliver(self):
        result = self.deliver(self.service, partner="acme", key_version="v1",
                              secret="acme-secret", event_id="evt-1",
                              sequence=1, body=b'{"a":1}')
        self.assertEqual(result.result, "accepted")
        self.storage.close()
        drain = self.cli("drain-outbox")
        self.assertEqual(drain.returncode, 2)
        self.assertIn("outbox-run", drain.stderr)
        conn = Storage(self.db_path)
        try:
            self.assertEqual(
                conn.conn.execute("SELECT status FROM outbox").fetchone()[0],
                "pending")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
