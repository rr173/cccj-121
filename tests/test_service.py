"""接收验证服务全链路测试。"""

from __future__ import annotations

import threading
import unittest

from partner_webhook.service import (
    ACCEPTED,
    CONFLICT,
    DUPLICATE,
    REJECTED,
)

from .helpers import PATH, WebhookTestCase, b64


def two_overlapping_keys(skew: int = 300) -> list[dict]:
    # v1 与 v2 在 2_000_000_000 前后的窗口重叠，覆盖切换期的在途请求
    return [{
        "id": "acme",
        "max_skew_seconds": skew,
        "keys": [
            {"version": "v1", "secret_b64": b64("old-secret"),
             "not_before": 1_999_999_000, "not_after": 2_000_000_600},
            {"version": "v2", "secret_b64": b64("new-secret"),
             "not_before": 2_000_000_000, "not_after": 2_000_001_000},
        ],
    }]


class AcceptanceTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_happy_path_persists_record_body_and_outbox(self):
        result = self.deliver(self.service, event_id="evt-1", sequence=1)
        self.assertEqual(result.result, ACCEPTED)
        self.assertEqual(result.http_status, 200)

        records = self.storage.query_records(partner_id="acme")
        self.assertEqual(len(records), 1)
        row = records[0]
        self.assertEqual(row["result"], ACCEPTED)
        self.assertIsNone(row["reason"])

        # 原始体可按摘要取回，用于重放
        body = self.storage.get_raw_body(row["body_sha256"])
        self.assertEqual(body, b'{"a":1}')

        events = self.storage.list_events(partner_id="acme")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], "evt-1")

        pending = self.storage.pending_outbox()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["event_id"], "evt-1")

    def test_header_order_and_case_are_ignored(self):
        result = self.deliver(self.service, event_id="evt-h", sequence=1,
                              shuffle=True)
        self.assertEqual(result.result, ACCEPTED)

    def test_missing_header_is_rejected_and_recorded(self):
        from partner_webhook.canonical import canonical_bytes
        from partner_webhook.crypto import decode_secret, sign
        canonical = canonical_bytes(
            method="POST", path=PATH, partner_id="acme", key_version="v1",
            timestamp=self.NOW, event_id="evt-x", sequence=1, body=b"{}",
        )
        headers = {
            "X-Webhook-Protocol": "webhook-v1",
            "X-Partner-Id": "acme",
            "X-Key-Version": "v1",
            # 故意缺少 X-Timestamp
            "X-Event-Id": "evt-x",
            "X-Sequence": "1",
            "X-Signature": sign(decode_secret(b64("old-secret")), canonical),
        }
        result = self.service.receive(
            method="POST", path=PATH, raw_headers=headers, body=b"{}"
        )
        self.assertEqual(result.result, REJECTED)
        self.assertEqual(result.reason, "missing_headers")
        self.assertEqual(result.http_status, 400)
        # 拒绝也必须留痕
        records = self.storage.query_records(result=REJECTED)
        self.assertEqual(len(records), 1)

    def test_bad_protocol_rejected(self):
        headers = self.signed_headers(
            partner="acme", key_version="v1", secret="old-secret",
            event_id="evt-p", sequence=1, timestamp=self.NOW, body=b"{}",
        )
        headers["X-Webhook-Protocol"] = "webhook-v9"
        out = self.service.receive(
            method="POST", path=PATH, raw_headers=headers, body=b"{}"
        )
        self.assertEqual(out.reason, "bad_protocol")
        self.assertEqual(out.http_status, 400)

    def test_unknown_partner_and_key_version(self):
        r1 = self.deliver(self.service, partner="nobody",
                          key_version="v1", secret="old-secret")
        self.assertEqual(r1.reason, "unknown_partner")
        self.assertEqual(r1.http_status, 404)

        r2 = self.deliver(self.service, key_version="v9",
                          secret="old-secret", event_id="evt-k")
        self.assertEqual(r2.reason, "unknown_key_version")
        self.assertEqual(r2.http_status, 401)


class SignatureTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_bad_signature_rejected(self):
        result = self.deliver(self.service, bad_signature=True,
                              event_id="evt-bad")
        self.assertEqual(result.result, REJECTED)
        self.assertEqual(result.reason, "bad_signature")
        # 签名失败不得产生事件或 outbox
        self.assertEqual(self.storage.list_events(), [])
        self.assertEqual(self.storage.pending_outbox(), [])

    def test_canonical_byte_difference_invalidates_signature(self):
        # 用载荷 A 算出的签名，服务端收到字节不同的载荷 B
        headers = self.signed_headers(
            partner="acme", key_version="v1", secret="old-secret",
            event_id="evt-c", sequence=1, timestamp=self.NOW,
            body=b'{"a":1}',
        )
        result = self.service.receive(
            method="POST", path=PATH, raw_headers=headers,
            body=b'{"a": 1}',  # 仅多一个空格，哈希已不同
        )
        self.assertEqual(result.reason, "bad_signature")

    def test_wrong_path_invalidates_signature(self):
        headers = self.signed_headers(
            partner="acme", key_version="v1", secret="old-secret",
            event_id="evt-path", sequence=1, timestamp=self.NOW, body=b"{}",
        )
        result = self.service.receive(
            method="POST", path="/webhook/different",
            raw_headers=headers, body=b"{}",
        )
        self.assertEqual(result.reason, "bad_signature")


class TimeWindowTest(WebhookTestCase):

    SKEW = 300

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys(skew=self.SKEW))
        self.service = self.make_service()

    def test_window_boundaries_inclusive(self):
        # 恰好等于偏差上限：接受（边界包含）
        r_edge = self.deliver(
            self.service, timestamp=self.NOW - self.SKEW, event_id="evt-edge",
            sequence=1,
        )
        self.assertEqual(r_edge.result, ACCEPTED)

        r_edge2 = self.deliver(
            self.service, timestamp=self.NOW + self.SKEW,
            event_id="evt-edge2", sequence=2,
        )
        self.assertEqual(r_edge2.result, ACCEPTED)

        # 超出 1 秒：拒绝
        r_out = self.deliver(
            self.service, timestamp=self.NOW - self.SKEW - 1,
            event_id="evt-out", sequence=3,
        )
        self.assertEqual(r_out.reason, "timestamp_outside_window")
        self.assertEqual(r_out.http_status, 401)

    def test_malformed_timestamp_and_sequence(self):
        headers = self.signed_headers(
            partner="acme", key_version="v1", secret="old-secret",
            event_id="evt-t", sequence=1, timestamp=self.NOW, body=b"{}",
        )
        headers["X-Timestamp"] = "not-a-number"
        r1 = self.service.receive(
            method="POST", path=PATH, raw_headers=headers, body=b"{}"
        )
        self.assertEqual(r1.reason, "bad_timestamp")

        headers = self.signed_headers(
            partner="acme", key_version="v1", secret="old-secret",
            event_id="evt-s", sequence=1, timestamp=self.NOW, body=b"{}",
        )
        headers["X-Sequence"] = "-3"
        r2 = self.service.receive(
            method="POST", path=PATH, raw_headers=headers, body=b"{}"
        )
        self.assertEqual(r2.reason, "bad_sequence")


class KeyHandoverTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_both_keys_accepted_during_overlap(self):
        # 切换重叠窗口内，旧密钥在途请求与新密钥请求都合法
        r_old = self.deliver(self.service, key_version="v1",
                             secret="old-secret", event_id="evt-old",
                             sequence=1)
        r_new = self.deliver(self.service, key_version="v2",
                             secret="new-secret", event_id="evt-new",
                             sequence=2)
        self.assertEqual(r_old.result, ACCEPTED)
        self.assertEqual(r_new.result, ACCEPTED)

    def test_expired_key_cannot_reenter(self):
        # 时钟推进到 v1 失效之后；用旧时间戳签名的请求即使签名正确，
        # 也会因密钥在声称时间点已失效而被拒绝（过期签名不能重新进入）
        self.clock.value = 2_000_000_700  # v1 not_after=2_000_000_600
        r = self.deliver(
            self.service, key_version="v1", secret="old-secret",
            event_id="evt-old-expired", sequence=1,
            timestamp=2_000_000_500,  # 落在 v1 窗口内、但在当前时间窗内
        )
        self.assertEqual(r.reason, "key_expired")
        self.assertEqual(r.http_status, 401)

    def test_key_not_before_boundary(self):
        # v2 从 2_000_000_000 起生效；之前一刻不能使用
        r_early = self.deliver(
            self.service, key_version="v2", secret="new-secret",
            event_id="evt-early", sequence=1,
            timestamp=1_999_999_999,
        )
        self.assertEqual(r_early.reason, "key_expired")

        r_ok = self.deliver(
            self.service, key_version="v2", secret="new-secret",
            event_id="evt-ok", sequence=2, timestamp=2_000_000_000,
        )
        self.assertEqual(r_ok.result, ACCEPTED)

    def test_replay_after_rotation_with_new_key_succeeds(self):
        # 原请求用 v1 接收；切换后用保存的原始体 + v2 重新签名可重放
        r1 = self.deliver(self.service, key_version="v1",
                          secret="old-secret", event_id="evt-rot",
                          sequence=1)
        self.assertEqual(r1.result, ACCEPTED)
        record = self.storage.get_record(r1.record_id)
        body = self.storage.get_raw_body(record["body_sha256"])

        from partner_webhook.canonical import canonical_bytes
        from partner_webhook.crypto import decode_secret, sign
        canonical = canonical_bytes(
            method="POST", path=PATH, partner_id="acme", key_version="v2",
            timestamp=self.NOW, event_id="evt-rot", sequence=1, body=body,
        )
        headers = self.signed_headers(
            partner="acme", key_version="v2", secret="new-secret",
            event_id="evt-rot", sequence=1, timestamp=self.NOW, body=body,
        )
        self.assertEqual(headers["X-Key-Version"], "v2")
        r2 = self.service.receive(
            method="POST", path=PATH, raw_headers=headers, body=body
        )
        # 同 ID 同载荷 -> 幂等重复，不重复进下游
        self.assertEqual(r2.result, DUPLICATE)
        self.assertEqual(len(self.storage.pending_outbox()), 1)


class DeduplicationAndConflictTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_duplicate_delivery_is_idempotent(self):
        kw = dict(event_id="evt-dup", sequence=7, body=b'{"x":1}')
        r1 = self.deliver(self.service, **kw)
        r2 = self.deliver(self.service, **kw)  # 模拟超时重投
        self.assertEqual(r1.result, ACCEPTED)
        self.assertEqual(r2.result, DUPLICATE)
        self.assertEqual(r2.reason, "duplicate_event")
        self.assertEqual(r2.http_status, 200)
        # 事件与 outbox 仍然只有一份
        self.assertEqual(len(self.storage.list_events()), 1)
        self.assertEqual(len(self.storage.pending_outbox()), 1)
        # 两次投递都有流水可查
        rows = self.storage.query_records(partner_id="acme")
        self.assertEqual([r["result"] for r in rows],
                         [ACCEPTED, DUPLICATE])

    def test_same_id_different_payload_is_conflict_and_isolated(self):
        r1 = self.deliver(self.service, event_id="evt-cf", sequence=1,
                          body=b'{"version":1}')
        self.assertEqual(r1.result, ACCEPTED)

        r2 = self.deliver(self.service, event_id="evt-cf", sequence=1,
                          body=b'{"version":2}')  # 同 ID 不同载荷
        self.assertEqual(r2.result, CONFLICT)
        self.assertEqual(r2.reason, "conflicting_event_id")
        self.assertEqual(r2.http_status, 409)

        # 原事件保持不变，冲突载荷被隔离，不进 outbox
        events = self.storage.list_events()
        self.assertEqual(len(events), 1)
        original = self.storage.get_raw_body(events[0]["body_sha256"])
        self.assertEqual(original, b'{"version":1}')
        self.assertEqual(len(self.storage.pending_outbox()), 1)

        # 冲突流水保留了冲突载荷的摘要，可审计
        conflict_row = self.storage.query_records(result=CONFLICT)[0]
        self.assertNotEqual(conflict_row["body_sha256"],
                            events[0]["body_sha256"])

    def test_out_of_order_sequences_are_kept_not_deduped(self):
        # 乱序到达：seq 3 -> seq 1 -> seq 2，事件 ID 各不相同
        for seq in (3, 1, 2):
            r = self.deliver(
                self.service, event_id=f"evt-seq-{seq}", sequence=seq,
                body=f"payload-{seq}".encode(),
            )
            self.assertEqual(r.result, ACCEPTED)

        # 已接受事件按源序号排序，乱序不影响顺序也不会被误判重复
        events = self.storage.list_events(partner_id="acme")
        self.assertEqual([e["source_seq"] for e in events], [1, 2, 3])

        pending = self.storage.pending_outbox()
        self.assertEqual([p["source_seq"] for p in pending], [1, 2, 3])


class RestartConsistencyTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_records_survive_process_restart(self):
        self.deliver(self.service, event_id="evt-r1", sequence=1)
        self.deliver(self.service, event_id="evt-r2", sequence=2)
        self.deliver(self.service, event_id="evt-r1", sequence=1)  # 重复
        self.deliver(self.service, event_id="evt-bad", sequence=9,
                      bad_signature=True)

        # 模拟进程重启：关闭连接并重新打开同一 SQLite 文件
        service2 = self.reopen_service()

        rows = self.storage.query_records(partner_id="acme")
        self.assertEqual(len(rows), 4)
        self.assertEqual(
            [r["result"] for r in rows],
            [ACCEPTED, ACCEPTED, DUPLICATE, REJECTED],
        )
        events = self.storage.list_events(partner_id="acme")
        self.assertEqual(len(events), 2)
        self.assertEqual(len(self.storage.pending_outbox()), 2)

        # 重启后去重/冲突规则依然生效
        r_dup = self.deliver(service2, event_id="evt-r1", sequence=1)
        self.assertEqual(r_dup.result, DUPLICATE)
        r_cf = self.deliver(service2, event_id="evt-r2", sequence=2,
                            body=b'different')
        self.assertEqual(r_cf.result, CONFLICT)

    def test_migration_is_idempotent_across_restarts(self):
        self.reopen_service()  # 再跑一次迁移
        self.reopen_service()
        version = self.storage.conn.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, 1)
        # 表都还在且数据未损坏
        tables = {
            r[0] for r in self.storage.iter_all(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertTrue(
            {"raw_bodies", "ingest_records",
             "accepted_events", "outbox"}.issubset(tables)
        )


class ConcurrentDeliveryTest(WebhookTestCase):
    """多线程并发投递同一事件，验证进程内锁 + 主键约束的去重安全性。"""

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_concurrent_same_event_accepted_once(self):
        results: list[str] = []
        errors: list[Exception] = []

        def worker():
            try:
                r = self.deliver(self.service, event_id="evt-race",
                                 sequence=1, body=b'{"race":true}')
                results.append(r.result)
            except Exception as exc:  # 不应有异常冒泡
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 10)
        # 恰好一个 accepted，其余全部 duplicate
        self.assertEqual(results.count(ACCEPTED), 1)
        self.assertEqual(results.count(DUPLICATE), 9)
        self.assertEqual(len(self.storage.list_events()), 1)
        self.assertEqual(len(self.storage.pending_outbox()), 1)


class QueryInterfaceTest(WebhookTestCase):

    def setUp(self):
        super().setUp()
        self.write_config(two_overlapping_keys())
        self.service = self.make_service()

    def test_query_by_partner_and_time_range(self):
        self.deliver(self.service, event_id="evt-a", sequence=1)
        self.clock.value += 100
        self.deliver(self.service, event_id="evt-b", sequence=2,
                     bad_signature=True)
        self.clock.value += 100
        self.deliver(self.service, event_id="evt-c", sequence=3)

        all_rows = self.storage.query_records(partner_id="acme")
        self.assertEqual(len(all_rows), 3)

        window = self.storage.query_records(
            partner_id="acme",
            start_ts=self.NOW + 50,
            end_ts=self.NOW + 150,
        )
        self.assertEqual([r["event_id"] for r in window], ["evt-b"])

        rejected = self.storage.query_records(
            partner_id="acme", result=REJECTED
        )
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["reason"], "bad_signature")

        # 其他合作方查不到数据
        self.assertEqual(
            self.storage.query_records(partner_id="globex"), []
        )


if __name__ == "__main__":
    unittest.main()
