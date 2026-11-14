"""下游 HTTP 发送工人验收材料（可复跑，全部断言化）。

演练内容：
1. 真实签名收件制造积压；可控接收器保存原始字节/请求头/已落地 delivery_key，
   预期清单在本文件手写，不从正式发送函数推导；
2. 逐字节核对普通正文、空体、二进制正文；合作方重号（同 event_id）与
   稀疏 source_seq；按 outbox.id 而不是 source_seq 排队；
3. 队首 429：提前运行无请求、到期后重送相同键；期间另一合作方照常送达，
   本合作方下一条不得越过；
4. 接收器先落地再主动断开：重试相同键返回已有结果，只产生一份业务记录；
5. 200 但摘要错 / 3xx / 400 的不同处置；人工重试前后记录；
6. 两个独立进程并发：占用未到期不能抢，过期接手先拿正确回执，最后放行
   旧工人的迟到回执，核对送达时间/尝试归属/下一条不被改变；
7. 已领取未完成的工人被结束，重开进程并推进时刻后接手，delivery_key 不变；
8. 迁移前已 delivered 不重发；源正文失配不出网；旧 drain 不能虚报成功。

输出（--out，默认临时目录）：接收器请求日志、接收端业务记录、本地投递状态
导出、断言输出。用法::

    python3 -I scripts/outbound_acceptance.py [--out 输出目录]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from partner_webhook.canonical import (  # noqa: E402
    HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER, HEADER_PROTOCOL,
    HEADER_SEQUENCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_bytes,
)
from partner_webhook.config import load_config  # noqa: E402
from partner_webhook.crypto import decode_secret, sign  # noqa: E402
from partner_webhook.outbound import (  # noqa: E402
    HEADER_BODY_SHA256, HEADER_DELIVERY_KEY, HEADER_EVENT_ID as OUT_EVENT,
    HEADER_PARTNER as OUT_PARTNER, HEADER_SOURCE_SEQ, DeliveryStore,
    backoff_seconds, delivery_key,
)
from partner_webhook.receiver import Receiver  # noqa: E402
from partner_webhook.service import PROTOCOL_VERSION, WebhookService  # noqa: E402
from partner_webhook.storage import Storage  # noqa: E402

PATH = "/webhook/events"
NOW = 2_000_000_000
ACME_SECRET = "b2xkLWFjbWUtc2VjcmV0LWtleS0wMDE="
GLOBEX_SECRET = "Z2xvYmV4LW9ubHkta2V5LWcwMQ=="

CONFIG = {
    "max_skew_seconds": 300,
    "partners": [
        {"id": "acme", "max_skew_seconds": 300, "keys": [
            {"version": "v1", "secret_b64": ACME_SECRET,
             "not_before": None, "not_after": None}]},
        {"id": "globex", "max_skew_seconds": 300, "keys": [
            {"version": "g1", "secret_b64": GLOBEX_SECRET,
             "not_before": None, "not_after": None}]},
    ],
}

# ---- 手写预期清单（独立于正式发送/接收实现） -------------------------- #
BIN_BODY = bytes(range(256)) + b"\xff\xfe\x00binary"
MANIFEST = {
    # 按收件（outbox.id）顺序插入：seq 故意稀疏且非递增
    "acme": [
        {"event_id": "evt-sparse-big", "source_seq": 9, "body": BIN_BODY},
        {"event_id": "evt-empty", "source_seq": 2, "body": b""},
        {"event_id": "evt-normal", "source_seq": 1, "body": b'{"order":1}'},
        {"event_id": "evt-shared", "source_seq": 20, "body": b'{"shared":1}'},
    ],
    "globex": [
        {"event_id": "g-sparse-30", "source_seq": 30, "body": b'{"g":30}'},
        {"event_id": "g-sparse-10", "source_seq": 10, "body": b'{"g":10}'},
        # 与合作方 acme 的 evt-shared 同号、同字节：delivery_key 必须不同
        {"event_id": "evt-shared", "source_seq": 20, "body": b'{"shared":1}'},
    ],
}

FAILURES: list[str] = []
CHECKS: list[str] = []


def check(label: str, actual, expected) -> None:
    ok = actual == expected
    line = ("PASS " if ok else "FAIL ") + label
    print(("  " + line))
    CHECKS.append(line)
    if not ok:
        print(f"         expected={expected!r} actual={actual!r}")
        FAILURES.append(label)


def check_true(label: str, condition: bool) -> None:
    check(label, bool(condition), True)


# --------------------------------------------------------------------- #
def make_deliverer(storage: Storage, config_path: Path):
    service = WebhookService(load_config(config_path), storage, clock=lambda: NOW)

    def deliver(partner: str, event_id: str, sequence: int,
                body: bytes) -> None:
        secret = ACME_SECRET if partner == "acme" else GLOBEX_SECRET
        key_version = "v1" if partner == "acme" else "g1"
        canonical = canonical_bytes(
            method="POST", path=PATH, partner_id=partner,
            key_version=key_version, timestamp=NOW, event_id=event_id,
            sequence=sequence, body=body,
        )
        headers = {
            HEADER_PROTOCOL: PROTOCOL_VERSION, HEADER_PARTNER: partner,
            HEADER_KEY_VERSION: key_version, HEADER_TIMESTAMP: str(NOW),
            HEADER_EVENT_ID: event_id, HEADER_SEQUENCE: str(sequence),
            HEADER_SIGNATURE: sign(decode_secret(secret), canonical),
        }
        result = service.receive(method="POST", path=PATH,
                                 raw_headers=headers, body=body)
        assert result.result == "accepted", (partner, event_id, result.reason)

    return deliver


class Drill:
    """一个独立演练：独立配置、数据库、接收器与工人子进程。"""

    def __init__(self, work: Path, name: str, plan: dict | None = None):
        self.name = name
        self.dir = work / name
        self.dir.mkdir(parents=True)
        self.config_path = self.dir / "config.json"
        self.config_path.write_text(json.dumps(CONFIG), encoding="utf-8")
        self.db_path = self.dir / "source.db"
        self.storage = Storage(str(self.db_path))
        self.deliver = make_deliverer(self.storage, self.config_path)
        self.receiver = Receiver(self.dir / "receiver", plan=plan)
        self.receiver.state.clock = lambda: float(NOW)
        self.url = self.receiver.start()
        self._workers: list[subprocess.Popen] = []

    def close(self) -> None:
        for proc in self._workers:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
        self.receiver.stop()
        self.storage.close()

    # -- helpers ----------------------------------------------------
    def register(self, partner: str) -> None:
        store = self._store()
        try:
            store.register_endpoint(partner, self.url + "/ingest", NOW)
        finally:
            store.close()

    def _store(self) -> DeliveryStore:
        return DeliveryStore(str(self.db_path))

    def cli(self, *args: str, now: int | None = NOW,
            allow_fail: bool = False,
            db_path: str | None = None) -> subprocess.CompletedProcess:
        command = [sys.executable, "-I",
                   str(REPO_ROOT / "partner_webhook" / "cli.py"),
                   "--config", str(self.config_path),
                   "--db", db_path or str(self.db_path),
                   *args]
        if now is not None and args and args[0] == "outbox-run":
            command += ["--now", str(now)]
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=120)
        if result.returncode != 0 and not allow_fail:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            raise SystemExit(f"命令失败: {' '.join(command)}")
        return result

    def run_partner(self, partner: str, now: int, *,
                    max_attempts: int = 10, extra: list[str] | None = None,
                    allow_fail: bool = False) -> dict:
        result = self.cli("outbox-run", "--partner", partner,
                          "--max-attempts", str(max_attempts),
                          *(extra or []), now=now, allow_fail=allow_fail)
        if result.returncode != 0:
            return {"returncode": result.returncode, "stderr": result.stderr}
        return json.loads(result.stdout)["reports"][0]

    def spawn_worker(self, partner: str, now: int, *,
                     max_attempts: int = 10, lease: int = 60,
                     timeout: float = 60.0, worker_id: str) -> subprocess.Popen:
        command = [sys.executable, "-I",
                   str(REPO_ROOT / "partner_webhook" / "cli.py"),
                   "--config", str(self.config_path), "--db", str(self.db_path),
                   "outbox-run", "--partner", partner,
                   "--max-attempts", str(max_attempts),
                   "--lease-seconds", str(lease),
                   "--timeout", str(timeout),
                   "--worker-id", worker_id,
                   "--now", str(now)]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        self._workers.append(proc)
        return proc

    @staticmethod
    def finish_process(proc: subprocess.Popen) -> tuple[int, str, str]:
        out, err = proc.communicate(timeout=120)
        return proc.returncode, out, err

    def state(self, partner: str, event_id: str) -> dict:
        store = self._store()
        try:
            return store.event_attempts(partner, event_id)
        finally:
            store.close()

    def queue(self, partner: str) -> list[dict]:
        store = self._store()
        try:
            return store.partner_queue(partner, limit=100)
        finally:
            store.close()

    def wait_requests(self, delivery_key_value: str, count: int = 1,
                      timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.receiver.requests_for(delivery_key_value)) >= count:
                return
            time.sleep(0.02)
        raise SystemExit(
            f"[{self.name}] 等待请求超时: key={delivery_key_value} count={count}")

    def request_body(self, entry: dict) -> bytes:
        return (self.dir / "receiver" / entry["body_file"]).read_bytes()


# --------------------------------------------------------------------- #
def section(title: str) -> None:
    print(f"\n== {title} ==")
    CHECKS.append(f"\n== {title} ==")


def run_delivery_drill(work: Path) -> None:
    section("1. 真实收件 → 逐字节交付（普通/空体/二进制、重号、稀疏序号、按 id 排队）")
    drill = Drill(work, "delivery")
    try:
        for partner, items in MANIFEST.items():
            for item in items:
                drill.deliver(partner, item["event_id"], item["source_seq"],
                              item["body"])
            drill.register(partner)

        # 队列按本地 outbox.id，而不是 source_seq
        acme_queue = drill.queue("acme")
        check("acme 队列顺序 == 收件 id 顺序（不看 source_seq）",
              [(q["event_id"], q["source_seq"]) for q in acme_queue],
              [(m["event_id"], m["source_seq"]) for m in MANIFEST["acme"]])
        check("acme 的 source_seq 非递增（稀疏序号未重排）",
              [q["source_seq"] for q in acme_queue], [9, 2, 1, 20])

        report_a = drill.run_partner("acme", NOW, max_attempts=20)
        report_g = drill.run_partner("globex", NOW, max_attempts=20)
        check("acme 全部送达（按 id 顺序）", report_a["delivered"],
              [m["event_id"] for m in MANIFEST["acme"]])
        check("globex 全部送达（按 id 顺序）", report_g["delivered"],
              [m["event_id"] for m in MANIFEST["globex"]])

        # 逐字节核对（手写清单）
        for partner, items in MANIFEST.items():
            for item in items:
                sha = hashlib.sha256(item["body"]).hexdigest()
                key = delivery_key(partner, item["event_id"], sha)
                reqs = drill.receiver.requests_for(key)
                check(f"[{partner}/{item['event_id']}] 恰好一次请求",
                      len(reqs), 1)
                entry = reqs[0]
                check(f"[{partner}/{item['event_id']}] 原始字节逐字节一致",
                      drill.request_body(entry), item["body"])
                check(f"[{partner}/{item['event_id']}] 头部 source_seq 往返",
                      entry["headers"].get(HEADER_SOURCE_SEQ),
                      str(item["source_seq"]))
                check(f"[{partner}/{item['event_id']}] 头部摘要 == 实际摘要",
                      entry["headers"].get(HEADER_BODY_SHA256), sha)
                check(f"[{partner}/{item['event_id']}] 头部合作方/事件 ID",
                      (entry["headers"].get(OUT_PARTNER),
                       entry["headers"].get(OUT_EVENT)),
                      (partner, item["event_id"]))
                check(f"[{partner}/{item['event_id']}] 不转发入站签名",
                      "X-Signature" in entry["headers"], False)
                # 接收端自己落地的 delivery_key 与请求头一致
                check(f"[{partner}/{item['event_id']}] 接收端落地键 == 请求头键",
                      drill.receiver.records()[key]["delivery_key"],
                      entry["headers"].get(HEADER_DELIVERY_KEY))
                # outbox 只有在有效回执后才 delivered
                state = drill.state(partner, item["event_id"])
                check(f"[{partner}/{item['event_id']}] outbox 已 delivered 且有确认时间",
                      (state["outbox"]["status"],
                       state["outbox"]["delivered_at"] is not None),
                      ("delivered", True))
                check(f"[{partner}/{item['event_id']}] 尝试记录为 success/200",
                      (state["attempts"][0]["outcome"],
                       state["attempts"][0]["http_status"]),
                      ("success", 200))

        # 合作方重号：同 event_id、同字节，delivery_key 必须不同
        acme_key = delivery_key("acme", "evt-shared",
                                hashlib.sha256(b'{"shared":1}').hexdigest())
        globex_key = delivery_key("globex", "evt-shared",
                                  hashlib.sha256(b'{"shared":1}').hexdigest())
        check("合作方重号事件的 delivery_key 不同", acme_key == globex_key, False)
        check("两方重号事件各产生一条接收端业务记录",
              len(drill.receiver.requests_for(acme_key))
              + len(drill.receiver.requests_for(globex_key)), 2)
    finally:
        drill.close()


def run_backoff_drill(work: Path) -> None:
    section("2. 队首 429：提前不发、到期同键重送；其他合作方不被阻塞")
    plan = {"default": [{"kind": "ok"}], "events": {
        "acme/evt-head": [{"kind": "429", "retry_after": "5"},
                          {"kind": "ok"}],
    }}
    drill = Drill(work, "backoff", plan)
    try:
        drill.deliver("acme", "evt-head", 1, b'{"n":1}')
        drill.deliver("acme", "evt-next", 2, b'{"n":2}')
        drill.deliver("globex", "g-ok", 1, b'{"g":1}')
        drill.register("acme")
        drill.register("globex")

        first = drill.run_partner("acme", NOW, max_attempts=5)
        check("首轮队首 429 进可重试等待",
              (first["retry_wait"][0]["event_id"],
               first["retry_wait"][0]["http_status"],
               first["retry_wait"][0]["next_attempt_at"]),
              ("evt-head", 429, NOW + 5))
        check("首轮没有送达、没有越过下一条",
              (first["delivered"], drill.state("acme", "evt-next")["outbox"]["status"]),
              ([], "pending"))
        count_before = drill.receiver.request_count()

        early = drill.run_partner("acme", NOW + 4, max_attempts=5)
        check("未到期提前运行：零网络尝试",
              (early["attempts"], early["deferred_head"]["blocked_by"],
               early["deferred_head"]["wait_seconds"]),
              (0, "backoff", 1))
        check("提前运行没有发出任何请求",
              drill.receiver.request_count(), count_before)

        globe = drill.run_partner("globex", NOW, max_attempts=5)
        check("期间另一合作方照常送达", globe["delivered"], ["g-ok"])

        due = drill.run_partner("acme", NOW + 5, max_attempts=5)
        check("到期后队首先送达，再放下一条", due["delivered"],
              ["evt-head", "evt-next"])
        key = delivery_key("acme", "evt-head",
                           hashlib.sha256(b'{"n":1}').hexdigest())
        reqs = drill.receiver.requests_for(key)
        check("两次请求使用相同 delivery_key", len(reqs), 2)
        check("两次请求键完全一致",
              {req["headers"].get(HEADER_DELIVERY_KEY) for req in reqs},
              {key})
        attempts = drill.state("acme", "evt-head")["attempts"]
        check("尝试记录保留首次 429 与最终成功",
              [(a["outcome"], a["http_status"]) for a in attempts],
              [("retryable_failure", 429), ("success", 200)])
        check("退避到期时间记录在本地状态",
              attempts[0]["detail_json"] is not None, True)
    finally:
        drill.close()


def run_disconnect_drill(work: Path) -> None:
    section("3. 接收端先落地再断开：同键重试，只产生一份下游业务记录")
    plan = {"default": [{"kind": "ok"}], "events": {
        "acme/evt-cut": [{"kind": "disconnect_after_save", "wait_seconds": 0.1},
                         {"kind": "ok"}],
    }}
    drill = Drill(work, "disconnect", plan)
    try:
        drill.deliver("acme", "evt-cut", 1, b'{"cut":1}')
        drill.register("acme")
        first = drill.run_partner("acme", NOW, max_attempts=5)
        check("首次因连接中断进入可重试",
              (first["retry_wait"][0]["event_id"],
               first["retry_wait"][0]["http_status"]),
              ("evt-cut", None))
        check("接收端已落地一份业务记录（但发送方未确认）",
              len(drill.receiver.records()), 1)
        check("发送方 outbox 仍为 pending",
              drill.state("acme", "evt-cut")["outbox"]["status"], "pending")

        second = drill.run_partner("acme", NOW + 1, max_attempts=5)
        check("重试后确认送达", second["delivered"], ["evt-cut"])
        key = delivery_key("acme", "evt-cut",
                           hashlib.sha256(b'{"cut":1}').hexdigest())
        check("重试使用相同 delivery_key，共两次请求",
              len(drill.receiver.requests_for(key)), 2)
        check("接收端按同键返回已有结果，仍只有一份业务记录",
              len(drill.receiver.records()), 1)
        record = next(iter(drill.receiver.records().values()))
        check("第二次回执即为已落地记录的键",
              record["delivery_key"], key)
        check("最终 outbox 已 delivered",
              drill.state("acme", "evt-cut")["outbox"]["status"], "delivered")
    finally:
        drill.close()


def run_failure_drill(work: Path) -> None:
    section("4. 200 但摘要错 / 3xx / 4xx 的处置与人工重试记录")
    plan = {"default": [{"kind": "ok"}], "events": {
        "acme/evt-badsha": [{"kind": "ok_wrong_sha"}, {"kind": "ok"}],
        "acme/evt-400": [{"kind": "status", "status": 400}, {"kind": "ok"}],
        "acme/evt-redirect": [{"kind": "redirect", "status": 302}],
    }}
    drill = Drill(work, "dispositions", plan)
    try:
        drill.deliver("acme", "evt-badsha", 1, b'{"bad":1}')
        drill.deliver("acme", "evt-400", 2, b'{"bad":2}')
        drill.deliver("acme", "evt-redirect", 3, b'{"bad":3}')
        drill.register("acme")

        first = drill.run_partner("acme", NOW, max_attempts=5)
        check("200 但摘要错：判无效回执，不标送达",
              (first["retry_wait"][0]["event_id"],
               first["retry_wait"][0]["http_status"],
               "receipt_field_mismatch" in first["retry_wait"][0]["reason"]),
              ("evt-badsha", 200, True))
        check("摘要错时 outbox 仍 pending",
              drill.state("acme", "evt-badsha")["outbox"]["status"], "pending")

        second = drill.run_partner("acme", NOW + 1, max_attempts=5)
        check("重试正确回执后送达；下一条 400 永久失败",
              (second["delivered"],
               second["permanent_failure"][0]["http_status"]),
              (["evt-badsha"], 400))
        check("400 记录具体状态码与原因",
              (drill.state("acme", "evt-400")["delivery"]["last_http_status"],
               drill.state("acme", "evt-400")
               ["delivery"]["last_failure_reason"]),
              (400, "http_4xx_client_error"))
        count_before_retry = drill.receiver.request_count()

        # 永久失败不人工重试就不会再发（也不越过）
        blocked = drill.run_partner("acme", NOW + 2, max_attempts=5)
        check("永久失败未人工重试：不自动发、不越过",
              (blocked["attempts"], blocked["deferred_head"]["blocked_by"]),
              (0, "permanent_failure"))
        check("未人工重试时没有新请求",
              drill.receiver.request_count(), count_before_retry)

        before = drill.state("acme", "evt-400")
        retry = json.loads(drill.cli(
            "outbox-retry", "--partner", "acme", "--event-id", "evt-400",
            "--operator", "ops-drill", now=NOW + 2).stdout)
        check("人工重试把状态放回 pending 且轮次清零",
              (retry["status"], retry["attempt_no"]), ("pending", 0))
        after = drill.state("acme", "evt-400")
        check("人工重试保留此前尝试记录",
              len(after["attempts"]), len(before["attempts"]))
        check("人工重试留下操作者动作审计",
              [(a["action"], json.loads(a["detail_json"])["operator"])
               for a in after["operator_actions"]],
              [("retry_permanent", "ops-drill")])
        check("尝试归属仍为失败那次（人工动作不改写历史）",
              after["attempts"][0]["outcome"], "permanent_failure")

        third = drill.run_partner("acme", NOW + 2, max_attempts=5)
        check("人工重试后可继续；3xx 不跟随，按永久失败处理",
              (third["delivered"],
               third["permanent_failure"][0]["event_id"],
               third["permanent_failure"][0]["http_status"],
               third["permanent_failure"][0]["reason"]),
              (["evt-400"], "evt-redirect", 302,
               "http_redirect_not_followed"))
        check("3xx 未跟随（接收端只收到一次该事件请求）",
              len(drill.receiver.requests_for(delivery_key(
                  "acme", "evt-redirect",
                  hashlib.sha256(b'{"bad":3}').hexdigest()))), 1)
        check("重试后尝试序列为 失败→成功",
              [a["outcome"] for a in
               drill.state("acme", "evt-400")["attempts"]],
              ["permanent_failure", "success"])
    finally:
        drill.close()


def run_concurrency_drill(work: Path) -> None:
    section("5. 两进程并发：占用未到期不抢 / 过期接手 / 旧回执迟到不覆盖")
    plan = {"default": [{"kind": "ok"}], "events": {
        "acme/evt-held": [{"kind": "hold", "gate": "held", "wait_seconds": 120},
                          {"kind": "ok"}],
    }}
    drill = Drill(work, "concurrency", plan)
    try:
        drill.deliver("acme", "evt-held", 1, b'{"held":1}')
        drill.deliver("acme", "evt-after", 2, b'{"after":2}')
        drill.deliver("globex", "g-live", 1, b'{"g":1}')
        drill.register("acme")
        drill.register("globex")
        key = delivery_key("acme", "evt-held",
                           hashlib.sha256(b'{"held":1}').hexdigest())

        worker_a = drill.spawn_worker("acme", NOW, max_attempts=5,
                                      lease=30, timeout=60, worker_id="worker-A")
        drill.wait_requests(key, 1)
        in_flight = drill.state("acme", "evt-held")["delivery"]
        check("工人甲已持有未到期占用",
              (in_flight["status"], in_flight["lease_owner"],
               in_flight["lease_expires_at"]),
              ("in_flight", "worker-A", NOW + 30))

        blocked = drill.run_partner("acme", NOW, max_attempts=1)
        check("工人乙在占用未到期时不能抢走",
              (blocked["attempts"], blocked["stopped_reason"]),
              (0, "head_not_ready"))
        globe = drill.run_partner("globex", NOW, max_attempts=5)
        check("其他合作方仍能同时发送", globe["delivered"], ["g-live"])

        takeover = drill.run_partner("acme", NOW + 31, max_attempts=5)
        check("占用过期后接手并送达队首与下一条",
              takeover["delivered"], ["evt-held", "evt-after"])
        delivered_at = drill.state("acme", "evt-held")["outbox"]["delivered_at"]
        check("送达时间由接手工人写入", delivered_at, NOW + 31)

        # 放行甲的旧回执；它迟到且凭据已失效
        drill.receiver.state.release("held")
        code, out, err = drill.finish_process(worker_a)
        check("旧工人进程正常结束", code, 0)
        report_a = json.loads(out)["reports"][0]
        check("旧工人的回执被标为迟到，不计成功",
              (report_a["delivered"], report_a["late"][0]["reason"]),
              ([], "lease_superseded"))
        after = drill.state("acme", "evt-held")
        check("旧回执未覆盖送达时间",
              after["outbox"]["delivered_at"], delivered_at)
        check("旧尝试归属为过期接手，迟到结果另行记录",
              (after["attempts"][0]["worker_id"],
               after["attempts"][0]["outcome"],
               after["attempts"][0]["late_outcome"]),
              ("worker-A", "lease_expired_takeover", "success"))
        check("最终完成归属接手工人（不是旧工人）",
              (after["attempts"][-1]["worker_id"] != "worker-A",
               after["attempts"][-1]["outcome"]),
              (True, "success"))
        check("下一条只由接手工人送达一次",
              (drill.state("acme", "evt-after")["delivery"]["status"],
               len(drill.receiver.requests_for(delivery_key(
                   "acme", "evt-after",
                   hashlib.sha256(b'{"after":2}').hexdigest())))),
              ("delivered", 1))
        check("接手的下一次发送未被旧工人改变（队首后无待发）",
              [q["event_id"] for q in drill.queue("acme")
               if q["outbox_status"] != "delivered"], [])
        check("接收端对同键共收到两次请求（至少一次语义）",
              len(drill.receiver.requests_for(key)), 2)
    finally:
        drill.close()


def run_orphan_drill(work: Path) -> None:
    section("6. 已领取工人被结束 → 重开进程推进时刻接手，delivery_key 不变")
    plan = {"default": [{"kind": "ok"}], "events": {
        "acme/evt-orphan": [{"kind": "hold", "gate": "orphan",
                             "wait_seconds": 120}, {"kind": "ok"}],
    }}
    drill = Drill(work, "orphan", plan)
    try:
        drill.deliver("acme", "evt-orphan", 1, b'{"orphan":1}')
        drill.register("acme")
        key = delivery_key("acme", "evt-orphan",
                           hashlib.sha256(b'{"orphan":1}').hexdigest())

        proc = drill.spawn_worker("acme", NOW, max_attempts=5, lease=30,
                                  timeout=120, worker_id="dying-worker")
        drill.wait_requests(key, 1)
        claimed = drill.state("acme", "evt-orphan")["delivery"]
        check("工人已领取并等待回执",
              (claimed["status"], claimed["lease_owner"]),
              ("in_flight", "dying-worker"))
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
        check("工人进程被结束（模拟失联）", proc.returncode != 0, True)

        pre = drill.run_partner("acme", NOW + 5, max_attempts=1)
        check("占用未到期：重开进程也不能接手",
              pre["attempts"], 0)

        reopened = drill.run_partner("acme", NOW + 31, max_attempts=5)
        check("推进时刻后重开进程接手并送达",
              reopened["delivered"], ["evt-orphan"])
        data = drill.state("acme", "evt-orphan")
        check("接手原因被记录",
              (data["attempts"][-1]["takeover_reason"],
               data["attempts"][-1]["previous_worker_id"]),
              ("lease_expired", "dying-worker"))
        check("两次尝试使用同一 delivery_key（未生成新键）",
              {a["delivery_key"] for a in data["attempts"]}, {key})
        check("旧尝试被标为过期接手",
              data["attempts"][0]["outcome"], "lease_expired_takeover")
        check("接收端只产生一份业务记录",
              len(drill.receiver.records()), 1)
        drill.receiver.state.release("orphan")
        time.sleep(0.1)
    finally:
        drill.close()


def run_legacy_drill(work: Path) -> None:
    section("7. 迁移前已 delivered 不重发 / 源正文失配不出网 / 旧 drain 不虚报")
    drill = Drill(work, "legacy")
    try:
        # 模拟迁移前的库：只有 0001 的表，既有记录已 delivered
        old_db = drill.dir / "old.db"
        conn = sqlite3.connect(old_db)
        conn.executescript(
            (REPO_ROOT / "migrations" / "0001_init.sql").read_text(
                encoding="utf-8"))
        body = b'{"legacy":1}'
        sha = hashlib.sha256(body).hexdigest()
        conn.execute(
            "INSERT INTO raw_bodies (body_sha256, body_blob, byte_length,"
            " first_seen_at) VALUES (?, ?, ?, ?)", (sha, body, len(body), NOW))
        conn.execute(
            "INSERT INTO outbox (partner_id, event_id, source_seq,"
            " body_sha256, created_at, status, delivered_at)"
            " VALUES ('acme', 'evt-legacy', 1, ?, ?, 'delivered', ?)",
            (sha, NOW, NOW - 1000))
        conn.commit()
        conn.close()
        check("迁移前库 user_version=1",
              sqlite3.connect(old_db).execute("PRAGMA user_version").fetchone()[0],
              1)
        # 用 CLI 触发迁移（init-db 会执行 0002），不破坏既有收件记录
        drill.cli("init-db", now=None, db_path=str(old_db))
        # 投递状态全部在旧库上操作：把演练切换到迁移后的旧库
        drill.storage.close()
        drill.db_path = str(old_db)
        drill.storage = Storage(str(old_db))
        drill.deliver = make_deliverer(drill.storage, drill.config_path)
        drill.register("acme")
        conn = sqlite3.connect(old_db)
        check("迁移后既有 delivered 记录仍在",
              conn.execute("SELECT status FROM outbox WHERE event_id="
                           "'evt-legacy'").fetchone()[0], "delivered")
        check("迁移后 user_version=2",
              conn.execute("PRAGMA user_version").fetchone()[0], 2)
        conn.close()

        # 另建一条正文与摘要失配的事件（登记摘要保留，字节被篡改）
        drill.deliver("acme", "evt-corrupt", 2, b'{"corrupt":1}')
        conn = sqlite3.connect(drill.db_path)
        sha2 = conn.execute("SELECT body_sha256 FROM outbox WHERE event_id="
                            "'evt-corrupt'").fetchone()[0]
        conn.execute("UPDATE raw_bodies SET body_blob=? WHERE body_sha256=?",
                     (b'{"corrupt":2}', sha2))
        conn.commit()
        conn.close()

        report = drill.run_partner("acme", NOW + 10, max_attempts=5)
        check("历史 delivered 不进入队列（队首直接是 evt-corrupt）",
              (report["delivered"],
               report["local_error"][0]["event_id"]),
              ([], "evt-corrupt"))
        check("源正文失配被识别为本地故障，不出网",
              "body_sha256_mismatch" in report["local_error"][0]["reason"],
              True)
        check("接收端没有收到任何请求",
              drill.receiver.request_count(), 0)
        state = drill.state("acme", "evt-corrupt")
        check("本地坏数据不标 delivered",
              (state["outbox"]["status"],
               state["delivery"]["status"]),
              ("pending", "permanent_failure"))

        # 旧 drain-outbox 已停用：退出码 2 且提示新命令，不改状态
        drain = drill.cli("drain-outbox", now=None, allow_fail=True)
        check("旧 drain-outbox 退出码为 2", drain.returncode, 2)
        check("旧 drain-outbox 提示新命令",
              "outbox-run" in drain.stderr, True)
        check("旧 drain-outbox 后积压仍为 pending",
              drill.state("acme", "evt-corrupt")["outbox"]["status"], "pending")
    finally:
        drill.close()


# --------------------------------------------------------------------- #
def dump_local_state(drill_dir: Path, out_path: Path) -> None:
    db = drill_dir / "source.db"
    if not db.exists():
        return
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    data = {}
    for table in ("outbox", "outbox_delivery", "delivery_attempts",
                  "delivery_operator_actions", "delivery_endpoints"):
        try:
            data[table] = [dict(r) for r in conn.execute(
                f"SELECT * FROM {table} ORDER BY rowid")]
        except sqlite3.Error:
            data[table] = []
    conn.close()
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2,
                                   sort_keys=True, default=str),
                        encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None,
                        help="保存接收器日志/本地状态/断言的目录（默认临时目录）")
    args = parser.parse_args()
    if args.out:
        work = Path(args.out).resolve()
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        temporary = False
    else:
        work = Path(tempfile.mkdtemp(prefix="outbound-acceptance-"))
        temporary = True

    print(f">>> 验收输出目录: {work}")
    started = time.time()
    try:
        run_delivery_drill(work)
        run_backoff_drill(work)
        run_disconnect_drill(work)
        run_failure_drill(work)
        run_concurrency_drill(work)
        run_orphan_drill(work)
        run_legacy_drill(work)
    finally:
        for name in ("delivery", "backoff", "disconnect", "dispositions",
                     "concurrency", "orphan", "legacy"):
            dump_local_state(work / name, work / f"local-state-{name}.json")

    print("\n== 结果 ==")
    summary = {
        "assertions": len([c for c in CHECKS if c.startswith(("PASS", "FAIL"))]),
        "failures": FAILURES,
        "elapsed_seconds": round(time.time() - started, 3),
        "outputs": {
            "receiver_logs": "*/receiver/requests.jsonl",
            "receiver_records": "*/receiver/receiver_state.json",
            "local_state": "local-state-*.json",
            "assertions": "assertions.txt",
        },
    }
    (work / "assertions.txt").write_text(
        "\n".join(CHECKS) + "\n\n" + json.dumps(summary, ensure_ascii=False,
                                                indent=2) + "\n",
        encoding="utf-8")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} 项")
        for item in FAILURES:
            print("  -", item)
        result = 1
    else:
        print(f"全部断言通过（{summary['assertions']} 项）")
        result = 0
    print(f">>> 输出保留在: {work}")
    if temporary:
        print("    （未指定 --out，临时目录不会自动删除以便核对）")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
