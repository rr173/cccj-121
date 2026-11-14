"""设备档案加工管线验收材料（可复跑，全部断言化）。

流程：
1. 用**真实签名收件**（与生产同一条 HMAC 验证流水线）把 seed/patch 写进
   签名接收库，再用 CLI 的 archive-* 命令加工并读回；
2. 预期文档与处置原因另见 :mod:`scripts.archive_examples` 里的**手写**小
   例子——它们只声明输入与期望，不调用正式加工函数生成答案；
3. 覆盖：空键与 ~ 转义、对象数字键与数组下标、同数组前移/后移、copy 后单独
   修改副本、超大整数 test、null 与根删除、后一步失败整条回滚；乱序等待、
   分支退回/人工选择恢复/撤销再退回、跨合作方同号拒绝、两个 seed 冲突、
   失败阻断后续、重复同步无操作、真实退出恢复、合作方隔离。

用法：``python3 -I scripts/archive_acceptance.py``（默认在临时目录运行）。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from partner_webhook.canonical import (  # noqa: E402
    HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER, HEADER_PROTOCOL,
    HEADER_SEQUENCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_bytes,
)
from partner_webhook.config import load_config  # noqa: E402
from partner_webhook.crypto import decode_secret, sign  # noqa: E402
from partner_webhook.service import PROTOCOL_VERSION, WebhookService  # noqa: E402
from partner_webhook.storage import Storage  # noqa: E402

# 手写小例子（独立于正式加工函数的期望值）。
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from archive_examples import (  # noqa: E402
    HANDWRITTEN_CASES, explain_expected,
)

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

FAILURES: list[str] = []


def check(label: str, actual, expected) -> None:
    ok = actual == expected
    print(("  PASS " if ok else "  FAIL ") + label)
    if not ok:
        print(f"         expected={expected!r}\n         actual  ={actual!r}")
        FAILURES.append(label)


def check_true(label: str, condition: bool) -> None:
    check(label, bool(condition), True)


class Clock:
    def __call__(self) -> float:
        return float(NOW)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="archive-acceptance-"))
    try:
        return run(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(work: Path) -> int:
    config_path = work / "config.json"
    config_path.write_text(json.dumps(CONFIG), encoding="utf-8")
    source_db = work / "source.db"
    archive_db = work / "archive.db"

    def cli(*args: str, allow_fail: bool = False) -> subprocess.CompletedProcess:
        command = [sys.executable, "-I",
                   str(REPO_ROOT / "partner_webhook" / "cli.py"),
                   "--config", str(config_path), "--db", str(source_db),
                   *args]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0 and not allow_fail:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            raise SystemExit(f"命令失败: {' '.join(command)}")
        return result

    storage = Storage(str(source_db))
    service = WebhookService(load_config(str(config_path)), storage,
                             clock=Clock())
    seq = 0

    def deliver(partner: str, key_version: str, secret: str, event_id: str,
                body: dict | str) -> None:
        nonlocal seq
        seq += 1
        blob = (body if isinstance(body, str)
                else json.dumps(body, ensure_ascii=False)).encode("utf-8")
        canonical = canonical_bytes(
            method="POST", path=PATH, partner_id=partner,
            key_version=key_version, timestamp=NOW, event_id=event_id,
            sequence=seq, body=blob,
        )
        headers = {
            HEADER_PROTOCOL: PROTOCOL_VERSION, HEADER_PARTNER: partner,
            HEADER_KEY_VERSION: key_version, HEADER_TIMESTAMP: str(NOW),
            HEADER_EVENT_ID: event_id, HEADER_SEQUENCE: str(seq),
            HEADER_SIGNATURE: sign(decode_secret(secret), canonical),
        }
        result = service.receive(method="POST", path=PATH,
                                 raw_headers=headers, body=blob)
        assert result.result == "accepted", (event_id, result.result,
                                             result.reason)

    def seed(partner, doc, event_id, document, secret=ACME_SECRET,
             key_version="v1"):
        deliver(partner, key_version, secret, event_id,
                {"kind": "seed", "document_id": doc, "revision": 0,
                 "document": document})

    def patch(partner, doc, event_id, base, revision, operations,
              secret=ACME_SECRET, key_version="v1"):
        deliver(partner, key_version, secret, event_id,
                {"kind": "patch", "document_id": doc,
                 "base_revision": base, "revision": revision,
                 "operations": operations})

    def sync() -> dict:
        return json.loads(cli("archive-sync", "--archive-db",
                              str(archive_db)).stdout)

    def document(partner: str, doc: str) -> dict:
        return json.loads(cli("archive-document", "--archive-db",
                              str(archive_db), "--partner", partner,
                              "--document-id", doc).stdout)

    def revisions(partner: str, doc: str) -> dict:
        return json.loads(cli("archive-revisions", "--archive-db",
                              str(archive_db), "--partner", partner,
                              "--document-id", doc).stdout)

    def disposition(partner: str, doc: str, event_id: str) -> dict:
        rows = json.loads(cli("archive-dispositions", "--archive-db",
                              str(archive_db), "--partner", partner,
                              "--document-id", doc).stdout)
        return next(r for r in rows if r["event_id"] == event_id)

    def select(partner, doc, revision, event_id, *, allow_fail=False):
        return cli("archive-select", "--archive-db", str(archive_db),
                   "--partner", partner, "--document-id", doc,
                   "--revision", str(revision), "--event-id", event_id,
                   allow_fail=allow_fail)

    def deselect(partner, doc, revision, *, allow_fail=False):
        return cli("archive-deselect", "--archive-db", str(archive_db),
                   "--partner", partner, "--document-id", doc,
                   "--revision", str(revision), allow_fail=allow_fail)

    print("== 0. 手写小例子核对（期望值不来自正式加工函数） ==")
    from partner_webhook.docarchive import EnvelopeFailure, validate_envelope
    from partner_webhook.jsonpatch import MISSING, PatchError, apply_patch
    from partner_webhook.strictjson import JsonObject, parse_strict_json

    def _mutable(value):
        if isinstance(value, JsonObject):
            return {k: _mutable(v) for k, v in value.values.items()}
        if isinstance(value, list):
            return [_mutable(v) for v in value]
        return value

    for case in HANDWRITTEN_CASES:
        explain_expected(case)  # 先打印人读的输入/期望说明
        allowed = {
            "adopted", "waiting_predecessor", "branch_unresolved",
            "not_selected", "operation_failed", "blocked_by_predecessor",
            "non_archive", "invalid_contract"}
        check(f"手写例子 {case['name']} 自带期望处置",
              all(code in allowed for code in case["expected_disposition"]),
              True)
        check(f"手写例子 {case['name']} 期望状态合法",
              case["state"] in {"present", "absent", "none"}, True)

        # 用引擎逐条解释来件（分支/等待类只核对失败与非档案约定，完整分支
        # 语义在后面的加工库场景里覆盖）。
        current = None
        engine_dispositions = []
        for text in case["incoming"]:
            parsed = validate_envelope(parse_strict_json(text.encode()))
            if isinstance(parsed, EnvelopeFailure):
                engine_dispositions.append(parsed.code)
                continue
            if parsed.kind == "seed":
                current = _mutable(parsed.document)
                engine_dispositions.append("adopted")
            else:
                try:
                    current = apply_patch(current, _mutable(parsed.operations))
                    engine_dispositions.append("adopted")
                except PatchError:
                    engine_dispositions.append("operation_failed")
        # 只在「纯线性、无分支/等待」的手写例子上比对引擎逐条结论；
        # 含分支/乱序的例子其期望处置由加工库场景验证。
        if case.get("linear", True):
            check(f"手写例子 {case['name']} 引擎逐条结论与手写期望一致",
                  engine_dispositions, case["expected_disposition"])
            if case["state"] == "present" and \
                    engine_dispositions[-1] == "adopted":
                check(f"手写例子 {case['name']} 最终档案与手写期望一致",
                      current, _mutable(parse_strict_json(
                          json.dumps(case["expected_document"]))))
            elif case["state"] == "absent":
                check(f"手写例子 {case['name']} 引擎得到根删除状态",
                      current is MISSING, True)

    print("\n== 1. 真实签名收件：seed + 一条六操作综合 patch ==")
    seed("acme", "demo", "e-seed", {
        "": {"slash/key": 1, "tilde~key": 2},
        "0": "object-numeric-key",
        "arr": [10, 20, 30],
        "big": 123456789012345678901234567891,
        "maybe": None,
    })
    patch("acme", "demo", "e-p1", 0, 1, [
        # 空键对象下的成员：第一段为空（双斜杠），再对键名做 ~1/~0 转义。
        {"op": "test", "path": "//slash~1key", "value": 1},
        {"op": "test", "path": "//tilde~0key", "value": 2},
        {"op": "replace", "path": "/0", "value": "still-string"},
        {"op": "move", "from": "/arr/2", "path": "/arr/0"},    # 同数组前移
        {"op": "copy", "from": "/arr", "path": "/arr-copy"},
        {"op": "add", "path": "/arr-copy/-", "value": 99},     # 改副本
        {"op": "test", "path": "/big",
         "value": 123456789012345678901234567891},             # 超大整数精确 test
        {"op": "test", "path": "/maybe", "value": None},
    ])
    report = sync()
    check("综合 patch 全部采用", report["disposition_counts"]["adopted"], 2)
    doc = document("acme", "demo")
    check("~1 解码访问的斜杠键保留", doc["document"][""]["slash/key"], 1)
    check("对象数字键按原名访问", doc["document"]["0"], "still-string")
    check("同数组前移结果",
          doc["document"]["arr"], [30, 10, 20])
    check("copy 副本独立修改不影响原数组",
          doc["document"]["arr-copy"], [30, 10, 20, 99])
    check("超大整数原样读回（不丢精度）",
          doc["document"]["big"], 123456789012345678901234567891)
    check("null 与缺失不同：显式 null 读回为 None",
          doc["document"]["maybe"], None)
    check("可沿当前内容查回采用事件链",
          [c["event_id"] for c in doc["chain"]], ["e-seed", "e-p1"])

    print("\n== 2. 同数组后移 + 未知指针转义拒绝 ==")
    patch("acme", "demo", "e-p2", 1, 2, [
        {"op": "move", "from": "/arr/0", "path": "/arr/2"},    # 后移
    ])
    sync()
    check("后移结果", document("acme", "demo")["document"]["arr"],
          [10, 20, 30])
    patch("acme", "demo", "e-bad-pointer", 2, 3, [
        {"op": "remove", "path": "/a~2b"},
    ])
    sync()
    bad = disposition("acme", "demo", "e-bad-pointer")
    check("未知转义在信封校验阶段拒绝", bad["disposition"], "invalid_contract")
    check("当前公布仍停在第 2 版",
          document("acme", "demo")["current_revision"], 2)

    print("\n== 3. 后一步失败使整条修改回滚（原修改保留查账） ==")
    patch("acme", "demo", "e-atomic", 2, 3, [
        {"op": "replace", "path": "/maybe", "value": "changed"},
        {"op": "test", "path": "/maybe", "value": None},       # 必失败
    ])
    sync()
    atomic = disposition("acme", "demo", "e-atomic")
    check("失败处置", atomic["disposition"], "operation_failed")
    check("指出第 2 个操作", atomic["failed_op"], 2)
    check("指出失败位置", atomic["failed_pointer"], "/maybe")
    check("前一个 replace 未留下（整条回滚）",
          document("acme", "demo")["document"]["maybe"], None)
    check("原修改事件仍在账上可查",
          "e-atomic" in [r["event_id"] for r in
                         revisions("acme", "demo")["events"]], True)

    print("\n== 4. null 档案与根删除/重建 ==")
    seed("acme", "rootdoc", "r-seed", None)
    patch("acme", "rootdoc", "r-rm", 0, 1,
          [{"op": "remove", "path": ""}])
    patch("acme", "rootdoc", "r-add", 1, 2,
          [{"op": "add", "path": "", "value": {"reborn": True}}])
    sync()
    null_view = document("acme", "rootdoc")
    check("根 add 重新建档（present）", null_view["state"], "present")
    check("根 add 重新建档内容", null_view["document"], {"reborn": True})
    check("当前修订为 2", null_view["current_revision"], 2)
    # 单独核对 remove 后的 absent 中间态：用一份只走到第 1 版的档案
    seed("acme", "gone", "g-seed", {"a": 1})
    patch("acme", "gone", "g-rm", 0, 1, [{"op": "remove", "path": ""}])
    sync()
    gone = document("acme", "gone")
    check("remove 根产生 absent（区别于 null）", gone["state"], "absent")
    check("absent 时无内容", gone["document"], None)
    # absent 之后 replace 根不能建档，必须根 add（用不同修订号，避免同号竞争
    # 被误当成需要人工选择的分支）。
    patch("acme", "gone", "g-bad-replace", 1, 2,
          [{"op": "replace", "path": "", "value": 1}])
    sync()
    check("absent 时 replace 根操作失败",
          disposition("acme", "gone", "g-bad-replace")["disposition"],
          "operation_failed")
    check("失败修订阻断同一档案后续",
          document("acme", "gone")["state"], "absent")
    # 失败修订不能跳过：另起一份档案演示根 add 是唯一建档方式
    seed("acme", "reborn", "rb-seed", {"a": 1})
    patch("acme", "reborn", "rb-rm", 0, 1, [{"op": "remove", "path": ""}])
    patch("acme", "reborn", "rb-add", 1, 2,
          [{"op": "add", "path": "", "value": {"ok": 1}}])
    sync()
    check("只有根 add 能重新建档",
          document("acme", "reborn")["document"], {"ok": 1})
    check("重新建档后公布到修订 2",
          document("acme", "reborn")["current_revision"], 2)

    print("\n== 5. 乱序：修订 2 先送、seed 最后送 ==")
    patch("acme", "late", "l-p2", 1, 2,
          [{"op": "replace", "path": "/v", "value": 2}])
    sync()
    check("缺 seed 时等待前版",
          disposition("acme", "late", "l-p2")["disposition"],
          "waiting_predecessor")
    check("等待期不公布内容",
          document("acme", "late")["current_revision"], None)
    patch("acme", "late", "l-p1", 0, 1,
          [{"op": "replace", "path": "/v", "value": 1}])
    sync()
    check("仍缺 seed，继续等待",
          disposition("acme", "late", "l-p1")["disposition"],
          "waiting_predecessor")
    seed("acme", "late", "l-seed", {"v": 0})
    sync()
    check("补齐后沿链接执行到第 2 版",
          document("acme", "late")["current_revision"], 2)
    check("第 2 版内容正确",
          document("acme", "late")["document"]["v"], 2)
    for eid in ("l-seed", "l-p1", "l-p2"):
        check(f"{eid} 已采用",
              disposition("acme", "late", eid)["disposition"], "adopted")

    print("\n== 6. 分支：补入第 1 版分支后退回，人工选择恢复，撤销再退回 ==")
    seed("acme", "branch", "b-seed", {"v": 0})
    patch("acme", "branch", "b-A", 0, 1,
          [{"op": "replace", "path": "/v", "value": 1}])
    patch("acme", "branch", "b-B", 1, 2,
          [{"op": "replace", "path": "/v", "value": 2}])
    sync()
    check("分支前已到第 2 版",
          document("acme", "branch")["current_revision"], 2)
    patch("acme", "branch", "b-C", 0, 1,
          [{"op": "replace", "path": "/v", "value": 11}])
    sync()
    check("新分支到达后公布退回第 0 版",
          document("acme", "branch")["current_revision"], 0)
    check("A 分支未选",
          disposition("acme", "branch", "b-A")["disposition"],
          "branch_unresolved")
    check("C 分支未选",
          disposition("acme", "branch", "b-C")["disposition"],
          "branch_unresolved")
    check("B 仍在账上但被含糊第 1 版阻断",
          disposition("acme", "branch", "b-B")["disposition"],
          "blocked_by_predecessor")
    # 人工选择 A
    select("acme", "branch", 1, "b-A")
    check("选择 A 后恢复到第 2 版",
          document("acme", "branch")["current_revision"], 2)
    check("A 已采用",
          disposition("acme", "branch", "b-A")["disposition"], "adopted")
    check("C 未被选中",
          disposition("acme", "branch", "b-C")["disposition"], "not_selected")
    check("B 重新接上",
          disposition("acme", "branch", "b-B")["disposition"], "adopted")
    # 撤销选择
    deselect("acme", "branch", 1)
    check("撤销后再次退回第 0 版",
          document("acme", "branch")["current_revision"], 0)
    check("撤销后 A 恢复分支未选",
          disposition("acme", "branch", "b-A")["disposition"],
          "branch_unresolved")
    check("撤销后 B 再次被阻断",
          disposition("acme", "branch", "b-B")["disposition"],
          "blocked_by_predecessor")
    check("撤销后选择表为空", revisions("acme", "branch")["selections"], {})

    print("\n== 7. 选择另一合作方同号事件被拒（错误选择不改状态） ==")
    seed("globex", "branch", "g-seed", {"v": 100},
         secret=GLOBEX_SECRET, key_version="g1")
    sync()
    refused = select("acme", "branch", 0, "g-seed", allow_fail=True)
    check("跨合作方选择退出码 2", refused.returncode, 2)
    check("拒绝原因写明不属于坐标", "不属于坐标" in refused.stderr, True)
    ghost = select("acme", "branch", 0, "no-such-event", allow_fail=True)
    check("不存在事件选择退出码 2", ghost.returncode, 2)
    check("错误选择不改任何状态（仍无选择）",
          revisions("acme", "branch")["selections"], {})
    check("合作方隔离：globex 同号档案独立公布",
          document("globex", "branch")["document"]["v"], 100)

    print("\n== 8. 两个 seed 冲突：未选择前不公布 ==")
    seed("acme", "twoseed", "t-one", {"v": 1})
    seed("acme", "twoseed", "t-two", {"v": 2})
    sync()
    check("两个 seed 时不公布内容",
          document("acme", "twoseed")["current_revision"], None)
    check("两个 seed 均为分支未选",
          {disposition("acme", "twoseed", e)["disposition"]
           for e in ("t-one", "t-two")},
          {"branch_unresolved"})
    select("acme", "twoseed", 0, "t-one")
    check("选择 seed 后才公布",
          document("acme", "twoseed")["document"]["v"], 1)
    check("另一个 seed 标记未被选中",
          disposition("acme", "twoseed", "t-two")["disposition"],
          "not_selected")

    print("\n== 9. 失败修订阻断后续，不能跳过接下一版 ==")
    seed("acme", "blocked", "k-seed", {"v": 0})
    patch("acme", "blocked", "k-fail", 0, 1,
          [{"op": "replace", "path": "/missing", "value": 1}])
    patch("acme", "blocked", "k-next", 1, 2,
          [{"op": "replace", "path": "/v", "value": 2}])
    sync()
    check("失败修订",
          disposition("acme", "blocked", "k-fail")["disposition"],
          "operation_failed")
    check("后续修订被阻断",
          disposition("acme", "blocked", "k-next")["disposition"],
          "blocked_by_predecessor")
    check("公布停在 seed",
          document("acme", "blocked")["current_revision"], 0)

    print("\n== 10. 重复同步是无操作，不重复登记 ==")
    before = json.loads(cli("archive-dispositions", "--archive-db",
                            str(archive_db)).stdout)
    again = sync()
    check("重复同步导入数为 0", again["imported"], 0)
    after = json.loads(cli("archive-dispositions", "--archive-db",
                           str(archive_db)).stdout)
    check("处置行数不增加", len(after), len(before))
    third = sync()
    check("第三次同步仍无导入", third["imported"], 0)

    print("\n== 11. 真实退出：写入新档案后、提交前退出，重开为旧结果 ==")
    seed("acme", "crash", "c-seed", {"v": 0})
    sync()
    patch("acme", "crash", "c-p1", 0, 1,
          [{"op": "replace", "path": "/v", "value": 1}])
    crash = cli("archive-sync", "--archive-db", str(archive_db),
                "--simulate-crash-before-commit", allow_fail=True)
    check("强制退出码 97", crash.returncode, 97)
    check("崩溃前已写库的提示存在", "尚未提交" in crash.stderr, True)
    check("重开仍是旧结果（第 0 版）",
          document("acme", "crash")["current_revision"], 0)
    rows = json.loads(cli("archive-dispositions", "--archive-db",
                          str(archive_db), "--partner", "acme",
                          "--document-id", "crash").stdout)
    check("未提交的事件未登记",
          [r["event_id"] for r in rows], ["c-seed"])
    recovered = sync()
    check("重新同步可继续", recovered["imported"], 1)
    check("恢复后到达第 1 版",
          document("acme", "crash")["current_revision"], 1)

    print("\n== 12. 重开进程：等待项、选择与结果都还在 ==")
    storage.close()
    fresh_report = sync()  # 新进程打开同一加工库
    check("重开后重复同步无导入", fresh_report["imported"], 0)
    check("重开后分支档案仍退回第 0 版",
          document("acme", "branch")["current_revision"], 0)
    select("acme", "branch", 1, "b-A")
    check("重开后选择仍生效，恢复第 2 版",
          document("acme", "branch")["current_revision"], 2)
    check("持久化选择可查",
          revisions("acme", "branch")["selections"], {"1": "b-A"})

    print("\n== 13. 非档案来件与约定不符各自指明事件 ==")
    # 第 12 节关闭过连接，这里按“重开进程”重新打开接收库继续收件。
    storage = Storage(str(source_db))
    service = WebhookService(load_config(str(config_path)), storage,
                             clock=Clock())
    deliver("acme", "v1", ACME_SECRET, "hb-event", '{"kind":"heartbeat"}')
    deliver("acme", "v1", ACME_SECRET, "bad-rev",
            {"kind": "seed", "document_id": "x", "revision": True,
             "document": 1})
    deliver("acme", "v1", ACME_SECRET, "dup-key", '{"a":1,"a":2}')
    sync()
    all_rows = {r["event_id"]: r for r in
                json.loads(cli("archive-dispositions", "--archive-db",
                               str(archive_db)).stdout)}
    check("heartbeat 非档案",
          all_rows["hb-event"]["disposition"], "non_archive")
    check("布尔 revision 约定不符",
          all_rows["bad-rev"]["disposition"], "invalid_contract")
    check("重复键约定不符",
          all_rows["dup-key"]["disposition"], "invalid_contract")
    check("每条都保留正文摘要",
          bool(all_rows["hb-event"]["body_preview"]), True)

    print("\n== 14. 源库与 outbox 未被加工触碰 ==")
    import sqlite3 as _sqlite3
    src = _sqlite3.connect(str(source_db))
    tables = {r[0] for r in src.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    check("源库没有加工侧表",
          any(t.startswith("archive_") or t == "documents"
              or t == "revisions_selected" for t in tables), False)
    # outbox 由签名收件流程写入（既有行为）；加工同步不得改变它。
    outbox_before = src.execute(
        "SELECT COUNT(*) FROM outbox").fetchone()[0]
    src.close()
    sync()
    src = _sqlite3.connect(str(source_db))
    outbox_after = src.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
    check("加工同步前后源 outbox 计数不变（不借用/不标记）",
          outbox_after, outbox_before)
    check("源 outbox 仅由收件流程产生（与已接受事件同数）",
          outbox_after,
          src.execute("SELECT COUNT(*) FROM accepted_events").fetchone()[0])
    # 加工状态全部落在独立加工库。
    arc = _sqlite3.connect(str(archive_db))
    arc_tables = {r[0] for r in arc.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    check("加工库自含全部加工状态表",
          {"archive_events", "archive_bodies", "documents",
           "revisions_selected"} <= arc_tables, True)
    check("加工库不含正文搜索索引表",
          any(t in ("nodes", "events", "index_generations")
              for t in arc_tables), False)
    arc.close()
    src.close()

    print("\n== 结果 ==")
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} 项")
        for item in FAILURES:
            print("  -", item)
        return 1
    print("全部断言通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
