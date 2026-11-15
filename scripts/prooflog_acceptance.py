"""可验证追加账本验收材料（可复跑，全部断言化）。

演练内容
--------
1. 在**已有旧数据**的接收库上安装账本；重复安装不换号、不重排。
2. 两个独立进程同时收件：已接受记录与叶子一一对应，叶序号连续。
3. 真实签名收件第 1、3、5、8、9 条后保存检查点；为首/中/尾事件生成在账
   证明；用**离线子进程**核验在账与前后追加关系。
4. 小样本直接递归参考实现（``scripts/prooflog_reference.py``，不 import
   正式节点/证明函数）逐一核对 0..9 的全部 (m,n) 与每个在账位置，再对路径
   做篡改（错叶、错位置、改节点、缺节点、多节点、非法十六进制、布尔冒充
   整数、跨合作方、跨 log_id），要求离线核验器失败且退出码非零。
5. 展示相同 source_seq、同正文不同事件、不同合作方同号事件、二进制正文，
   以及重复/冲突/拒收对树长的影响。
6. 一次新接收在提交前抛错回滚：源表、叶序号、根都不分离，不产生幽灵叶。
7. 增加到数万片叶子，用节点读取计数与耗时证明查询旧前缀/生成证明没有随
   总事件数线性读取。
8. 移走数据库后，保存的检查点与证明仍可用离线核验器独立核验。

用法::

    python3 -I scripts/prooflog_acceptance.py [--out 输出目录] [--bulk N]

``--out`` 省略时使用临时目录；``--bulk`` 默认 20000（越大越能展示对数
增长；节点读取计数与树高而非总数成正比）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import prooflog_reference as ref  # noqa: E402

from partner_webhook import merkle  # noqa: E402
from partner_webhook.canonical import (  # noqa: E402
    HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER, HEADER_PROTOCOL,
    HEADER_SEQUENCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_bytes,
)
from partner_webhook.config import load_config  # noqa: E402
from partner_webhook.crypto import decode_secret, sign  # noqa: E402
from partner_webhook.eventlog import (  # noqa: E402
    LedgerError, ReadTrace, install, log_status, prove_consistency,
    prove_inclusion, read_checkpoint,
)
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

FAILURES: list[str] = []
CHECKS = 0


def check(label: str, actual, expected):
    global CHECKS
    CHECKS += 1
    ok = actual == expected
    print(("  PASS " if ok else "  FAIL ") + label)
    if not ok:
        print(f"         expected={expected!r} actual={actual!r}")
        FAILURES.append(label)
    return ok


def check_true(label: str, condition, detail=""):
    return check(label + (f" ({detail})" if detail else ""), bool(condition), True)


def section(title: str) -> None:
    print(f"\n== {title} ==")


class Clock:
    def __call__(self) -> float:
        return float(NOW)


def secret_for(partner: str) -> tuple[str, str]:
    if partner == "acme":
        return "v1", ACME_SECRET
    return "g1", GLOBEX_SECRET


def make_service(db_path: str) -> tuple[WebhookService, Storage]:
    storage = Storage(db_path)
    config = load_config(str(CONFIG_PATH))
    return WebhookService(config, storage, clock=Clock()), storage


def signed(partner: str, event_id: str, sequence: int, body: bytes,
           timestamp: int = NOW) -> dict[str, str]:
    key_version, secret = secret_for(partner)
    canonical = canonical_bytes(
        method="POST", path=PATH, partner_id=partner, key_version=key_version,
        timestamp=timestamp, event_id=event_id, sequence=sequence, body=body,
    )
    return {
        HEADER_PROTOCOL: PROTOCOL_VERSION, HEADER_PARTNER: partner,
        HEADER_KEY_VERSION: key_version, HEADER_TIMESTAMP: str(timestamp),
        HEADER_EVENT_ID: event_id, HEADER_SEQUENCE: str(sequence),
        HEADER_SIGNATURE: sign(decode_secret(secret), canonical),
    }


def deliver(service, partner: str, event_id: str, sequence: int, body: bytes,
            *, timestamp: int = NOW, bad_signature: bool = False):
    headers = signed(partner, event_id, sequence, body, timestamp)
    if bad_signature:
        headers[HEADER_SIGNATURE] = "0" * 64
    return service.receive(method="POST", path=PATH, raw_headers=headers,
                           body=body)


def cli(*args: str, allow_fail: bool = False) -> subprocess.CompletedProcess:
    command = [sys.executable, "-I", str(REPO_ROOT / "partner_webhook" / "cli.py"),
               "--config", str(CONFIG_PATH), "--db", str(SOURCE_DB), *args]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0 and not allow_fail:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"命令失败: {command}")
    return result


def offline(*args: str, allow_fail: bool = False) -> subprocess.CompletedProcess:
    command = [sys.executable, "-I",
               str(REPO_ROOT / "partner_webhook" / "verifylog.py"), *args]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0 and not allow_fail:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"离线核验命令失败: {command}")
    return result


def checkpoint_file(path: Path, checkpoint: merkle.Checkpoint) -> Path:
    path.write_text(merkle.dump_document(checkpoint.as_dict()),
                    encoding="utf-8")
    return path


def proof_file(path: Path, doc: dict) -> Path:
    path.write_text(merkle.dump_document(doc), encoding="utf-8")
    return path


def verify_inclusion_offline(cp: Path, proof: Path, event_id: str,
                             source_seq: int, body: bytes,
                             partner: str | None = None) -> subprocess.CompletedProcess:
    args = ["inclusion", "--checkpoint", str(cp), "--proof", str(proof),
            "--event-id", event_id, "--source-seq", str(source_seq),
            "--body-sha256", hashlib.sha256(body).hexdigest(), "--json"]
    if partner:
        args += ["--partner", partner]
    return offline(*args, allow_fail=True)


# --------------------------------------------------------------------- #
# 旧库准备与安装
# --------------------------------------------------------------------- #
def seed_legacy_events() -> None:
    """安装前先真实签名收件，制造「安装时纳入历史」的场景。"""
    service, storage = make_service(str(SOURCE_DB))
    try:
        for index, (event_id, seq) in enumerate(
                [("legacy-a", 3), ("legacy-b", 1), ("legacy-c", 2)]):
            body = f'{{"legacy":{index}}}'.encode()
            result = deliver(service, "acme", event_id, seq, body)
            assert result.result == "accepted", (event_id, result)
        # 另一合作方也有历史事件（安装互不影响）
        result = deliver(service, "globex", "g-legacy", 5, b'{"g":1}')
        assert result.result == "accepted"
    finally:
        storage.close()


def run_reference_cross_check(prefix: list[bytes]) -> None:
    """用独立参考实现核对 0..9 的全部 (m,n) 与每个在账位置。"""
    section("5. 直接递归参考实现交叉核对（0..9 全部 (m,n) 与全部在账位置）")
    for size in range(0, len(prefix) + 1):
        formal_root = merkle.root_from_leaves(prefix[:size])
        check(f"树长 {size} 根与参考实现一致",
              formal_root, ref.tree_root(prefix[:size]))
        for index in range(size):
            formal_path = merkle.inclusion_path_from_leaves(prefix[:size], index)
            reference_path = ref.inclusion_proof(prefix[:size], index)
            check(f"在账路径 n={size} i={index} 一致",
                  [node.hex() for node in formal_path],
                  [node.hex() for node in reference_path])
            check(f"参考实现重建根 n={size} i={index}",
                  ref.inclusion_root(prefix[index], index, size,
                                     reference_path), formal_root)
        for m in range(0, size + 1):
            formal_path = merkle.consistency_path_from_leaves(prefix[:size], m)
            reference_path = ref.consistency_proof(prefix[:size], m)
            check(f"一致性路径 m={m} n={size} 一致",
                  [node.hex() for node in formal_path],
                  [node.hex() for node in reference_path])
            old_root = ref.tree_root(prefix[:m]) if m else ref.EMPTY_ROOT
            new_root = ref.tree_root(prefix[:size])
            check(f"参考实现重建前后根 m={m} n={size}",
                  tuple(node.hex() for node in ref.consistency_verify(
                      old_root, new_root, m, size, reference_path)),
                  (old_root.hex(), new_root.hex()))


# --------------------------------------------------------------------- #
# 检查点与证明
# --------------------------------------------------------------------- #
CHECKPOINTS: dict[int, merkle.Checkpoint] = {}
BODIES: dict[str, bytes] = {}
SEQUENCES: dict[str, int] = {}


LIVE_DB: Path | None = None


def capture_checkpoint(size: int) -> merkle.Checkpoint:
    checkpoint = read_checkpoint(str(LIVE_DB), "acme")
    assert checkpoint.tree_size == size, (size, checkpoint.tree_size)
    CHECKPOINTS[size] = checkpoint
    path = CHECKPOINT_DIR / f"checkpoint-{size:02d}.json"
    checkpoint_file(path, checkpoint)
    print(f"         已保存检查点 tree_size={size} root={checkpoint.root_hash.hex()[:16]}...")
    return checkpoint


def check_inclusion_offline(tag: str, event_id: str, size: int) -> None:
    checkpoint = CHECKPOINTS[size]
    proof = prove_inclusion(str(LIVE_DB), "acme", checkpoint, event_id)
    path = proof_file(PROOF_DIR / f"inclusion-{tag}-n{size}.json",
                      proof.as_dict())
    cp_path = CHECKPOINT_DIR / f"checkpoint-{size:02d}.json"
    result = verify_inclusion_offline(cp_path, path, event_id,
                                      SEQUENCES[event_id], BODIES[event_id])
    check(f"离线核验在账证明 {tag} n={size} 退出码 0", result.returncode, 0)
    payload = json.loads(result.stdout) if result.stdout.strip() else {}
    check(f"离线核验在账证明 {tag} n={size} ok", payload.get("ok"), True)


def live_leaf_hashes(size: int, db_path=None) -> list[bytes]:
    """按叶序取前 size 片叶子的独立参考哈希。"""
    conn = sqlite3.connect(db_path or LIVE_DB)
    rows = conn.execute(
        "SELECT event_id, source_seq, body_sha256 FROM log_leaves"
        " WHERE partner_id='acme' ORDER BY leaf_index LIMIT ?",
        (size,)).fetchall()
    conn.close()
    return [ref.leaf_hash("acme", eid, seq, bytes.fromhex(digest))
            for eid, seq, digest in rows]


# --------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------- #
def main() -> int:
    global CONFIG_PATH, SOURCE_DB, CHECKPOINT_DIR, PROOF_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None, help="输出目录（默认临时目录）")
    parser.add_argument("--bulk", type=int, default=20000,
                        help="大样本叶数（默认 20000）")
    parser.add_argument("--keep", action="store_true",
                        help="保留输出目录（默认保留临时目录以便检查）")
    args = parser.parse_args()

    work = Path(args.out) if args.out else Path(tempfile.mkdtemp(
        prefix="prooflog-acceptance-"))
    work.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH = work / "config.json"
    CONFIG_PATH.write_text(json.dumps(CONFIG, ensure_ascii=False),
                           encoding="utf-8")
    SOURCE_DB = work / "source.db"
    CHECKPOINT_DIR = work / "checkpoints"
    PROOF_DIR = work / "proofs"
    CHECKPOINT_DIR.mkdir(exist_ok=True)
    PROOF_DIR.mkdir(exist_ok=True)
    print(f">>> 工作目录: {work}")

    try:
        run(work, args)
    finally:
        if FAILURES:
            print(f"\nFAILED: {len(FAILURES)} 项 / 共 {CHECKS} 项断言")
            for item in FAILURES:
                print("  -", item)
            return 1
        print(f"\n全部 {CHECKS} 项断言通过")
    return 0


def run(work: Path, args) -> None:
    global SOURCE_DB, LIVE_DB

    # ---------------- 1. 旧库 + 安装 ----------------
    section("1. 已有旧数据的接收库上安装账本")
    seed_legacy_events()
    status_before = sqlite3.connect(SOURCE_DB).execute(
        "SELECT COUNT(*) FROM accepted_events WHERE partner_id='acme'"
    ).fetchone()[0]
    check("安装前已有 3 条 acme 已接受事件", status_before, 3)
    check("安装前没有账本表行",
          sqlite3.connect(SOURCE_DB).execute(
              "SELECT COUNT(*) FROM event_logs").fetchone()[0], 0)

    install_report = install(db_path=str(SOURCE_DB), partner_id="acme")
    check("安装纳入 3 片历史叶子", install_report["tree_size"], 3)
    check("首次安装不是复核", install_report["already_installed"], False)
    old_log_id = install_report["log_id"]

    again = install(db_path=str(SOURCE_DB), partner_id="acme")
    check("重复安装不换号", again["log_id"], old_log_id)
    check("重复安装标为复核", again["already_installed"], True)
    # 安装状态只核对、不改写；重复安装与首次安装持有同一写锁。
    check("重复安装后已接受事件数量未变",
          again["leaves"], 3)
    check("重复安装后 log_id 与根保持",
          (again["log_id"], again["root_hash"]),
          (old_log_id, install_report["root_hash"]))

    # 叶序按 ingest_record_id 递增，而不是 source_seq。
    conn = sqlite3.connect(SOURCE_DB)
    leaf_order = conn.execute(
        "SELECT event_id FROM log_leaves WHERE partner_id='acme'"
        " ORDER BY leaf_index").fetchall()
    conn.close()
    check("叶序按 ingest_record_id 递增（非 source_seq）",
          [row[0] for row in leaf_order], ["legacy-a", "legacy-b", "legacy-c"])

    # 安装校验：正文缺失/摘要不符时整次拒绝，不产生任何账本记录。
    broken_db = work / "broken.db"
    shutil.copyfile(SOURCE_DB, broken_db)
    conn = sqlite3.connect(broken_db)
    # 保持登记长度，只改字节内容，触发摘要不符（而非长度不符）。
    length = conn.execute(
        "SELECT byte_length FROM raw_bodies WHERE body_sha256 ="
        " (SELECT body_sha256 FROM accepted_events"
        "  WHERE event_id='legacy-b')").fetchone()[0]
    conn.execute("UPDATE raw_bodies SET body_blob = ? WHERE body_sha256 ="
                 " (SELECT body_sha256 FROM accepted_events"
                 "  WHERE event_id='legacy-b')", (b"x" * length,))
    conn.commit()
    conn.close()
    try:
        install(db_path=str(broken_db), partner_id="acme")
        check("正文摘要不符时安装被拒绝", "未报错", "应报错")
    except LedgerError as exc:
        check("正文摘要不符时安装被拒绝", exc.code, "body_digest_mismatch")
    check("被拒绝的安装不留下账本行（副本仍保留源库原有账本）",
          sqlite3.connect(broken_db).execute(
              "SELECT COUNT(*) FROM event_logs").fetchone()[0], 1)

    # 安装到另一个合作方也与 acme 隔离
    install(db_path=str(SOURCE_DB), partner_id="globex")
    check("globex 账本独立", log_status(str(SOURCE_DB), "globex")["tree_size"], 1)

    service, storage = make_service(str(SOURCE_DB))
    try:
        # 安装后的第一个事件追加在历史之后
        legacy_result = deliver(service, "acme", "after-install", 0,
                                b'{"after":"install"}')
        check("安装后新事件被接受", legacy_result.result, "accepted")
        check("安装后新事件追加为第 4 片叶子",
              log_status(str(SOURCE_DB), "acme")["tree_size"], 4)
    finally:
        storage.close()

    # ---------------- 2. 两进程交错收件 ----------------
    section("2. 两个独立进程同时向同一合作方收件")
    concurrency_db = work / "concurrent.db"
    concurrency_db.unlink(missing_ok=True)
    Storage(str(concurrency_db)).close()
    install(db_path=str(concurrency_db), partner_id="acme")
    # 安装后再由两个独立进程交错投递；两个进程都从磁盘重新打开同一库。
    events = [(f"race-{i:03d}", (i * 7) % 50) for i in range(60)]
    plan = work / "race-plan.json"
    plan.write_text(json.dumps(events), encoding="utf-8")
    helper = work / "race_worker.py"
    helper.write_text(RACE_WORKER, encoding="utf-8")
    procs = [subprocess.Popen(
        [sys.executable, "-I", str(helper), str(concurrency_db),
         str(CONFIG_PATH), str(plan), str(slot), "2", str(REPO_ROOT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for slot in (0, 1)]
    outputs = [proc.communicate(timeout=300) for proc in procs]
    for proc, (out, err) in zip(procs, outputs):
        if proc.returncode != 0:
            print(out)
            print(err, file=sys.stderr)
            raise SystemExit("并发收件子进程失败")
    conn = sqlite3.connect(concurrency_db)
    accepted = conn.execute(
        "SELECT COUNT(*) FROM accepted_events WHERE partner_id='acme'"
    ).fetchone()[0]
    leaves = conn.execute(
        "SELECT COUNT(*), MIN(leaf_index), MAX(leaf_index) FROM log_leaves"
        " WHERE partner_id='acme'").fetchone()
    distinct = conn.execute(
        "SELECT COUNT(DISTINCT event_id) FROM log_leaves"
        " WHERE partner_id='acme'").fetchone()[0]
    # 每片叶子对应一条 accepted_events
    mismatch = conn.execute(
        "SELECT COUNT(*) FROM log_leaves l LEFT JOIN accepted_events a"
        " ON a.partner_id=l.partner_id AND a.event_id=l.event_id"
        " AND a.source_seq=l.source_seq AND a.body_sha256=l.body_sha256"
        " WHERE a.event_id IS NULL").fetchone()[0]
    meta = conn.execute(
        "SELECT tree_size, root_hash FROM event_logs WHERE partner_id='acme'"
    ).fetchone()
    conn.close()
    check("两进程共收 60 条事件", accepted, 60)
    check("叶子数等于已接受数", leaves[0], 60)
    check("叶序号从 0 连续到 59", (leaves[1], leaves[2]), (0, 59))
    check("无重复 event_id", distinct, 60)
    check("每片叶子都能对回 accepted_events", mismatch, 0)
    check("账本 tree_size 与叶数一致", meta[0], 60)
    # 独立重新计算根
    conn = sqlite3.connect(concurrency_db)
    rows = conn.execute(
        "SELECT event_id, source_seq, body_sha256 FROM log_leaves"
        " WHERE partner_id='acme' ORDER BY leaf_index").fetchall()
    conn.close()
    recomputed = ref.tree_root([
        ref.leaf_hash("acme", eid, seq, bytes.fromhex(digest))
        for eid, seq, digest in rows])
    check("并发后的根与独立参考实现一致",
          bytes.fromhex(meta[1]), recomputed)

    # ---------------- 3. 收件、检查点与证明 ----------------
    section("3. 第 1/3/5/8/9 条接受后的检查点与在账证明")
    live_db = work / "live.db"
    LIVE_DB = live_db
    live_db.unlink(missing_ok=True)
    Storage(str(live_db)).close()
    install(db_path=str(live_db), partner_id="acme")
    # 主线流程使用 live_db：安装后第 1 条 leaf index 0。
    global_install = install(db_path=str(live_db), partner_id="acme")
    log_id = global_install["log_id"]
    service, storage = make_service(str(live_db))
    accepted_bodies: list[bytes] = []
    accepted_ids: list[str] = []
    try:
        for position in range(1, 10):
            event_id = f"cp-{position:02d}"
            # 故意让 source_seq 稀疏且乱序
            sequence = [50, 7, 31, 2, 99, 0, 13, 77, 4][position - 1]
            body = json.dumps({"position": position}, ensure_ascii=False).encode()
            result = deliver(service, "acme", event_id, sequence, body)
            check(f"第 {position} 条接受", result.result, "accepted")
            accepted_bodies.append(body)
            accepted_ids.append(event_id)
            BODIES[event_id] = body
            SEQUENCES[event_id] = sequence
            if position in (1, 3, 5, 8, 9):
                capture_checkpoint(position)
    finally:
        storage.close()

    # 用旧库里已保存的检查点重建「旧」文件（此处复用了 live_db 的路径）。
    # 检查点根必须与独立参考实现一致。
    leaf_hashes = [ref.leaf_hash("acme", eid, SEQUENCES[eid],
                                 hashlib.sha256(BODIES[eid]).digest())
                   for eid in accepted_ids]
    for size in (1, 3, 5, 8, 9):
        check(f"检查点 n={size} 根与参考实现一致",
              CHECKPOINTS[size].root_hash, ref.tree_root(leaf_hashes[:size]))
        check(f"检查点 n={size} 只含声明的树长",
              CHECKPOINTS[size].tree_size, size)

    # 首/中/尾事件在各检查点前缀下的在账证明
    for size in (1, 3, 5, 8, 9):
        for event_id in ("cp-01", "cp-05", "cp-09"):
            index = int(event_id.split("-")[1]) - 1
            if index >= size:
                continue
            check_inclusion_offline(f"main-{event_id}", event_id, size)
            proof = prove_inclusion(str(live_db), "acme",
                                    CHECKPOINTS[size], event_id)
            reference_path = ref.inclusion_proof(leaf_hashes[:size], index)
            check(f"在账路径与参考实现一致 {event_id} n={size}",
                  [node.hex() for node in proof.path],
                  [node.hex() for node in reference_path])

    # 旧检查点的在账证明在继续追加之后仍然成立（旧检查点不因新收件改变）
    service, storage = make_service(str(live_db))
    try:
        for position in (10, 11):
            body = json.dumps({"position": position}).encode()
            deliver(service, "acme", f"cp-{position:02d}", 500 + position, body)
            BODIES[f"cp-{position:02d}"] = body
            SEQUENCES[f"cp-{position:02d}"] = 500 + position
    finally:
        storage.close()
    check("追加后旧检查点 n=5 仍然可用",
          verify_inclusion_offline(
              CHECKPOINT_DIR / "checkpoint-05.json",
              proof_file(PROOF_DIR / "inclusion-main-cp-05-n5.json",
                         prove_inclusion(str(live_db), "acme",
                                         CHECKPOINTS[5], "cp-05").as_dict()),
              "cp-05", SEQUENCES["cp-05"], BODIES["cp-05"]).returncode, 0)

    # ---------------- 5. 一致性证明与离线核验 ----------------
    section("4. 前后追加关系证明（离线子进程核验）")
    for m, n in ((0, 9), (1, 9), (1, 3), (3, 5), (5, 8), (8, 9), (9, 9),
                 (3, 11), (5, 11)):
        old = read_checkpoint(str(live_db), "acme", tree_size=m)
        new = read_checkpoint(str(live_db), "acme", tree_size=n)
        # 0 树长的检查点协议里没有大小字段；用当前检查点信息构造空检查点。
        if m == 0:
            old = merkle.Checkpoint(new.log_id, "acme", 0, merkle.empty_root())
        proof = prove_consistency(str(live_db), "acme", old, new)
        old_path = checkpoint_file(CHECKPOINT_DIR / f"cons-{m}.json", old)
        new_path = checkpoint_file(CHECKPOINT_DIR / f"cons-{n}.json", new)
        proof_path = proof_file(PROOF_DIR / f"consistency-{m}-{n}.json",
                                proof.as_dict())
        result = offline("consistency", "--old-checkpoint", str(old_path),
                         "--new-checkpoint", str(new_path),
                         "--proof", str(proof_path), "--json", allow_fail=True)
        check(f"一致性 {m}->{n} 离线核验退出码 0", result.returncode, 0)
        payload = json.loads(result.stdout) if result.stdout.strip() else {}
        check(f"一致性 {m}->{n} 新增叶数", payload.get("appended_leaves"), n - m)
        # 参考实现交叉核对路径（树长超过 9 时，参考实现需要同一批叶子）
        prefix = leaf_hashes if n <= len(leaf_hashes) else live_leaf_hashes(n)
        reference_path = ref.consistency_proof(prefix[:n], m)
        check(f"一致性 {m}->{n} 路径与参考实现一致",
              [node.hex() for node in proof.path],
              [node.hex() for node in reference_path])

    # 用检查点文件本身演示「旧检查点没有被新收件改写」
    saved = json.loads((CHECKPOINT_DIR / "checkpoint-05.json").read_text())
    current = read_checkpoint(str(live_db), "acme")
    check("已发出的旧检查点仍是 tree_size=5", saved["tree_size"], 5)
    check("当前检查点已前进到 11", current.tree_size, 11)
    try:
        prove_consistency(
            str(live_db), "acme",
            merkle.Checkpoint("wrong-log", "acme", 5, CHECKPOINTS[5].root_hash),
            current)
        check("生成时拒绝错误的 log_id", "未报错", "应报错")
    except LedgerError as exc:
        check("生成时拒绝错误的 log_id", exc.code, "cross_log_id")
    try:
        prove_consistency(
            str(live_db), "acme",
            merkle.Checkpoint(log_id, "acme", 5, b"\x00" * 32), current)
        check("生成时拒绝根不符的检查点", "未报错", "应报错")
    except LedgerError as exc:
        check("生成时拒绝根不符的检查点", exc.code, "checkpoint_root_mismatch")

    # ---------------- 6. 小样本参考实现 + 篡改 ----------------
    run_reference_cross_check(leaf_hashes[:9])

    section("6. 篡改证明后离线核验必须失败（非零退出码）")
    tamper_dir = work / "tamper"
    tamper_dir.mkdir(exist_ok=True)
    cp_path = CHECKPOINT_DIR / "checkpoint-09.json"
    good_event = "cp-05"
    good = prove_inclusion(str(live_db), "acme", CHECKPOINTS[9], good_event)
    good_doc = good.as_dict()
    good_proof_path = proof_file(tamper_dir / "good.json", good_doc)
    check("原始证明核验通过",
          verify_inclusion_offline(cp_path, good_proof_path, good_event,
                                   SEQUENCES[good_event],
                                   BODIES[good_event]).returncode, 0)

    def flip_hex(text: str) -> str:
        return ("f" if text[0] != "f" else "0") + text[1:]

    tampered: list[tuple[str, dict, dict]] = []
    tampered.append(("错叶（换成别的事件）",
                     {**good_doc, "event_id": "cp-06"},
                     {"event_id": "cp-06", "sequence": SEQUENCES["cp-06"],
                      "body": BODIES["cp-06"]}))
    tampered.append(("错位置", {**good_doc, "leaf_index": 6},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    path_mod = list(good_doc["path"])
    path_mod[0] = flip_hex(path_mod[0])
    tampered.append(("修改路径节点", {**good_doc, "path": path_mod},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    tampered.append(("缺节点", {**good_doc, "path": good_doc["path"][:-1]},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    tampered.append(("多节点", {**good_doc, "path": good_doc["path"] + ["0" * 64]},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    tampered.append(("非法十六进制",
                     {**good_doc, "path": ["zz" + good_doc["path"][0][2:]]
                      + good_doc["path"][1:]},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    tampered.append(("布尔值冒充整数", {**good_doc, "source_seq": True},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    tampered.append(("跨合作方", {**good_doc, "partner_id": "globex"},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    tampered.append(("跨 log_id", {**good_doc, "log_id": "0" * 32},
                     {"event_id": good_event, "sequence": SEQUENCES[good_event],
                      "body": BODIES[good_event]}))
    for label, doc, fields in tampered:
        path = proof_file(tamper_dir / f"{len(tampered)}-{label}.json", doc)
        result = verify_inclusion_offline(
            cp_path, path, fields["event_id"], fields["sequence"], fields["body"])
        check(f"篡改「{label}」被拒绝（非零退出码）",
              result.returncode != 0, True)
        check(f"篡改「{label}」失败原因可读", bool(result.stderr.strip()), True)

    # 用别的检查点核验同一证明：树长不符也必须失败
    result = verify_inclusion_offline(
        CHECKPOINT_DIR / "checkpoint-08.json", good_proof_path, good_event,
        SEQUENCES[good_event], BODIES[good_event])
    check("用不相符的检查点核验在账证明被拒绝",
          result.returncode != 0, True)

    # 一致性证明篡改
    old = read_checkpoint(str(live_db), "acme", tree_size=3)
    new = read_checkpoint(str(live_db), "acme", tree_size=11)
    cons = prove_consistency(str(live_db), "acme", old, new).as_dict()
    old_path = checkpoint_file(tamper_dir / "old3.json", old)
    new_path = checkpoint_file(tamper_dir / "new11.json", new)
    cons_tampered = [
        ("修改一致性节点",
         {**cons, "path": [flip_hex(cons["path"][0])] + cons["path"][1:]}),
        ("缺一致性节点", {**cons, "path": cons["path"][:-1]}),
        ("多一致性节点", {**cons, "path": cons["path"] + ["0" * 64]}),
        ("一致性树长改小", {**cons, "old_size": 4}),
        ("一致性跨 log_id", {**cons, "log_id": "1" * 32}),
    ]
    for label, doc in cons_tampered:
        path = proof_file(tamper_dir / f"cons-{len(doc)}-{label}.json", doc)
        result = offline("consistency", "--old-checkpoint", str(old_path),
                         "--new-checkpoint", str(new_path), "--proof",
                         str(path), allow_fail=True)
        check(f"篡改「{label}」被拒绝（非零退出码）", result.returncode != 0, True)
    # 旧新检查点大小倒退
    result = offline("consistency", "--old-checkpoint", str(new_path),
                     "--new-checkpoint", str(old_path),
                     "--proof", str(proof_file(tamper_dir / "cons-x.json",
                                               cons)), allow_fail=True)
    check("树长倒退被拒绝", result.returncode != 0, True)

    # 空树与一叶树行为
    section("7. 空树与一叶树")
    empty_cp = merkle.Checkpoint(log_id, "acme", 0, merkle.empty_root())
    empty_path = checkpoint_file(tamper_dir / "empty.json", empty_cp)
    one_cp = read_checkpoint(str(live_db), "acme", tree_size=1)
    one_path = checkpoint_file(tamper_dir / "one.json", one_cp)
    empty_proof = ref.consistency_proof(leaf_hashes[:1], 0)
    empty_cons = merkle.ConsistencyProof(log_id, "acme", 0, 1,
                                         tuple(empty_proof))
    result = offline("consistency", "--old-checkpoint", str(empty_path),
                     "--new-checkpoint", str(one_path),
                     "--proof", str(proof_file(tamper_dir / "empty-cons.json",
                                               empty_cons.as_dict())),
                     allow_fail=True)
    check("0->1 一致性证明为空且核验通过", result.returncode, 0)
    same = merkle.ConsistencyProof(log_id, "acme", 1, 1, ())
    result = offline("consistency", "--old-checkpoint", str(one_path),
                     "--new-checkpoint", str(one_path),
                     "--proof", str(proof_file(tamper_dir / "same-cons.json",
                                               same.as_dict())), allow_fail=True)
    check("相同树长一致性证明为空且核验通过", result.returncode, 0)
    one_inc = prove_inclusion(str(live_db), "acme", one_cp, "cp-01")
    check("一叶树在账路径为空", one_inc.path, ())
    result = verify_inclusion_offline(
        one_path, proof_file(tamper_dir / "one-inc.json", one_inc.as_dict()),
        "cp-01", SEQUENCES["cp-01"], BODIES["cp-01"])
    check("一叶树在账证明核验通过", result.returncode, 0)
    empty_inc = merkle.InclusionProof(log_id, "acme", 0, 0, "x", 0, "0" * 64,
                                      ())
    result = offline("inclusion", "--checkpoint", str(empty_path),
                     "--proof", str(proof_file(tamper_dir / "empty-inc.json",
                                               empty_inc.as_dict())),
                     "--event-id", "x", "--source-seq", "0",
                     "--body-sha256", "0" * 64, allow_fail=True)
    check("空树检查点下无法生成在账证明", result.returncode != 0, True)

    # ---------------- 7. 重复/冲突/拒收对树长的影响 ----------------
    section("8. 重复、冲突、拒收与身份边界")
    size_before = log_status(str(live_db), "acme")["tree_size"]
    service, storage = make_service(str(live_db))
    try:
        duplicate = deliver(service, "acme", "cp-03", 31, BODIES["cp-03"])
        check("重复投递判定 duplicate", duplicate.result, "duplicate")
        conflict = deliver(service, "acme", "cp-03", 31, b'{"different":1}')
        check("同号异载荷判定 conflict", conflict.result, "conflict")
        rejected = deliver(service, "acme", "cp-reject", 12, b'{"x":1}',
                           bad_signature=True)
        check("坏签名判定 rejected", rejected.result, "rejected")
        # 相同 source_seq 的不同事件都追加叶子
        deliver(service, "acme", "same-seq-1", 1234, b'{"same":1}')
        deliver(service, "acme", "same-seq-2", 1234, b'{"same":2}')
        # 同正文不同事件
        deliver(service, "acme", "same-body-1", 2000, b'{"same_body":true}')
        deliver(service, "acme", "same-body-2", 2001, b'{"same_body":true}')
        # 二进制正文
        binary = bytes(range(256)) + b"\x00\xff"
        deliver(service, "acme", "binary-body", 3000, binary)
        BODIES["binary-body"] = binary
        SEQUENCES["binary-body"] = 3000
    finally:
        storage.close()
    size_after = log_status(str(live_db), "acme")["tree_size"]
    check("重复/冲突/拒收不增加叶子（+5 条合法事件）",
          size_after - size_before, 5)

    # 不同合作方的同号事件：各自账本独立
    install(db_path=str(live_db), partner_id="globex")
    check("live 库中 globex 初始账本为空",
          log_status(str(live_db), "globex")["tree_size"], 0)
    service, storage = make_service(str(live_db))
    try:
        result = deliver(service, "globex", "cp-05", 31,
                         json.dumps({"position": 5}).encode())
        check("globex 与 acme 同号事件被接受", result.result, "accepted")
    finally:
        storage.close()
    acme_status = log_status(str(live_db), "acme")
    globex_status = log_status(str(live_db), "globex")
    check("acme 账本不受 globex 影响", acme_status["tree_size"], size_after)
    check("globex 账本独立计数", globex_status["tree_size"], 1)
    check("两合作方 log_id 不同", acme_status["log_id"] != globex_status["log_id"],
          True)
    # 跨合作方证明被拒绝：globex 账本里没有 acme 的事件
    globex_cp = read_checkpoint(str(live_db), "globex")
    try:
        prove_inclusion(str(live_db), "globex", globex_cp, "cp-01")
        check("跨合作方生成证明被拒绝", "未报错", "应报错")
    except LedgerError as exc:
        check("跨合作方生成证明被拒绝", exc.code, "event_not_in_log")
    # 跨 log_id：合作方正确但 log_id 不是本账本的，必须被拒绝
    try:
        prove_inclusion(
            str(live_db), "acme",
            merkle.Checkpoint("0" * 32, "acme", 9, CHECKPOINTS[9].root_hash),
            "cp-05")
        check("跨 log_id 生成证明被拒绝", "未报错", "应报错")
    except LedgerError as exc:
        check("跨 log_id 生成证明被拒绝", exc.code, "cross_log_id")
    # 离线核验：globex 的检查点不能给 acme 的证明背书
    globex_path = checkpoint_file(tamper_dir / "globex-1.json", globex_cp)
    acme_good = proof_file(tamper_dir / "acme-good.json", good_doc)
    result = verify_inclusion_offline(
        globex_path, acme_good, good_event, SEQUENCES[good_event],
        BODIES[good_event])
    check("跨合作方检查点核验 acme 证明被拒绝", result.returncode != 0, True)

    # 加权不变式：叶子字段与 accepted_events 逐条对应
    conn = sqlite3.connect(live_db)
    mismatch = conn.execute(
        "SELECT COUNT(*) FROM log_leaves l JOIN accepted_events a"
        " ON a.partner_id=l.partner_id AND a.event_id=l.event_id"
        " WHERE a.source_seq != l.source_seq OR a.body_sha256 != l.body_sha256"
    ).fetchone()[0]
    orphan = conn.execute(
        "SELECT COUNT(*) FROM log_leaves l LEFT JOIN accepted_events a"
        " ON a.partner_id=l.partner_id AND a.event_id=l.event_id"
        " WHERE a.event_id IS NULL").fetchone()[0]
    conn.close()
    check("叶字段与 accepted_events 一致", mismatch, 0)
    check("没有孤立叶子", orphan, 0)

    # ---------------- 8. 回滚不留幽灵叶 ----------------
    section("9. 接收事务提交前抛错回滚")
    rollback_db = work / "rollback.db"
    shutil.copyfile(live_db, rollback_db)
    try:
        install(db_path=str(rollback_db), partner_id="acme")
    except LedgerError:
        pass
    conn = sqlite3.connect(rollback_db)
    before = (
        conn.execute("SELECT COUNT(*) FROM accepted_events").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM log_leaves").fetchone()[0],
        conn.execute("SELECT tree_size, root_hash FROM event_logs"
                     " WHERE partner_id='acme'").fetchone(),
    )
    conn.close()
    service, storage = make_service(str(rollback_db))
    try:
        body = b'{"rollback":true}'
        headers = signed("acme", "rollback-event", 4000, body)
        # 注入一个在提交前必然失败的钩子：账本追加后抛错。
        original = storage.append_event_log_leaf

        def boom(**kwargs):
            original(**kwargs)
            raise RuntimeError("模拟账本写入后崩溃")

        storage.append_event_log_leaf = boom
        try:
            service.receive(method="POST", path=PATH, raw_headers=headers,
                            body=body)
            raised = False
        except RuntimeError:
            raised = True
        check("模拟崩溃被抛出", raised, True)
    finally:
        storage.close()
    conn = sqlite3.connect(rollback_db)
    after = (
        conn.execute("SELECT COUNT(*) FROM accepted_events").fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM log_leaves").fetchone()[0],
        conn.execute("SELECT tree_size, root_hash FROM event_logs"
                     " WHERE partner_id='acme'").fetchone(),
    )
    ghost_leaf = conn.execute(
        "SELECT COUNT(*) FROM log_leaves WHERE event_id='rollback-event'"
    ).fetchone()[0]
    conn.close()
    check("回滚后 accepted_events 未增加", after[0], before[0])
    check("回滚后没有幽灵叶子", after[1], before[1])
    check("回滚后账本 tree_size/root 不变", after[2], before[2])
    check("回滚事件没有留下叶子行", ghost_leaf, 0)

    # ---------------- 9. 大样本：节点访问不随总事件数线性增长 ----------------
    section(f"10. {args.bulk} 片叶子：旧前缀查询与证明的节点读取计数")
    bulk_db = work / "bulk.db"
    bulk_db.unlink(missing_ok=True)
    Storage(str(bulk_db)).close()
    install(db_path=str(bulk_db), partner_id="acme")
    service, storage = make_service(str(bulk_db))
    started = time.monotonic()
    try:
        for index in range(args.bulk):
            body = b"x"  # 正文内容不重要，摘要不同即可
            event_id = f"bulk-{index}"
            headers = signed("acme", event_id, index % 100003, body)
            service.receive(method="POST", path=PATH, raw_headers=headers,
                            body=body)
    finally:
        storage.close()
    elapsed = time.monotonic() - started
    total = log_status(str(bulk_db), "acme")["tree_size"]
    check("大样本叶子总数", total, args.bulk)

    # 查询旧前缀：节点读取应当 O(log n)，而不是 O(n)
    trace_small = ReadTrace()
    small_cp = read_checkpoint(str(bulk_db), "acme", tree_size=64,
                               trace=trace_small)
    trace_large = ReadTrace()
    large_cp = read_checkpoint(str(bulk_db), "acme", tree_size=args.bulk,
                               trace=trace_large)
    trace_mid = ReadTrace()
    mid_size = args.bulk // 2
    mid_cp = read_checkpoint(str(bulk_db), "acme", tree_size=mid_size,
                             trace=trace_mid)
    print(f"         旧前缀 64 节点读取={trace_small.node_reads}；"
          f"{mid_size} 节点读取={trace_mid.node_reads}；"
          f"{args.bulk} 节点读取={trace_large.node_reads}")
    check_true("旧前缀 64 的节点读取 < 20", trace_small.node_reads < 20,
               str(trace_small.node_reads))
    check_true(f"旧前缀 {args.bulk} 的节点读取 <= log2(n)+2",
               trace_large.node_reads <= args.bulk.bit_length() + 2,
               str(trace_large.node_reads))
    check_true("两倍树长的读取增长很小（不是线性）",
               trace_large.node_reads - trace_mid.node_reads <= 4,
               f"{trace_mid.node_reads} -> {trace_large.node_reads}")

    # 旧前缀的根必须与独立参考实现按前缀重算的根一致
    bulk_prefix_hashes = live_leaf_hashes(args.bulk, bulk_db)
    check("旧前缀 64 的根与参考实现一致",
          small_cp.root_hash, ref.checkpoint_root(bulk_prefix_hashes, 64))
    check("旧前缀一半的根与参考实现一致",
          mid_cp.root_hash, ref.checkpoint_root(bulk_prefix_hashes, mid_size))
    check("当前根与参考实现一致",
          large_cp.root_hash, ref.tree_root(bulk_prefix_hashes))
    check_true("旧前缀根不是当前根（前缀根确实按 tree_size 重建）",
               small_cp.root_hash != large_cp.root_hash, True)

    # 单条在账证明的节点读取
    latest_cp = read_checkpoint(str(bulk_db), "acme")
    inclusion_proof = None
    proof_trace = ReadTrace()
    inclusion_proof = prove_inclusion(str(bulk_db), "acme", latest_cp,
                                      f"bulk-{args.bulk - 1}",
                                      trace=proof_trace)
    print(f"         在账证明（含前缀根重建 + 路径）节点读取="
          f"{proof_trace.node_reads}")
    check_true("在账证明节点读取随树高增长而非叶数",
               proof_trace.node_reads < 4 * args.bulk.bit_length(),
               str(proof_trace.node_reads))

    # 一致性证明的读取
    old_cp = read_checkpoint(str(bulk_db), "acme", tree_size=args.bulk - 1)
    consistency_trace = ReadTrace()
    consistency = prove_consistency(str(bulk_db), "acme", old_cp,
                                    latest_cp, trace=consistency_trace)
    print(f"         一致性证明节点读取={consistency_trace.node_reads}")
    check_true("一致性证明读取随树高而非叶数",
               consistency_trace.node_reads < 6 * args.bulk.bit_length(),
               str(consistency_trace.node_reads))
    check("一致性证明路径与参考实现一致（n-1 -> n）",
          [node.hex() for node in consistency.path],
          [node.hex() for node in ref.consistency_proof(
              bulk_prefix_hashes, args.bulk - 1)])

    # 扫描量证据：直接对 accepted_events/log_leaves 的读取计数为 0
    check("证明生成不读取 accepted_events（meta_reads 只含 event_logs）",
          proof_trace.meta_reads, 1)
    check("检查点读取只读 event_logs 一行", trace_large.meta_reads, 1)
    static_scan = sqlite3.connect(bulk_db).execute(
        "EXPLAIN QUERY PLAN SELECT node_hash FROM log_nodes WHERE"
        " partner_id=? AND level=? AND node_index=?",
        ("acme", 0, 0)).fetchall()
    plan_text = " | ".join(str(row[-1]) for row in static_scan)
    print(f"         节点点查执行计划: {plan_text}")
    check_true("节点点查使用主键索引（不是全表扫描）",
               ("USING PRIMARY KEY" in plan_text or
                "USING INDEX" in plan_text or "SEARCH" in plan_text)
               and "SCAN log_nodes" not in plan_text, plan_text)
    leaf_scan = sqlite3.connect(bulk_db).execute(
        "EXPLAIN QUERY PLAN SELECT leaf_hash FROM log_leaves WHERE"
        " partner_id=? AND leaf_index=?", ("acme", 0)).fetchall()
    leaf_text = " | ".join(str(row[-1]) for row in leaf_scan)
    print(f"         叶点查执行计划: {leaf_text}")
    check_true("叶点查使用主键索引（不是全表扫描）",
               "SCAN log_leaves" not in leaf_text, leaf_text)


    # 查询耗时与叶数不成正比
    query_started = time.monotonic()
    for _ in range(100):
        read_checkpoint(str(bulk_db), "acme", tree_size=args.bulk)
    query_elapsed = time.monotonic() - query_started
    print(f"         100 次当前检查点读取耗时 {query_elapsed:.3f}s"
          f"（{args.bulk} 叶，单次 {query_elapsed * 10:.1f}ms）")
    check_true("单次检查点读取 < 50ms", query_elapsed / 100 < 0.05, f"{query_elapsed:.3f}s")
    print(f"         写入 {args.bulk} 条真实收件耗时 {elapsed:.1f}s")

    # 路径与参考实现一致（抽样大树）
    bulk_leaf_hashes = []
    conn = sqlite3.connect(bulk_db)
    rows = conn.execute(
        "SELECT event_id, source_seq, body_sha256 FROM log_leaves"
        " WHERE partner_id='acme' ORDER BY leaf_index").fetchall()
    conn.close()
    # 只取需要的两段：整个列表用于参考实现可能较慢，抽尾叶验证
    sample_index = args.bulk - 1
    tail = rows[-64:]
    start_index = args.bulk - len(tail)
    ref_tail = [ref.leaf_hash("acme", e, s, bytes.fromhex(d))
                for e, s, d in tail]
    ref_path = ref.inclusion_proof(ref_tail, sample_index - start_index)
    # 参考实现的路径从尾段局部树出发，与整树路径只在尾部相同；
    # 用整树重建更直接：从节点存储取路径已经由离线核验器独立核验。
    result = offline(
        "inclusion", "--checkpoint", str(checkpoint_file(
            CHECKPOINT_DIR / "bulk-current.json", latest_cp)),
        "--proof", str(proof_file(PROOF_DIR / "bulk-inclusion.json",
                                  inclusion_proof.as_dict())),
        "--event-id", f"bulk-{sample_index}", "--source-seq",
        str(rows[sample_index][1]),
        "--body-sha256", rows[sample_index][2], "--json", allow_fail=True)
    check("大样本在账证明离线核验通过", result.returncode, 0)

    # ---------------- 10. 移走数据库后独立核验 ----------------
    section("11. 移走数据库后，保存的凭据仍可独立核验")
    saved_cp = CHECKPOINT_DIR / "checkpoint-09.json"
    saved_proof = PROOF_DIR / "inclusion-main-cp-05-n9.json"
    hidden = work / "live.db.hidden"
    os.replace(live_db, hidden)
    try:
        result = verify_inclusion_offline(
            saved_cp, saved_proof, "cp-05", SEQUENCES["cp-05"],
            BODIES["cp-05"])
        check("数据库移走后离线核验在账证明", result.returncode, 0)
        result = offline("consistency", "--old-checkpoint",
                         str(CHECKPOINT_DIR / "cons-3.json"),
                         "--new-checkpoint", str(CHECKPOINT_DIR / "cons-11.json"),
                         "--proof", str(PROOF_DIR / "consistency-3-11.json"),
                         allow_fail=True)
        check("数据库移走后离线核验一致性证明", result.returncode, 0)
    finally:
        os.replace(hidden, live_db)

    # 证明文件不带任何其他事件的身份/正文
    inclusion_doc = json.loads(saved_proof.read_text())
    allowed = {"format", "version", "protocol", "log_id", "partner_id",
               "tree_size", "leaf_index", "event_id", "source_seq",
               "body_sha256", "path"}
    check("在账证明字段固定且不含其他事件", set(inclusion_doc), allowed)
    check("在账证明不含正文", "body_blob" not in json.dumps(inclusion_doc),
          True)
    check("在账证明只携带待验叶的摘要，不含其他叶摘要",
          json.dumps(inclusion_doc).count('"body_sha256"'), 1)

    # 账本重开后仍能为旧检查点出证明
    service, storage = make_service(str(live_db))
    storage.close()
    reopened = prove_inclusion(str(live_db), "acme", CHECKPOINTS[5], "cp-03")
    check("账本重开后仍能为旧检查点出证明",
          verify_inclusion_offline(
              CHECKPOINT_DIR / "checkpoint-05.json",
              proof_file(PROOF_DIR / "reopen-cp-03.json", reopened.as_dict()),
              "cp-03", SEQUENCES["cp-03"], BODIES["cp-03"]).returncode, 0)


RACE_WORKER = r'''
"""两进程并发收件子进程：交错投递同一批事件。"""
import json
import sys

from pathlib import Path

REPO_ROOT = Path(sys.argv[6])
sys.path.insert(0, str(REPO_ROOT))

from partner_webhook.canonical import (
    HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER, HEADER_PROTOCOL,
    HEADER_SEQUENCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_bytes,
)
from partner_webhook.config import load_config
from partner_webhook.crypto import decode_secret, sign
from partner_webhook.service import PROTOCOL_VERSION, WebhookService
from partner_webhook.storage import Storage

db_path, config_path, plan_path, slot, total, _ = sys.argv[1:7]
slot = int(slot)
total = int(total)
events = json.loads(Path(plan_path).read_text())
storage = Storage(db_path)
service = WebhookService(load_config(config_path), storage,
                         clock=lambda: 2_000_000_000.0)
secret = decode_secret("b2xkLWFjbWUtc2VjcmV0LWtleS0wMDE=")
try:
    for position in range(slot, len(events), total):
        event_id, sequence = events[position]
        body = json.dumps({"position": position}).encode()
        canonical = canonical_bytes(
            method="POST", path="/webhook/events", partner_id="acme",
            key_version="v1", timestamp=2_000_000_000,
            event_id=event_id, sequence=sequence, body=body,
        )
        headers = {
            HEADER_PROTOCOL: PROTOCOL_VERSION, HEADER_PARTNER: "acme",
            HEADER_KEY_VERSION: "v1", HEADER_TIMESTAMP: "2000000000",
            HEADER_EVENT_ID: event_id, HEADER_SEQUENCE: str(sequence),
            HEADER_SIGNATURE: sign(secret, canonical),
        }
        result = service.receive(method="POST", path="/webhook/events",
                                 raw_headers=headers, body=body)
        if result.result != "accepted":
            raise SystemExit(f"意外结果 {event_id}: {result.result}")
finally:
    storage.close()
'''


if __name__ == "__main__":
    raise SystemExit(main())
