#!/usr/bin/env python3
"""离线接收库提取器验收材料（可复跑，真实建库 + 真实破坏 + 独立核对）。

流程：
  1. 用现有服务（WebhookService）与标准 sqlite3 生成真实数据库镜像，
     覆盖 512 / 4096 / 65536 三种页长、足以分裂内部/叶子页的事件量、
     跨多张溢出页的大正文、空正文、含零字节正文、非 UTF-8 正文、
     大 rowid（9 字节 varint）与大整数列；
  2. 以正常库的 SQL 查询结果为独立参照，逐字段核对提取输出，
     并用独立片段读取器按 bodies.jsonl 的 fragments 从源镜像拼回正文；
  3. 复制镜像并针对已知页做破坏（叶页 / 单 cell / 溢出链 / 共享页 /
     目录 / 截短 / 正文字节），验证退出码、诊断与隔离粒度；
  4. 演示资源上限、非空 WAL 旁文件、输出目录已存在等拒绝/部分结果路径；
  5. 每次提取前后比较源文件摘要，证明源库从未被修改。

用法：
  python3 -I scripts/salvage_acceptance.py [--workdir DIR]

本脚本只用于造库、破坏副本与核对；被测提取路径（partner_webhook/salvage.py）
不经过 SQL 引擎。
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
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))  # 仅为造库/核对导入现有服务代码

from partner_webhook.canonical import (  # noqa: E402
    HEADER_EVENT_ID, HEADER_KEY_VERSION, HEADER_PARTNER, HEADER_PROTOCOL,
    HEADER_SEQUENCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, canonical_bytes,
)
from partner_webhook.config import load_config  # noqa: E402
from partner_webhook.crypto import decode_secret, sign  # noqa: E402
from partner_webhook.service import WebhookService  # noqa: E402
from partner_webhook.storage import Storage  # noqa: E402

SALVAGE_PY = REPO_ROOT / "partner_webhook" / "salvage.py"
MIGRATION_SQL = (REPO_ROOT / "migrations" / "0001_init.sql").read_text(
    encoding="utf-8")
CONFIG_JSON = REPO_ROOT / "config.example.json"

NOW = 1_770_000_000  # 固定时钟（2026-02），落在示例密钥 v1 有效期内
SECRET = decode_secret("b2xkLWFjbWUtc2VjcmV0LWtleS0wMDE=")  # acme / v1

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" +
          (f" — {detail}" if detail else ""))


def check(name: str, errors: list[str]) -> None:
    if errors:
        record(name, False, f"{len(errors)} 处不符：{errors[0]}")
        for err in errors[1:6]:
            print(f"        - {err}")
    else:
        record(name, True)


# --------------------------------------------------------------------------- #
# 造库：现有服务 + 标准 sqlite3
# --------------------------------------------------------------------------- #
def deliver(service, event_id, seq, body, *, bad_signature=False):
    canonical = canonical_bytes(
        method="POST", path="/webhook/events", partner_id="acme",
        key_version="v1", timestamp=NOW, event_id=event_id,
        sequence=seq, body=body)
    headers = {
        HEADER_PROTOCOL: "webhook-v1",
        HEADER_PARTNER: "acme",
        HEADER_KEY_VERSION: "v1",
        HEADER_TIMESTAMP: str(NOW),
        HEADER_EVENT_ID: event_id,
        HEADER_SEQUENCE: str(seq),
        HEADER_SIGNATURE: "0" * 64 if bad_signature else sign(SECRET, canonical),
    }
    return service.receive(method="POST", path="/webhook/events",
                           raw_headers=headers, body=body)


def patterned_body(size: int) -> bytes:
    """确定性大正文（含零字节与非 UTF-8 字节）。"""
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def build_image(db_path: Path, page_size: int, n_events: int,
                big_bodies: list[int]) -> None:
    """按页长建库：迁移 + 服务投递 + SQL 补充大 rowid / 大整数行。"""
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA page_size={page_size}")
    conn.executescript(MIGRATION_SQL)
    conn.commit()
    conn.close()

    storage = Storage(str(db_path))
    service = WebhookService(load_config(str(CONFIG_JSON)), storage,
                             clock=lambda: float(NOW))
    for i in range(n_events):
        body = json.dumps({"n": i, "pad": "x" * (i % 37)}).encode()
        result = deliver(service, f"evt-{i:04d}", i + 1, body)
        assert result.result == "accepted", (i, result)
    # 特殊正文：空、含零字节、非 UTF-8、跨多页溢出的大正文
    specials = [(f"evt-special-empty", b""),
                (f"evt-special-zeros", b"\x00\x01\x00\x00\xff"),
                (f"evt-special-nonutf8", b"\xff\xfe\x00bin")]
    for idx, size in enumerate(big_bodies):
        specials.append((f"evt-special-big{idx}", patterned_body(size)))
    seq = n_events + 1
    for event_id, body in specials:
        result = deliver(service, event_id, seq, body)
        assert result.result == "accepted", (event_id, result)
        seq += 1
    # 重复 / 冲突 / 拒收：产生未关联正文（不得判为损坏）
    deliver(service, "evt-0000", 1, json.dumps({"n": 0, "pad": ""}).encode())
    deliver(service, "evt-0000", 1, b'{"n":0,"conflict":true}')
    deliver(service, "evt-rejected", seq, b'{"bad":true}', bad_signature=True)
    storage.close()

    # 标准 sqlite3 补充：大 rowid（9 字节 varint）、负 rowid、大整数列
    conn = sqlite3.connect(db_path)
    big_body = b"big-rowid-body\x00"
    big_sha = hashlib.sha256(big_body).hexdigest()
    conn.execute(
        "INSERT INTO raw_bodies(rowid, body_sha256, body_blob, byte_length,"
        " first_seen_at) VALUES (?,?,?,?,?)",
        (1 << 61, big_sha, big_body, len(big_body), NOW))
    conn.execute(
        "INSERT INTO accepted_events(rowid, event_id, partner_id, source_seq,"
        " key_version, body_sha256, ingest_record_id, claimed_timestamp,"
        " accepted_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (1 << 60, "evt-huge-rowid", "acme", 1 << 50, "v1", big_sha, 1,
         1 << 40, NOW))
    neg_body = b"neg-rowid-body"
    neg_sha = hashlib.sha256(neg_body).hexdigest()
    conn.execute(
        "INSERT INTO raw_bodies(rowid, body_sha256, body_blob, byte_length,"
        " first_seen_at) VALUES (?,?,?,?,?)",
        (-(1 << 40), neg_sha, neg_body, len(neg_body), NOW))
    conn.execute(
        "INSERT INTO accepted_events(rowid, event_id, partner_id, source_seq,"
        " key_version, body_sha256, ingest_record_id, claimed_timestamp,"
        " accepted_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (-9, "evt-neg-rowid", "acme", 7, "v1", neg_sha, 1, NOW, NOW))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    for suffix in ("-wal", "-journal"):
        side = str(db_path) + suffix
        if os.path.exists(side):
            assert os.path.getsize(side) == 0, f"旁文件未归并: {side}"
            os.unlink(side)


def reference_dump(db_path: Path) -> dict:
    """独立参照：正常库的 SQL 查询结果。"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    events = [dict(r) for r in conn.execute(
        "SELECT rowid AS _rowid, * FROM accepted_events ORDER BY rowid")]
    bodies = []
    for row in conn.execute(
            "SELECT rowid AS _rowid, body_sha256, body_blob, byte_length,"
            " first_seen_at FROM raw_bodies ORDER BY rowid"):
        bodies.append({"_rowid": row["_rowid"],
                       "body_sha256": row["body_sha256"],
                       "byte_length": row["byte_length"],
                       "first_seen_at": row["first_seen_at"],
                       "blob_hex": bytes(row["body_blob"]).hex()})
    conn.close()
    return {"events": [{k: v for k, v in e.items()} for e in events],
            "bodies": bodies}


# --------------------------------------------------------------------------- #
# 提取（真实命令行）与独立核对
# --------------------------------------------------------------------------- #
def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_extract(image: Path, out: Path, *extra: str):
    """按文档命令运行提取器；返回 (退出码, stdout, stderr, 耗时秒)。"""
    cmd = [sys.executable, "-I", str(SALVAGE_PY), "--db", str(image),
           "--out", str(out), *extra]
    print(f"  $ {' '.join(cmd)}")
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    elapsed = time.monotonic() - started
    for line in proc.stdout.strip().splitlines():
        print(f"    {line}")
    if proc.stderr.strip():
        for line in proc.stderr.strip().splitlines():
            print(f"    [stderr] {line}")
    print(f"    -> 退出码 {proc.returncode}（{elapsed:.2f}s）")
    return proc.returncode, proc.stdout, proc.stderr, elapsed


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def splice_body(image_path: Path, fragments: list[dict]) -> bytes:
    """独立片段读取器：按 fragments 直接从源镜像拼回正文。"""
    parts = []
    with open(image_path, "rb") as fh:
        for frag in fragments:
            fh.seek(frag["offset"])
            data = fh.read(frag["length"])
            if len(data) != frag["length"]:
                raise AssertionError(f"片段读取短缺 @{frag['offset']}")
            parts.append(data)
    return b"".join(parts)


def compare_full(image: Path, out_dir: Path, ref: dict) -> list[str]:
    """提取输出与 SQL 参照逐字段核对 + 片段拼接核对。"""
    errors: list[str] = []
    events = read_jsonl(out_dir / "events.jsonl")
    bodies = read_jsonl(out_dir / "bodies.jsonl")
    confirmed = [e for e in events if e["status"] == "confirmed"]
    if len(confirmed) != len(ref["events"]):
        errors.append(f"确认事件数 {len(confirmed)} != 参照 {len(ref['events'])}")
    by_key = {(e["columns"]["partner_id"], e["columns"]["event_id"]): e
              for e in confirmed}
    for want in ref["events"]:
        got = by_key.get((want["partner_id"], want["event_id"]))
        if got is None:
            errors.append(f"缺少事件 {want['event_id']}")
            continue
        if got["rowid"] != want["_rowid"]:
            errors.append(f"{want['event_id']} rowid 不符")
        for col in ("event_id", "partner_id", "source_seq", "key_version",
                    "body_sha256", "ingest_record_id", "claimed_timestamp",
                    "accepted_at"):
            if got["columns"][col] != want[col]:
                errors.append(f"{want['event_id']}.{col} 不符")
        if got["body"]["state"] != "verified":
            errors.append(f"{want['event_id']} 正文关联状态 "
                          f"{got['body']['state']} != verified")
    verified = {b["declared_sha256"]: b for b in bodies
                if b["status"] == "verified"}
    if len(bodies) != len(ref["bodies"]):
        errors.append(f"正文条数 {len(bodies)} != 参照 {len(ref['bodies'])}")
    for want in ref["bodies"]:
        got = verified.get(want["body_sha256"])
        if got is None:
            errors.append(f"正文未验证 {want['body_sha256'][:12]}")
            continue
        blob = bytes.fromhex(want["blob_hex"])
        if got["rowid"] != want["_rowid"]:
            errors.append(f"正文 {want['body_sha256'][:12]} rowid 不符")
        if got["declared_byte_length"] != want["byte_length"]:
            errors.append(f"正文 {want['body_sha256'][:12]} byte_length 不符")
        if got["first_seen_at"] != want["first_seen_at"]:
            errors.append(f"正文 {want['body_sha256'][:12]} first_seen_at 不符")
        data = (out_dir / got["file"]).read_bytes()
        if data != blob:
            errors.append(f"正文 {want['body_sha256'][:12]} 文件字节不符")
        try:
            if splice_body(image, got["fragments"]) != blob:
                errors.append(f"正文 {want['body_sha256'][:12]} 片段拼接不符")
        except AssertionError as exc:
            errors.append(str(exc))
    return errors


class Case:
    """一个验收场景：建库/破坏/提取/核对。"""

    def __init__(self, workdir: Path, name: str):
        self.dir = workdir / name
        self.dir.mkdir(parents=True, exist_ok=False)
        self.name = name
        self.out_seq = 0

    def out_dir(self) -> Path:
        self.out_seq += 1
        return self.dir / f"out-{self.out_seq}"

    @staticmethod
    def poke(path: Path, offset: int, data: bytes) -> None:
        with open(path, "r+b") as fh:
            fh.seek(offset)
            fh.write(data)


def page_offset(page_no: int, page_size: int) -> int:
    return (page_no - 1) * page_size


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", default="demo_salvage_out",
                        help="验收工作目录（已存在则拒绝）")
    args = parser.parse_args()
    workdir = Path(args.workdir).resolve()
    if workdir.exists():
        print(f"工作目录已存在，拒绝覆盖: {workdir}", file=sys.stderr)
        return 1
    workdir.mkdir(parents=True)

    print(f"验收工作目录: {workdir}")
    print("=" * 72)

    # ------------------------------------------------------------------ #
    # 1. 三种页长的正常库：完整提取（退出码 0）+ 逐字段独立核对
    # ------------------------------------------------------------------ #
    plans = {512: (240, [5_000, 60_000]),
             4096: (1500, [200_000]),
             65536: (150, [300_000])}
    healthy: dict[int, dict] = {}
    for page_size, (n_events, big_bodies) in plans.items():
        print(f"\n### 正常库（页长 {page_size}，{n_events} 事件，"
              f"大正文 {big_bodies}）")
        case = Case(workdir, f"healthy-{page_size}")
        image = case.dir / f"healthy-{page_size}.db"
        build_image(image, page_size, n_events, big_bodies)
        ref = reference_dump(image)
        (case.dir / "reference.json").write_text(
            json.dumps(ref, ensure_ascii=False, indent=1), encoding="utf-8")
        before = sha256_file(image)
        out_dir = case.out_dir()
        code, _so, _se, _el = run_extract(image, out_dir)
        errors = []
        if code != 0:
            errors.append(f"退出码 {code} != 0")
        else:
            errors += compare_full(image, out_dir, ref)
        if sha256_file(image) != before:
            errors.append("提取前后源文件摘要发生变化")
        summary = json.loads((out_dir / "summary.json").read_text(
            encoding="utf-8"))
        print(f"    汇总: {json.dumps(summary['counts'], ensure_ascii=False)}")
        check(f"healthy-{page_size}: 完整提取且与 SQL 参照一致", errors)
        healthy[page_size] = {"image": image, "ref": ref, "out": out_dir,
                              "case": case}

    base512 = healthy[512]
    image512 = base512["image"]
    ref512 = base512["ref"]
    ok_events = read_jsonl(base512["out"] / "events.jsonl")
    ok_bodies = read_jsonl(base512["out"] / "bodies.jsonl")
    confirmed_ids = {e["columns"]["event_id"] for e in ok_events
                     if e["status"] == "confirmed"}

    # ------------------------------------------------------------------ #
    # 2. 破坏一个叶页：该页事件隔离，邻近好数据不丢
    # ------------------------------------------------------------------ #
    print("\n### 破坏：accepted_events 的一个叶页")
    case = Case(workdir, "corrupt-leaf")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    by_leaf: dict[int, list] = {}
    for event in ok_events:
        by_leaf.setdefault(event["leaf_page"], []).append(event)
    leaf = next(p for p, evs in sorted(by_leaf.items())
                if len(evs) >= 2 and p != 1)
    lost_ids = {e["columns"]["event_id"] for e in by_leaf[leaf]}
    print(f"  目标叶页 {leaf}（{len(lost_ids)} 条事件应隔离，"
          f"其余 {len(confirmed_ids) - len(lost_ids)} 条应保留）")
    case.poke(damaged, page_offset(leaf, 512), b"\x00" * 16)
    before = sha256_file(damaged)
    code, _so, _se, _el = run_extract(damaged, case.out_dir())
    out_dir = case.dir / "out-1"
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        after = read_jsonl(out_dir / "events.jsonl")
        now_confirmed = {e["columns"]["event_id"] for e in after
                         if e["status"] == "confirmed"}
        if lost_ids & now_confirmed:
            errors.append("坏页上的事件仍被确认")
        if now_confirmed != confirmed_ids - lost_ids:
            errors.append("邻近好数据没有完整保留")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        if not any(d.get("page") == leaf and d["severity"] == "error"
                   for d in diags):
            errors.append("诊断未指出损坏叶页")
    if sha256_file(damaged) != before:
        errors.append("源文件被修改")
    check("corrupt-leaf: 坏页隔离、其余保留", errors)

    # ------------------------------------------------------------------ #
    # 3. 破坏单个 cell：只隔离该条记录
    # ------------------------------------------------------------------ #
    print("\n### 破坏：单个 cell（cell 指针指向界外）")
    case = Case(workdir, "corrupt-cell")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    target = next(e for e in ok_events if e["leaf_page"] != 1)
    ptr_off = page_offset(target["leaf_page"], 512) + 8 + 2 * target["cell_index"]
    print(f"  目标事件 {target['columns']['event_id']}"
          f"（叶页 {target['leaf_page']} cell {target['cell_index']}）")
    case.poke(damaged, ptr_off, b"\xff\xff")
    before = sha256_file(damaged)
    code, _so, _se, _el = run_extract(damaged, case.out_dir())
    out_dir = case.dir / "out-1"
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        after = read_jsonl(out_dir / "events.jsonl")
        now_confirmed = {e["columns"]["event_id"] for e in after
                         if e["status"] == "confirmed"}
        lost = target["columns"]["event_id"]
        if lost in now_confirmed:
            errors.append("被坏 cell 的事件仍被确认")
        if now_confirmed != confirmed_ids - {lost}:
            errors.append("同叶页其他记录被牵连")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        if not any(d["code"] == "bad_cell_pointer" for d in diags):
            errors.append("缺少 bad_cell_pointer 诊断")
    if sha256_file(damaged) != before:
        errors.append("源文件被修改")
    check("corrupt-cell: 单条记录隔离", errors)

    # ------------------------------------------------------------------ #
    # 4. 溢出链：切断 / 成环 / 共享页
    # ------------------------------------------------------------------ #
    big_entry = next(b for b in ok_bodies
                     if b["fragments"] and len(b["fragments"]) > 5)
    big_sha = big_entry["declared_sha256"]
    big_event_id = next(e["columns"]["event_id"] for e in ok_events
                        if e["body"].get("declared_sha256") == big_sha)
    first_overflow_page = big_entry["fragments"][1]["offset"] // 512 + 1
    print(f"\n### 溢出链破坏（大正文 {big_sha[:12]}…，"
          f"事件 {big_event_id}，首溢出页 {first_overflow_page}）")

    def overflow_case(name, new_next, expect_diag):
        case = Case(workdir, name)
        damaged = case.dir / "damaged.db"
        shutil.copyfile(image512, damaged)
        case.poke(damaged, page_offset(first_overflow_page, 512),
                  new_next.to_bytes(4, "big"))
        before = sha256_file(damaged)
        code, _so, _se, elapsed = run_extract(damaged, case.out_dir())
        out_dir = case.dir / "out-1"
        errors = [] if code == 2 else [f"退出码 {code} != 2"]
        if not errors:
            bodies = read_jsonl(out_dir / "bodies.jsonl")
            if any(b["declared_sha256"] == big_sha
                   and b["status"] == "verified" for b in bodies):
                errors.append("受影响正文被列为已验证")
            events = read_jsonl(out_dir / "events.jsonl")
            big_event = next(e for e in events
                             if e["columns"]["event_id"] == big_event_id)
            if big_event["body"]["state"] != "missing":
                errors.append(f"事件正文状态 "
                              f"{big_event['body']['state']} != missing")
            diags = read_jsonl(out_dir / "diagnostics.jsonl")
            if not any(expect_diag in json.dumps(d, ensure_ascii=False)
                       for d in diags):
                errors.append(f"缺少诊断特征 {expect_diag!r}")
            others = {e["columns"]["event_id"] for e in events
                      if e["status"] == "confirmed"}
            if others != confirmed_ids:
                errors.append("其他事件未完整保留（事件行本身应全部确认，"
                              "只有正文关联降级）")
        if sha256_file(damaged) != before:
            errors.append("源文件被修改")
        check(f"{name}: 有界结束（{elapsed:.2f}s）且未验证", errors)

    overflow_case("corrupt-overflow-cut", 10 ** 9, "溢出页")
    overflow_case("corrupt-overflow-cycle", first_overflow_page, "成环")

    # 共享页：溢出链指向 accepted_events 的叶页 -> 双方记录都不得确认
    print("\n### 破坏：溢出链与表树共享同一页")
    case = Case(workdir, "corrupt-shared-page")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    victim_leaf = next(e["leaf_page"] for e in ok_events if e["leaf_page"] != 1)
    victim_ids = {e["columns"]["event_id"] for e in ok_events
                  if e["leaf_page"] == victim_leaf}
    print(f"  溢出链下一指针改为表树叶页 {victim_leaf}"
          f"（{len(victim_ids)} 条事件应被隔离）")
    case.poke(damaged, page_offset(first_overflow_page, 512),
              victim_leaf.to_bytes(4, "big"))
    before = sha256_file(damaged)
    code, _so, _se, _el = run_extract(damaged, case.out_dir())
    out_dir = case.dir / "out-1"
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        events = read_jsonl(out_dir / "events.jsonl")
        quarantined = {e["columns"]["event_id"] for e in events
                       if e["status"] == "quarantined"}
        if quarantined != victim_ids:
            errors.append("被歧义占用影响的事件未全部隔离")
        confirmed_now = {e["columns"]["event_id"] for e in events
                         if e["status"] == "confirmed"}
        if confirmed_now & victim_ids:
            errors.append("歧义页上的事件仍被确认")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        if not any(d["code"] == "page_ownership_conflict"
                   and d.get("page") == victim_leaf for d in diags):
            errors.append("缺少 page_ownership_conflict 诊断")
    if sha256_file(damaged) != before:
        errors.append("源文件被修改")
    check("corrupt-shared-page: 歧义占用双方隔离", errors)

    # ------------------------------------------------------------------ #
    # 5. 目录损坏 / 布局不符 / 截短 / 正文校验失配
    # ------------------------------------------------------------------ #
    print("\n### 破坏：目录（第 1 页类型字节）")
    case = Case(workdir, "corrupt-catalog")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    case.poke(damaged, 100, b"\x00")
    code, _so, stderr, _el = run_extract(damaged, case.out_dir())
    errors = [] if code == 1 else [f"退出码 {code} != 1"]
    if "提取被拒绝" not in stderr:
        errors.append("缺少可读的拒绝诊断")
    if (case.dir / "out-1").exists():
        errors.append("整体拒绝不应产生输出目录")
    check("corrupt-catalog: 整体拒绝（退出码 1）", errors)

    print("\n### 破坏：目录中目标表布局不符")
    case = Case(workdir, "corrupt-layout")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    data = damaged.read_bytes()
    col_at = data.index(b"event_id           TEXT NOT NULL")
    case.poke(damaged, col_at, b"event_XX")
    code, _so, stderr, _el = run_extract(damaged, case.out_dir())
    errors = [] if code == 1 else [f"退出码 {code} != 1"]
    if "布局不符" not in stderr:
        errors.append("缺少布局不符诊断")
    check("corrupt-layout: 整体拒绝（退出码 1）", errors)

    print("\n### 破坏：文件截短（保留前 60% 页）")
    case = Case(workdir, "truncated")
    damaged = case.dir / "damaged.db"
    total_pages = os.path.getsize(image512) // 512
    keep = int(total_pages * 0.6)
    with open(image512, "rb") as fh:
        head = fh.read(keep * 512)
    damaged.write_bytes(head)
    print(f"  总页数 {total_pages}，保留 {keep} 页")
    before = sha256_file(damaged)
    code, _so, _se, _el = run_extract(damaged, case.out_dir())
    out_dir = case.dir / "out-1"
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        events = read_jsonl(out_dir / "events.jsonl")
        confirmed_now = {e["columns"]["event_id"] for e in events
                         if e["status"] == "confirmed"}
        if not confirmed_now:
            errors.append("截短后没有任何可达事件被交付")
        if not confirmed_now < confirmed_ids:
            errors.append("截短后确认集合应是真子集")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        if not any(d["code"] in ("page_out_of_bounds", "db_size_mismatch",
                                 "child_out_of_bounds") for d in diags):
            errors.append("缺少截短相关诊断")
    if sha256_file(damaged) != before:
        errors.append("源文件被修改")
    check("truncated: 部分交付（退出码 2）", errors)

    print("\n### 破坏：正文单字节（SHA-256 校验失配）")
    case = Case(workdir, "corrupt-body-byte")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    victim = next(b for b in ok_bodies
                  if b["fragments"] and len(b["fragments"]) == 1
                  and b["fragments"][0]["length"] >= 4)
    flip_at = victim["fragments"][0]["offset"] + 2
    with open(damaged, "r+b") as fh:
        fh.seek(flip_at)
        original = fh.read(1)
        fh.seek(flip_at)
        fh.write(bytes([original[0] ^ 0xFF]))
    print(f"  翻转正文 {victim['declared_sha256'][:12]}… 的 1 字节"
      f"（文件偏移 {flip_at}）")
    before = sha256_file(damaged)
    code, _so, _se, _el = run_extract(damaged, case.out_dir())
    out_dir = case.dir / "out-1"
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        bodies = read_jsonl(out_dir / "bodies.jsonl")
        entry = next((b for b in bodies
                      if b["declared_sha256"] == victim["declared_sha256"]),
                     None)
        if entry is None or entry["status"] != "digest_mismatch":
            errors.append("失配正文未标为 digest_mismatch")
        elif not entry["file"].startswith("bodies/quarantine/"):
            errors.append("失配正文未隔离存放")
        events = read_jsonl(out_dir / "events.jsonl")
        linked = [e for e in events
                  if e["body"].get("declared_sha256")
                  == victim["declared_sha256"]]
        if not linked or any(e["body"]["state"] != "digest_mismatch"
                             for e in linked):
            errors.append("引用该正文的事件未列出失配")
        diags = read_jsonl(out_dir / "diagnostics.jsonl")
        if not any(d["code"] == "body_digest_mismatch" for d in diags):
            errors.append("缺少 body_digest_mismatch 诊断")
    if sha256_file(damaged) != before:
        errors.append("源文件被修改")
    check("corrupt-body-byte: 校验失配被列出", errors)

    # ------------------------------------------------------------------ #
    # 6. 旁文件 / 输出目录 / 资源上限
    # ------------------------------------------------------------------ #
    print("\n### 拒绝：非空 -wal / -journal 旁文件")
    for suffix in ("-wal", "-journal"):
        case = Case(workdir, f"sidefile{suffix.replace('-', '')}")
        damaged = case.dir / "damaged.db"
        shutil.copyfile(image512, damaged)
        Path(str(damaged) + suffix).write_bytes(b"\x01" * 16)
        code, _so, stderr, _el = run_extract(damaged, case.out_dir())
        errors = [] if code == 1 else [f"退出码 {code} != 1"]
        if "旁文件" not in stderr:
            errors.append("缺少旁文件拒绝诊断")
        check(f"sidefile{suffix}: 整体拒绝（退出码 1）", errors)

    print("\n### 拒绝：输出目录已存在")
    case = Case(workdir, "output-exists")
    existing = case.dir / "out-1"
    existing.mkdir()
    code, _so, stderr, _el = run_extract(image512, existing)
    errors = [] if code == 1 else [f"退出码 {code} != 1"]
    if "拒绝覆盖" not in stderr:
        errors.append("缺少拒绝覆盖诊断")
    check("output-exists: 整体拒绝（退出码 1）", errors)

    print("\n### 资源上限（退出码 2，留下未完成原因）")
    healthy_summary = json.loads(
        (base512["out"] / "summary.json").read_text(encoding="utf-8"))
    visited = healthy_summary["source"]["pages_visited"]

    case = Case(workdir, "limit-pages")
    code, _so, _se, _el = run_extract(image512, case.out_dir(),
                                      "--max-pages", str(visited - 3))
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        summary = json.loads((case.dir / "out-1" / "summary.json").read_text(
            encoding="utf-8"))
        if "page_limit" not in summary["unfinished_reasons"]:
            errors.append("缺少 page_limit 未完成原因")
    check(f"limit-pages: 访问页数上限（健康遍历需 {visited} 页）", errors)

    case = Case(workdir, "limit-payload")
    code, _so, _se, _el = run_extract(image512, case.out_dir(),
                                      "--max-payload-bytes", "4096")
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        summary = json.loads((case.dir / "out-1" / "summary.json").read_text(
            encoding="utf-8"))
        if "payload_limit" not in summary["unfinished_reasons"]:
            errors.append("缺少 payload_limit 未完成原因")
        bodies = read_jsonl(case.dir / "out-1" / "bodies.jsonl")
        if any(b["status"] == "verified" and b["computed_byte_length"]
               and b["computed_byte_length"] > 4096 for b in bodies):
            errors.append("超限正文仍被列为已验证")
    check("limit-payload: 单条载荷上限", errors)

    case = Case(workdir, "limit-diagnostics")
    damaged = case.dir / "damaged.db"
    shutil.copyfile(image512, damaged)
    for leaf in sorted(by_leaf)[:6]:
        case.poke(damaged, page_offset(leaf, 512), b"\x00" * 16)
    code, _so, _se, _el = run_extract(damaged, case.out_dir(),
                                      "--max-diagnostics", "3")
    errors = [] if code == 2 else [f"退出码 {code} != 2"]
    if not errors:
        diags = read_jsonl(case.dir / "out-1" / "diagnostics.jsonl")
        if not diags or diags[-1]["code"] != "diagnostics_limit_reached":
            errors.append("缺少 diagnostics_limit_reached 诊断")
        summary = json.loads((case.dir / "out-1" / "summary.json").read_text(
            encoding="utf-8"))
        if "diagnostics_limit" not in summary["unfinished_reasons"]:
            errors.append("缺少 diagnostics_limit 未完成原因")
    check("limit-diagnostics: 诊断条数上限", errors)

    # ------------------------------------------------------------------ #
    print("\n" + "=" * 72)
    failed = [name for name, ok, _d in RESULTS if not ok]
    print(f"验收场景 {len(RESULTS)} 项，失败 {len(failed)} 项")
    for name, ok, detail in RESULTS:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if failed:
        print("存在失败场景", file=sys.stderr)
        return 1
    print("全部通过。输出保留在:", workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
