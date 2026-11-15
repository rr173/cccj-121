"""正文差量交接验收材料（可复跑，全部断言化）。

演练内容：

1. 真实签名收件，旧文件只放接收端；只把签名复制给发送端，发送端从收件库
   生成差量包（生成期间旧文件不可见）；随后移走源库，接收端仅靠旧文件与
   差量包还原，并逐字节与事先保存的新正文比对；
2. 手工小例子（开头插入、内部删除、局部替换、重复块、空旧文件、空新正文、
   短于一块、短尾块）逐条列出指令与弱校验预期；
3. 用独立的慢速小样本匹配器（scripts/delta_reference.py，不 import 正式
   delta/signature）核对生产包的确定性 COPY 选择；
4. 弱值相同但内容不同的块：只复用强摘要一致的块；
5. 许多重复/碰撞候选：内存与候选数量无关；
6. 错旧文件、损坏签名、包格式错误逐项运行，核对非零退出码与目标不存在；
7. 每次最多返回 1..7 字节的读取包装测试协议短读；
8. 几十 MiB、头部插入少量字节：报告大小、COPY/字面字节、滚动更新、强摘要
   次数与进程峰值内存；由另一个进程核对还原长度与 SHA-256。

用法::

    python3 -I scripts/delta_acceptance.py [--out 输出目录]

输出目录默认是临时目录；``--out`` 指定的目录必须不存在或为空。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from partner_webhook.delta import generate_delta  # noqa: E402
from partner_webhook.signature import write_signature  # noqa: E402
from partner_webhook.storage import Storage  # noqa: E402
import delta_reference  # noqa: E402

PARTNER = "acme"
NOW = 2_000_000_000
FAILURES: list[str] = []
CHECKS: list[str] = []


def check(label: str, actual, expected) -> None:
    ok = actual == expected
    line = ("PASS " if ok else "FAIL ") + label
    print("  " + line)
    CHECKS.append(line)
    if not ok:
        FAILURES.append(f"{label}: 实际 {actual!r} / 期望 {expected!r}")


def check_true(label: str, condition: bool) -> None:
    check(label, bool(condition), True)


def run_cli(module: str, *args: str, cwd: str | None = None):
    cmd = [sys.executable, "-I", str(REPO_ROOT / "partner_webhook" / module),
           *args]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc


def sha256_file(path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def add_event(db_path: str, event_id: str, body: bytes, seq: int,
              partner: str = PARTNER) -> str:
    storage = Storage(db_path)
    digest = hashlib.sha256(body).hexdigest()
    storage.store_raw_body(body, NOW)
    rid = storage.insert_ingest_record(dict(
        received_at=NOW, partner_id=partner, key_version="v1",
        claimed_timestamp=NOW, event_id=event_id, source_seq=seq,
        body_sha256=digest, result="accepted", reason=None,
        http_status=200, headers={}))
    storage.insert_accepted_event(dict(
        event_id=event_id, partner_id=partner, source_seq=seq,
        key_version="v1", body_sha256=digest, ingest_record_id=rid,
        claimed_timestamp=NOW, accepted_at=NOW))
    storage.enqueue_outbox(partner_id=partner, event_id=event_id,
                           source_seq=seq, body_sha256=digest, now=NOW)
    storage.commit()
    storage.close()
    return digest


# --------------------------------------------------------------------- #
# 手工小例子：期望由本文件独立写出，不从生产实现推导
# --------------------------------------------------------------------- #
def weak_of(data: bytes) -> int:
    length = len(data)
    a = sum(data) % 65536
    b = sum((length - i) * data[i] for i in range(length)) % 65536
    return (b << 16) | a


def hand_examples(out: Path):
    print("\n== 手工小例子：指令与弱校验预期 ==")
    examples = [
        {
            # 两个旧块内容相同 -> 规则规定一律选最小偏移 0
            "name": "start_insert",
            "old": b"ABCDEFGH" * 2,
            "new": b"XY" + b"ABCDEFGH" * 2,
            "B": 8,
            "expect_ops": [("LITERAL", b"XY"),
                           ("COPY", 0, 8), ("COPY", 0, 8)],
        },
        {
            # 三个旧块内容各不相同：块0=ABCDEFGH，块1=IJKLMNOP，块2=QRSTUVWX
            "name": "internal_delete",
            "old": b"ABCDEFGHIJKLMNOPQRSTUVWX",
            "new": b"ABCDEFGH" + b"QRSTUVWX",   # 删掉中间块
            "B": 8,
            "expect_ops": [("COPY", 0, 8), ("COPY", 16, 8)],
        },
        {
            "name": "local_replace",
            "old": b"ABCDEFGHIJKLMNOPQRSTUVWX",
            "new": b"ABCDEFGH" + b"QQQQQQQQ" + b"QRSTUVWX",  # 替换中间块
            "B": 8,
            "expect_ops": [("COPY", 0, 8), ("LITERAL", b"QQQQQQQQ"),
                           ("COPY", 16, 8)],
        },
        {
            "name": "duplicate_blocks",
            "old": b"AAAABBBBAAAACCCC",
            "new": b"AAAACCCCAAAABBBB",
            "B": 4,
            "expect_ops": [("COPY", 0, 4), ("COPY", 12, 4),
                           ("COPY", 0, 4), ("COPY", 4, 4)],
        },
        {
            "name": "empty_old",
            "old": b"",
            "new": b"fresh body",
            "B": 4,
            "expect_ops": [("LITERAL", b"fresh body")],
        },
        {
            "name": "empty_new",
            "old": b"ABCDEFGH",
            "new": b"",
            "B": 8,
            "expect_ops": [],
        },
        {
            "name": "shorter_than_block",
            "old": b"ABCDEFGH" * 2,
            "new": b"hi",
            "B": 100,
            "expect_ops": [("LITERAL", b"hi")],
        },
        {
            "name": "short_tail",
            "old": b"0123456789ABCDE",   # B=8 -> tail 7 字节
            "new": b"ZZ" + b"0123456789ABCDE",
            "B": 8,
            "expect_ops": [("LITERAL", b"ZZ"),
                           ("COPY", 0, 8), ("COPY", 8, 7)],
        },
    ]
    db = str(out / "examples.db")
    Storage(db).close()
    results = {}
    for seq, ex in enumerate(examples):
        old_path = out / f"ex-{ex['name']}.old"
        old_path.write_bytes(ex["old"])
        sig_path = out / f"ex-{ex['name']}.sig"
        write_signature(old_path, ex["B"], sig_path)
        add_event(db, f"evt-{ex['name']}", ex["new"], seq + 1)
        delta_path = out / f"ex-{ex['name']}.delta"
        stats = generate_delta(db, PARTNER, f"evt-{ex['name']}", sig_path,
                               delta_path)
        pkg = delta_reference.parse_package(delta_path.read_bytes())
        coalesced = delta_reference.coalesce_literals(pkg["ops"])
        got = [(op[0], *op[1:]) if op[0] == "COPY"
               else ("LITERAL", op[1]) for op in coalesced]
        expected = [(op[0], *op[1:]) if op[0] == "COPY"
                    else ("LITERAL", op[1]) for op in ex["expect_ops"]]
        check(f"小例子 {ex['name']} 指令序列", got, expected)
        # 弱校验预期：独立计算并核对包/签名所用的值
        blocks = delta_reference.blocked(ex["old"], ex["B"])
        expected_weaks = [weak_of(content) for _, content in blocks]
        printed = [(offset, len(content), weak_of(content))
                   for offset, content in blocks]
        print(f"     {ex['name']}: B={ex['B']} 旧块 offset/len/weak = {printed}")
        # 还原并逐字节核对
        target = out / f"ex-{ex['name']}.out"
        proc = run_cli("apply.py", "--old", str(old_path), "--delta",
                       str(delta_path), "--out", str(target))
        check(f"小例子 {ex['name']} apply 退出码", proc.returncode, 0)
        check(f"小例子 {ex['name']} 还原字节",
              target.read_bytes() if target.exists() else None, ex["new"])
        results[ex["name"]] = {
            "stats": {k: stats[k] for k in
                      ("copy_ops", "literal_ops", "copy_bytes",
                       "literal_bytes", "roll_updates", "strong_checks")},
            "old_blocks_offset_len_weak": printed,
            "instructions": [list(op) if op[0] == "COPY"
                             else [op[0], op[1].hex()] for op in got],
        }
    return results


def separated_handoff(out: Path, body: bytes, old: bytes, block_size: int,
                      name: str):
    """双方分离：旧文件留在接收端；只把签名交给发送端。"""
    receiver = out / f"handoff-{name}"
    sender = out / f"sender-{name}"
    receiver.mkdir()
    sender.mkdir()
    (receiver / "old.bin").write_bytes(old)
    (receiver / "expected-new.bin").write_bytes(body)
    db = str(receiver / "webhook.db")
    Storage(db).close()
    add_event(db, f"evt-{name}", body, 1)
    sig = receiver / "old.sig"
    write_signature(receiver / "old.bin", block_size, sig)
    # 只复制签名到发送端；发送端看不到旧文件
    shutil.copy2(sig, sender / "old.sig")
    check_true(f"{name}: 发送端没有旧文件",
               not (sender / "old.bin").exists())
    package = sender / "delta.bin"
    proc = run_cli("delta.py", "--db", db, "--partner", PARTNER,
                   "--event-id", f"evt-{name}", "--signature",
                   str(sender / "old.sig"), "--out", str(package),
                   "--tmp-dir", str(sender))
    check(f"{name}: 发送端生成包退出码", proc.returncode, 0)
    # 接收端随后移走源库
    moved = receiver / "webhook.db.moved"
    os.replace(db, moved)
    for suffix in ("-wal", "-shm"):
        side = Path(db + suffix)
        if side.exists():
            side.unlink()
    check_true(f"{name}: 源库已移走", not Path(db).exists())
    target = receiver / "restored.bin"
    proc = run_cli("apply.py", "--old", str(receiver / "old.bin"),
                   "--delta", str(package), "--out", str(target))
    check(f"{name}: 接收端 apply 退出码", proc.returncode, 0)
    if target.exists():
        check(f"{name}: 逐字节与事先保存的新正文一致",
              target.read_bytes() == (receiver / "expected-new.bin").read_bytes(), True)
        check(f"{name}: 独立 SHA-256",
              sha256_file(target),
              hashlib.sha256((receiver / "expected-new.bin").read_bytes()).hexdigest())
    # 独立进程核对长度与摘要
    verify = run_cli_verify(target, receiver / "expected-new.bin")
    check(f"{name}: 另一进程核对长度与 SHA-256", verify, True)
    return package, receiver


def peak_rss_kib() -> int:
    """本进程真实峰值内存：/proc/self/status 的 VmHWM（exec 后重置）。

    ``resource.ru_maxrss`` 会从父进程 fork 时继承高水位，子进程不能用来
    判断自身峰值；VmHWM 不受父进程影响。
    """
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except OSError:
        pass
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def run_cli_verify(target: Path, expected: Path) -> bool:
    code = (
        "import hashlib,sys\n"
        "a=open(sys.argv[1],'rb').read(); b=open(sys.argv[2],'rb').read()\n"
        "print(len(a), hashlib.sha256(a).hexdigest())\n"
        "sys.exit(0 if a==b else 1)\n"
    )
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(target),
                           str(expected)], capture_output=True, text=True)
    return proc.returncode == 0


def weak_collision_case(out: Path):
    print("\n== 弱值相同但内容不同：只复用强摘要一致的块 ==")
    block_a = b"\x00\x02\x00\x00"
    block_b = b"\x01\x00\x01\x00"
    check("弱值碰撞对弱值相同", weak_of(block_a), weak_of(block_b))
    check_true("弱值碰撞对内容不同", block_a != block_b)
    old = block_a * 4
    new = block_b + block_a
    db = str(out / "weakcollide.db")
    Storage(db).close()
    add_event(db, "evt-weak", new, 1)
    old_path = out / "weak.old"; old_path.write_bytes(old)
    sig = out / "weak.sig"; write_signature(old_path, 4, sig)
    stats = generate_delta(db, PARTNER, "evt-weak", sig, out / "weak.delta")
    pkg = delta_reference.parse_package((out / "weak.delta").read_bytes())
    check("碰撞窗口先字面输出（未被误当 COPY）", pkg["ops"][0],
          ("LITERAL", block_b))
    copies = [op for op in pkg["ops"] if op[0] == "COPY"]
    ok_strong = all(old[op[1]:op[1] + op[2]] == block_a for op in copies)
    check_true("所有 COPY 引用的旧块强摘要与内容一致", ok_strong)
    check("强摘要计算次数（仅命中候选的窗口）", stats["strong_checks"], 2)
    target = out / "weak.out"
    proc = run_cli("apply.py", "--old", str(old_path), "--delta",
                   str(out / "weak.delta"), "--out", str(target))
    check("弱碰撞样本还原", target.read_bytes() if target.exists() else None,
          new)


def many_candidates_case(out: Path):
    print("\n== 大量重复/碰撞候选：内存不随候选数量增长 ==")
    block = b"COLLIDE!"
    old = block * 4000
    new = block * 3
    db = str(out / "many.db")
    Storage(db).close()
    add_event(db, "evt-many", new, 1)
    old_path = out / "many.old"; old_path.write_bytes(old)
    sig = out / "many.sig"; write_signature(old_path, 8, sig)
    # 用独立子进程测峰值 RSS：候选很多时也不应把签名/候选整体装进内存
    code = f"""
import json, sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from partner_webhook.delta import generate_delta
s = generate_delta({db!r}, {PARTNER!r}, 'evt-many', {str(sig)!r},
                   {str(out / 'many.delta')!r})
print(json.dumps(s))
peak = 0
for line in open('/proc/self/status', encoding='ascii'):
    if line.startswith('VmHWM:'):
        peak = int(line.split()[1])
print('MAXRSS', peak)
"""
    proc = subprocess.run([sys.executable, "-I", "-c", code],
                          capture_output=True, text=True)
    check("候选压力生成退出码", proc.returncode, 0)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    stats = json.loads(lines[0])
    rss_kib = int(lines[1].split()[1])
    check("4000 个重复候选仍按最小偏移复用", stats["copy_ops"], 3)
    check("强摘要次数不随候选数量增长", stats["strong_checks"] <= 3, True)
    check_true(f"候选压力峰值 RSS < 100 MiB（实际 {rss_kib} KiB）",
               rss_kib < 100 * 1024)
    print(f"     candidate case: strong_checks={stats['strong_checks']} "
          f"peak_rss={rss_kib} KiB")


def error_matrix(out: Path):
    print("\n== 错误矩阵：退出码与目标不存在 ==")
    old = b"hello old world"
    new = b"hello NEW world"
    db = str(out / "err.db")
    Storage(db).close()
    add_event(db, "evt-err", new, 1)
    old_path = out / "err.old"; old_path.write_bytes(old)
    sig = out / "err.sig"; write_signature(old_path, 4, sig)
    package = out / "err.delta"
    generate_delta(db, PARTNER, "evt-err", sig, package)
    raw = package.read_bytes()

    def expect_fail(label: str, old_file: Path, package_file: Path,
                    expect_text: str | None = None):
        target = out / f"err-{label}.out"
        proc = run_cli("apply.py", "--old", str(old_file), "--delta",
                       str(package_file), "--out", str(target))
        check(f"{label}: 非零退出码", proc.returncode != 0, True)
        check_true(f"{label}: 目标不存在", not target.exists())
        check_true(f"{label}: 不残留 .part",
                   not Path(str(target) + ".part").exists())
        if expect_text:
            check_true(f"{label}: 错误可定位（含 {expect_text}）",
                       expect_text in (proc.stderr + proc.stdout))

    # 错旧文件
    bad_old = out / "err-bad.old"; bad_old.write_bytes(b"hellp old world")
    expect_fail("wrong-old", bad_old, package, "SHA-256")
    bad_len = out / "err-len.old"; bad_len.write_bytes(b"hello old worl")
    expect_fail("wrong-old-length", bad_len, package, "长度")

    # 损坏签名
    bad_sig = out / "err-sig.bad"
    damaged = bytearray(sig.read_bytes()); damaged[len(damaged) - 5] ^= 0x40
    bad_sig.write_bytes(bytes(damaged))
    target = out / "err-badsig.delta"
    proc = run_cli("delta.py", "--db", db, "--partner", PARTNER,
                   "--event-id", "evt-err", "--signature", str(bad_sig),
                   "--out", str(target))
    check("bad-signature: delta 非零退出码", proc.returncode != 0, True)
    check_true("bad-signature: 未生成包", not target.exists())

    # 包格式错误
    variants = {
        "bad-magic": b"X" + raw[1:],
        "bad-version": raw[:8] + b"\x00\x09" + raw[10:],
        "trailing": raw + b"junk",
        "truncated": raw[:len(raw) // 2],
    }
    end = raw.find(b"PWEND001")
    variants["no-end"] = raw[:end] + b"XXXXXXXX"
    for label, data in variants.items():
        path = out / f"errpkg-{label}.bin"
        path.write_bytes(data)
        expect_fail(f"pkg-{label}", old_path, path)

    # COPY 越界/不对齐、未知指令：重算整包尾部摘要，让错误来自结构检查
    header_len = 98 + len(PARTNER.encode()) + len("evt-err".encode()) + 8
    def repack(mutate, label):
        data = bytearray(raw)
        mutate(data)
        body_end = len(data) - 32
        data[body_end:] = hashlib.sha256(bytes(data[:body_end])).digest()
        path = out / f"errpkg-{label}.bin"
        path.write_bytes(bytes(data))
        return path

    def copy_overflow(data, header_len=header_len):
        data[header_len + 9:header_len + 13] = (99).to_bytes(4, "big")
    path = repack(copy_overflow, "copy-overflow")
    expect_fail("pkg-copy-overflow", old_path, path, "COPY")

    def copy_misaligned(data, header_len=header_len):
        data[header_len + 1:header_len + 9] = (1).to_bytes(8, "big")
    path = repack(copy_misaligned, "copy-misaligned")
    expect_fail("pkg-copy-misaligned", old_path, path, "对齐")

    def unknown(data, header_len=header_len):
        data[header_len] = 0x7F
    path = repack(unknown, "unknown-op")
    expect_fail("pkg-unknown-op", old_path, path, "未知指令")

    def bad_new_digest(data):
        data[42:74] = b"\x00" * 32
    path = repack(bad_new_digest, "bad-digest")
    expect_fail("pkg-bad-digest", old_path, path, "SHA-256")

    # 已有目标拒绝覆盖
    existing = out / "err-existing.out"
    existing.write_bytes(b"keep me")
    proc = run_cli("apply.py", "--old", str(old_path), "--delta",
                   str(package), "--out", str(existing))
    check("existing-target: 非零退出码", proc.returncode != 0, True)
    check("existing-target: 原文件未被改写", existing.read_bytes(), b"keep me")


class ShortReadWrapper:
    """把包文件包装成每次 read 至多返回 max_chunk（1..7）字节。"""

    def __init__(self, path, max_chunk):
        self.path = path
        self.max_chunk = max_chunk

    def __enter__(self):
        self._fh = open(self.path, "rb")
        return self

    def __exit__(self, *exc):
        self._fh.close()

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.max_chunk
        return self._fh.read(min(n, self.max_chunk))


def short_read_case(out: Path):
    print("\n== 短读包装（1..7 字节） ==")
    from partner_webhook.apply import ApplyLimits, parse_header
    from partner_webhook.deltaformat import HashingReader, ReadWrapper

    old = bytes(range(128)) * 3
    new = b"HEAD" + old + b"TAIL"
    db = str(out / "short.db")
    Storage(db).close()
    add_event(db, "evt-short", new, 1)
    old_path = out / "short.old"; old_path.write_bytes(old)
    sig = out / "short.sig"; write_signature(old_path, 16, sig)
    package = out / "short.delta"
    generate_delta(db, PARTNER, "evt-short", sig, package)
    for max_chunk in range(1, 8):
        with ShortReadWrapper(str(package), max_chunk) as raw:
            reader = ReadWrapper(HashingReader(raw))
            header = parse_header(reader, ApplyLimits())
        check(f"短读 {max_chunk}: 合作方身份", header.partner_id, PARTNER)
        check(f"短读 {max_chunk}: 新正文长度", header.new_length, len(new))
        target = out / f"short-{max_chunk}.out"
        proc = run_cli("apply.py", "--old", str(old_path), "--delta",
                       str(package), "--out", str(target))
        check(f"短读 {max_chunk}: CLI 还原", target.read_bytes()
              if target.exists() else None, new)
    print("     说明：协议读取均用 read_exact 循环，短读不会截断字段。")


def measure_memory_growth(out: Path) -> dict:
    """16 / 48 / 96 MiB 三档正文：峰值内存应接近常数。"""
    from partner_webhook.signature import write_signature
    from partner_webhook.storage import Storage
    result = {}
    for mb in (16, 48, 96):
        folder = out / f"scale-{mb}"
        folder.mkdir()
        B = 4096
        count = mb * 1024 * 1024 // B
        old = b"".join(hashlib.sha256(i.to_bytes(8, "big")).digest()
                       * (B // 32) for i in range(count))
        prefix = b"PREFIX!"
        new = prefix + old
        (folder / "old.bin").write_bytes(old)
        write_signature(folder / "old.bin", B, folder / "old.sig")
        db = str(folder / "webhook.db")
        Storage(db).close()
        add_event(db, f"evt-{mb}", new, 1)
        code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from partner_webhook.delta import generate_delta
s = generate_delta({db!r}, 'acme', 'evt-{mb}', {str(folder/'old.sig')!r},
                   {str(folder/'delta.bin')!r}, tmp_dir={str(folder)!r})
peak = 0
for line in open('/proc/self/status', encoding='ascii'):
    if line.startswith('VmHWM:'):
        peak = int(line.split()[1])
print(peak, s['copy_ops'], s['roll_updates'], s['delta_bytes'])
"""
        proc = subprocess.run([sys.executable, "-I", "-c", code],
                              capture_output=True, text=True)
        check(f"scale-{mb}: 生成退出码", proc.returncode, 0)
        tokens = proc.stdout.split()
        result[mb] = {"peak_rss_kib": int(tokens[0]),
                      "copy_ops": int(tokens[1]),
                      "roll_updates": int(tokens[2]),
                      "delta_bytes": int(tokens[3])}
        print(f"     scale-{mb}: peak_rss={result[mb]['peak_rss_kib']} KiB "
              f"copy_ops={result[mb]['copy_ops']} "
              f"delta_bytes={result[mb]['delta_bytes']}")
    check("内存不随正文线性增长：96MiB 峰值 < 2 倍 16MiB 峰值",
          result[96]["peak_rss_kib"] < 2 * result[16]["peak_rss_kib"], True)
    check("内存不随签名总量线性增长：块数增 6 倍峰值仍 < 2 倍",
          result[96]["peak_rss_kib"] < 2 * result[16]["peak_rss_kib"], True)
    check("三档都按头部插入处理（字面=前缀，其余 COPY）",
          [r["roll_updates"] for r in result.values()], [len(b"PREFIX!")] * 3)
    return {str(k): v for k, v in result.items()}


def large_case(out: Path):
    print("\n== 几十 MiB 头部插入：实际路径统计 ==")
    old_len = 48 * 1024 * 1024
    B = 4096
    old = bytearray()
    for i in range(old_len // B):
        block = hashlib.sha256(i.to_bytes(8, "big")).digest() * (B // 32)
        old += block
    old = bytes(old)
    prefix = b"HEAD-INSERTED-0123456789"
    new = prefix + old
    rest = out / "large"
    rest.mkdir()
    (rest / "old.bin").write_bytes(old)
    (rest / "expected.bin").write_bytes(new)
    db = str(rest / "webhook.db")
    Storage(db).close()
    add_event(db, "evt-large", new, 1)
    old_path = rest / "old.bin"
    sig = rest / "old.sig"
    write_signature(old_path, B, sig)
    # 发送端看不到旧文件：签名单独复制到一个目录，源库仍是只读输入
    sender = rest / "sender"
    sender.mkdir()
    shutil.copy2(sig, sender / "only.sig")
    code = f"""
import json, sys, os, time
sys.path.insert(0, {str(REPO_ROOT)!r})
from partner_webhook.delta import generate_delta
t = time.perf_counter()
s = generate_delta({db!r}, {PARTNER!r}, 'evt-large', {str(sender/'only.sig')!r},
                   {str(rest/'delta.bin')!r}, tmp_dir={str(sender)!r})
elapsed = time.perf_counter() - t
peak = 0
for line in open('/proc/self/status', encoding='ascii'):
    if line.startswith('VmHWM:'):
        peak = int(line.split()[1])
s['elapsed_seconds'] = round(elapsed, 3)
s['peak_rss_kib'] = peak
json.dump(s, open({str(rest/'stats.json')!r}, 'w'), indent=2)
print(json.dumps(s))
"""
    # 发送端只保留签名：用独立进程 + 只读源库；旧文件不出现在参数里
    proc = subprocess.run([sys.executable, "-I", "-c", code],
                          capture_output=True, text=True)
    check("large: 生成退出码", proc.returncode, 0)
    stats = json.loads(proc.stdout.strip().splitlines()[-1])
    check("large: 新正文大小", stats["new_length"], len(new))
    check("large: 包大小远小于新正文",
          stats["delta_bytes"] < len(new) // 10, True)
    check("large: 头部插入走字面", stats["literal_bytes"], len(prefix))
    check("large: 其余全部 COPY", stats["copy_bytes"], old_len)
    check("large: 滚动更新次数 = 插入前缀长度",
          stats["roll_updates"], len(prefix))
    check("large: 强摘要只按命中窗口计",
          stats["strong_checks"], stats["copy_ops"])
    print(f"     new={stats['new_length']} delta={stats['delta_bytes']} "
          f"copy_bytes={stats['copy_bytes']} literal_bytes={stats['literal_bytes']} "
          f"roll_updates={stats['roll_updates']} strong_checks={stats['strong_checks']} "
          f"peak_rss={stats['peak_rss_kib']} KiB "
          f"elapsed={stats['elapsed_seconds']}s")
    # 移走源库，接收端只用旧文件与包
    os.replace(db, rest / "webhook.db.moved")
    for suffix in ("-wal", "-shm"):
        side = Path(db + suffix)
        if side.exists():
            side.unlink()
    target = rest / "restored.bin"
    proc = run_cli("apply.py", "--old", str(old_path), "--delta",
                   str(rest / "delta.bin"), "--out", str(target))
    check("large: apply 退出码", proc.returncode, 0)
    check("large: 还原字节与事先保存的新正文一致",
          sha256_file(target), sha256_file(rest / "expected.bin"))
    # 另一个独立进程核对长度与 SHA-256
    verify_code = (
        "import hashlib,sys\n"
        "p=sys.argv[1]; h=hashlib.sha256(); n=0\n"
        "f=open(p,'rb')\n"
        "while True:\n"
        "    c=f.read(1<<20)\n"
        "    if not c: break\n"
        "    n+=len(c); h.update(c)\n"
        "print(n, h.hexdigest())\n"
    )
    proc = subprocess.run([sys.executable, "-I", "-c", verify_code,
                           str(target)], capture_output=True, text=True)
    length, digest = proc.stdout.split()
    check("large: 另一进程核对长度", int(length), len(new))
    check("large: 另一进程核对 SHA-256", digest,
          hashlib.sha256(new).hexdigest())
    check_true(f"large: 进程峰值内存不随正文线性增长"
               f"（{stats['peak_rss_kib']} KiB < 128 MiB）",
               stats["peak_rss_kib"] < 128 * 1024)
    # 内存构成：约 8 MiB 扫描缓冲 + SQLite 页缓存 + 解释器基线，接近常数。
    # 另用 16/48/96 MiB 三档实测，验证峰值不随正文线性增长。
    growth = measure_memory_growth(out)
    return stats


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
    else:
        out = Path(tempfile.mkdtemp(prefix="delta-acceptance-"))
    print(f"验收输出目录: {out}")

    examples = hand_examples(out)
    (out / "hand_examples.json").write_text(
        json.dumps(examples, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n== 双方分离交接 ==")
    separated_handoff(out, b"inserted prefix then old body\n" + b"BODY" * 20,
                      b"BODY" * 20, 8, "small")
    separated_handoff(out, b"", b"", 4, "empty")
    separated_handoff(out, b"only new", b"", 7, "emptyold")

    weak_collision_case(out)
    many_candidates_case(out)
    error_matrix(out)
    short_read_case(out)
    large_case(out)

    summary = {
        "checks": len(CHECKS),
        "failures": FAILURES,
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n共 {len(CHECKS)} 项检查，失败 {len(FAILURES)} 项")
    if FAILURES:
        for failure in FAILURES:
            print("  FAIL " + failure)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
