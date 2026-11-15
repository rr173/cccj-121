#!/usr/bin/env bash
# 可验证追加账本演示：真实签名收件 → 安装账本 → 检查点 → 在账/一致性证明
# → 离线核验 → 移走数据库后独立核验。全程离线，临时目录结束自动清理。
# 完整可复跑断言：python3 -I scripts/prooflog_acceptance.py
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
DB="$WORK/demo.db"
PORT="${PORT:-18094}"
CLI=(python3 -I "$REPO_ROOT/partner_webhook/cli.py"
     --config "$REPO_ROOT/config.example.json" --db "$DB")
VERIFY=(python3 -I "$REPO_ROOT/partner_webhook/verifylog.py")

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo ">>> 工作目录: $WORK"
"${CLI[@]}" init-db >/dev/null

# ---- 1. 先收 3 条旧事件，再安装账本（纳入历史） ----
"${CLI[@]}" serve --port "$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1.2

section() { echo; echo "=== $* ==="; }

section "1. 安装前的历史事件（source_seq 故意乱序）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id hist-3 --sequence 30 --body '{"n":3}' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id hist-1 --sequence 10 --body '{"n":1}' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id hist-2 --sequence 20 --body '{"n":2}' >/dev/null
"${CLI[@]}" events --partner acme | python3 -c \
  'import json,sys; print([(e["event_id"], e["source_seq"]) for e in json.load(sys.stdin)])'

section "2. 安装账本（按 ingest_record_id 纳入已有事件）"
"${CLI[@]}" log-install --partner acme | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print({k:d[k] for k in ("log_id","tree_size","root_hash","already_installed")})'

section "3. 继续真实收件，在第 5 条后保存检查点"
for i in 4 5 6 7; do
  "${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
    --key-version v1 --event-id "evt-$i" --sequence "$((i*10))" \
    --body "{\"n\":$i}" >/dev/null
done
"${CLI[@]}" log-checkpoint --partner acme --tree-size 5 --out "$WORK/cp-05.json" 2>/dev/null
"${CLI[@]}" log-checkpoint --partner acme --out "$WORK/cp-07.json" 2>/dev/null
kill "$SRV_PID" 2>/dev/null || true; SRV_PID=""
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
for name in ("cp-05.json", "cp-07.json"):
    doc = json.loads((work / name).read_text())
    print(f'{name}: tree_size={doc["tree_size"]} root={doc["root_hash"][:16]}...')
PY

section "4. 为首/中/尾事件生成在账证明（旧前缀 tree_size=5）"
for event in hist-3 evt-4 evt-5; do
  "${CLI[@]}" log-prove-inclusion --partner acme --event-id "$event" \
    --tree-size 5 --out "$WORK/inclusion-$event.json" 2>/dev/null
  python3 - "$WORK" "$event" <<'PY'
import json, sys
from pathlib import Path
work, event = Path(sys.argv[1]), sys.argv[2]
doc = json.loads((work / f"inclusion-{event}.json").read_text())
print(f'{event}: leaf_index={doc["leaf_index"]} path_nodes={len(doc["path"])} '
      f'source_seq={doc["source_seq"]}')
PY
done

section "5. 为 5 -> 7 生成前后追加关系证明"
"${CLI[@]}" log-prove-consistency --partner acme \
  --old-checkpoint "$WORK/cp-05.json" --new-checkpoint "$WORK/cp-07.json" \
  --out "$WORK/consistency-5-7.json" 2>/dev/null
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
doc = json.loads((Path(sys.argv[1]) / "consistency-5-7.json").read_text())
print(f'old={doc["old_size"]} new={doc["new_size"]} '
      f'path_nodes={len(doc["path"])}')
PY

section "6. 离线核验（不访问数据库）"
BODY_SHA=$(python3 - "$DB" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(conn.execute("SELECT body_sha256 FROM accepted_events"
                   " WHERE event_id='evt-4'").fetchone()[0])
PY
)
"${VERIFY[@]}" inclusion --checkpoint "$WORK/cp-05.json" \
  --proof "$WORK/inclusion-evt-4.json" --event-id evt-4 --source-seq 40 \
  --body-sha256 "$BODY_SHA"
"${VERIFY[@]}" consistency --old-checkpoint "$WORK/cp-05.json" \
  --new-checkpoint "$WORK/cp-07.json" --proof "$WORK/consistency-5-7.json"

section "7. 篡改证明：离线核验必须失败（非零退出码）"
python3 - "$WORK" <<'PY'
import json, sys
from pathlib import Path
work = Path(sys.argv[1])
doc = json.loads((work / "inclusion-evt-4.json").read_text())
doc["path"][0] = ("f" if doc["path"][0][0] != "f" else "0") + doc["path"][0][1:]
(work / "inclusion-tampered.json").write_text(json.dumps(doc))
PY
set +e
"${VERIFY[@]}" inclusion --checkpoint "$WORK/cp-05.json" \
  --proof "$WORK/inclusion-tampered.json" --event-id evt-4 --source-seq 40 \
  --body-sha256 "$BODY_SHA" 2>"$WORK/tamper.err"
CODE=$?
set -e
echo "exit=$CODE stderr=$(cat "$WORK/tamper.err")"

section "8. 移走数据库后，保存的检查点与证明仍可独立核验"
mv "$DB" "$DB.hidden"
"${VERIFY[@]}" inclusion --checkpoint "$WORK/cp-05.json" \
  --proof "$WORK/inclusion-evt-4.json" --event-id evt-4 --source-seq 40 \
  --body-sha256 "$BODY_SHA"
"${VERIFY[@]}" consistency --old-checkpoint "$WORK/cp-05.json" \
  --new-checkpoint "$WORK/cp-07.json" --proof "$WORK/consistency-5-7.json"
mv "$DB.hidden" "$DB"

section "9. 重复安装不换号；账本状态"
"${CLI[@]}" log-install --partner acme | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("reinstall:", {"log_id":d["log_id"], "tree_size":d["tree_size"], "already_installed":d["already_installed"]})'
"${CLI[@]}" log-status --partner acme

echo
echo ">>> 演示完成。完整断言：python3 -I scripts/prooflog_acceptance.py --bulk 20000"
