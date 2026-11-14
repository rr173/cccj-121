#!/usr/bin/env bash
# 下游 HTTP 发送演示：真实签名收件 → 登记接收地址 → 受控接收器 → 发送工人。
# 全程本机环回；临时目录结束自动清理。完整断言验收见
#   python3 -I scripts/outbound_acceptance.py
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
DB="$WORK/source.db"
OUT="$WORK/receiver"
PORT="${PORT:-18092}"
CLI=(python3 -I "$REPO_ROOT/partner_webhook/cli.py"
     --config "$REPO_ROOT/config.example.json" --db "$DB")
NOW=2000000000

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  [[ -n "${RCV_PID:-}" ]] && kill "$RCV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

cat >"$WORK/plan.json" <<'JSON'
{"default": [{"kind": "ok"}],
 "events": {"acme/evt-429": [{"kind": "429", "retry_after": "5"}, {"kind": "ok"}],
            "acme/evt-400": [{"kind": "status", "status": 400}, {"kind": "ok"}]}}
JSON

echo ">>> 工作目录: $WORK"
"${CLI[@]}" init-db >/dev/null
"${CLI[@]}" serve --port "$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
python3 -I "$REPO_ROOT/partner_webhook/receiver.py" --port "$((PORT+1))" \
  --dir "$OUT" --plan "$WORK/plan.json" >"$WORK/receiver.log" 2>&1 &
RCV_PID=$!
sleep 1.2

echo
echo "=== 1. 真实签名收件制造积压（含空体/二进制/稀疏序号） ==="
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id evt-429 --sequence 9 --body '{"n":1}' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id evt-normal --sequence 2 --body '{"n":2}' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id evt-empty --sequence 5 --body-file /dev/null >/dev/null
printf '\x00\x01\xff\xfe二进制' >"$WORK/bin.body"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id evt-bin --sequence 1 --body-file "$WORK/bin.body" >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id evt-400 --sequence 3 --body '{"n":3}' >/dev/null
kill "$SRV_PID" 2>/dev/null || true; SRV_PID=""

echo
echo "=== 2. 登记固定接收地址（再次登记不同地址会被拒绝） ==="
"${CLI[@]}" outbox-endpoint --partner acme \
  --register "http://127.0.0.1:$((PORT+1))/ingest"
set +e
"${CLI[@]}" outbox-endpoint --partner acme \
  --register "http://127.0.0.1:$((PORT+1))/elsewhere" 2>&1 | tail -1
set -e

echo
echo "=== 3. 掷一轮：队首 429 进入退避，不发后续；提前运行无请求 ==="
"${CLI[@]}" outbox-run --partner acme --max-attempts 5 --now "$NOW" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["reports"][0];
print("retry_wait:", [(x["event_id"], x["http_status"], x["next_attempt_at"]) for x in r["retry_wait"]])'
"${CLI[@]}" outbox-run --partner acme --max-attempts 5 --now "$((NOW+4))" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["reports"][0];
print("early attempts:", r["attempts"], "blocked_by:", r["deferred_head"]["blocked_by"])'

echo
echo "=== 4. 到期后同键重送；随后 400 永久失败，需人工重试 ==="
"${CLI[@]}" outbox-run --partner acme --max-attempts 5 --now "$((NOW+5))" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["reports"][0];
print("delivered:", r["delivered"]); print("permanent:", [(x["event_id"], x["http_status"], x["reason"]) for x in r["permanent_failure"]])'
"${CLI[@]}" outbox-queue --partner acme | python3 -c \
  'import json,sys; d=json.load(sys.stdin);
print("queue:", [(q["event_id"], q["status"] or q["outbox_status"]) for q in d["queue"]])'
"${CLI[@]}" outbox-attempts --partner acme --event-id evt-429 | python3 -c \
  'import json,sys; d=json.load(sys.stdin);
print("evt-429 attempts:", [(a["outcome"], a["http_status"], a["attempt_no"]) for a in d["attempts"]])'

echo
echo "=== 5. 人工重试永久失败（保留此前尝试，轮次清零；接收器第二次回 ok） ==="
"${CLI[@]}" outbox-retry --partner acme --event-id evt-400 --operator demo \
  --now "$((NOW+6))" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("retry ->", d["status"], "attempt_no:", d["attempt_no"])'
"${CLI[@]}" outbox-run --partner acme --max-attempts 5 --now "$((NOW+6))" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["reports"][0];
print("after retry delivered:", r["delivered"])'
"${CLI[@]}" outbox-attempts --partner acme --event-id evt-400 | python3 -c \
  'import json,sys; d=json.load(sys.stdin);
print("attempts:", [(a["outcome"], a["http_status"]) for a in d["attempts"]],
      "operator_actions:", [a["action"] for a in d["operator_actions"]])'

echo
echo "=== 6. 接收器实际收到的字节与头部（逐字节核对） ==="
python3 - "$OUT" <<'PY'
import hashlib, json, sys
from pathlib import Path
out = Path(sys.argv[1])
for line in (out / "requests.jsonl").read_text().splitlines():
    entry = json.loads(line)
    if entry.get("event") != "completed":
        continue
    data = (out / entry["body_file"]).read_bytes()
    print(f'{entry["event_id"]:<12} bytes={len(data):<4} sha_ok='
          f'{hashlib.sha256(data).hexdigest() == entry["headers"]["X-Body-Sha256"]} '
          f'key={entry["headers"]["X-Delivery-Key"][:16]}...')
PY

echo
echo "=== 7. 旧 drain-outbox 已停用（不会虚报成功） ==="
set +e
"${CLI[@]}" drain-outbox 2>&1 | head -2
echo "exit=$?"
set -e

echo
echo ">>> 演示完成。本地状态与请求日志结构见 scripts/outbound_acceptance.py 输出"
