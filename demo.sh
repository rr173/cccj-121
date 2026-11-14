#!/usr/bin/env bash
# 端到端演示：本地环回启动收件服务，用请求生成器覆盖全部关键场景。
# 全程不连接真实外网；数据写入独立临时目录，结束后自动清理。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
DB="$WORK/demo.db"
PORT="${PORT:-18090}"
CLI=(python3 -I "$REPO_ROOT/partner_webhook/cli.py"
     --config "$REPO_ROOT/config.example.json" --db "$DB")

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo ">>> 工作目录: $WORK"
"${CLI[@]}" init-db
"${CLI[@]}" serve --port "$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1.2

section() { echo; echo "=== $* ==="; }

section "1. 正常事件（含乱序 seq 3 -> 1 -> 2，保留源序号）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-100 --sequence 3 --body '{"order":100}'
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-101 --sequence 1 --body '{"order":101}'
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-102 --sequence 2 --body '{"order":102}'

section "2. 新旧密钥交接（重叠窗口内 v2 同样合法，在途请求不丢）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v2 --event-id evt-103 --sequence 4 --body '{"order":103}'

section "3. 网络超时重投（同 ID 同载荷 -> 幂等 duplicate，不重复入下游）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-100 --sequence 3 --body '{"order":100}'

section "4. 同 ID 不同载荷（冲突隔离 409，原事件不被覆盖）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-100 --sequence 3 --body '{"order":999}'

section "5. 错误签名（401 拒绝并记录原因）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-200 --sequence 9 --body '{"x":1}' --badge

section "6. 超出时间窗（401，过期签名不能重新进入）"
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme \
  --key-version v1 --event-id evt-201 --sequence 9 --body '{"x":2}' \
  --ts-offset 99999

section "7. 查询：按合作方的接收流水（结果与拒绝原因）"
"${CLI[@]}" query --partner acme | python3 -c \
  'import json,sys; print([(r["id"], r["result"], r["reason"]) for r in json.load(sys.stdin)])'

section "8. 查询：已接受事件按源序号排序（乱序归位）"
"${CLI[@]}" events --partner acme | python3 -c \
  'import json,sys; print([(e["event_id"], e["source_seq"]) for e in json.load(sys.stdin)])'

section "9. 导出可重放的原始字节体（按记录 ID）"
"${CLI[@]}" body 1 --output "$WORK/body1.bin"
cat "$WORK/body1.bin"; echo

section "10. outbox 按源序号顺序投递到下游"
"${CLI[@]}" drain-outbox | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print("delivered seq:", [x["source_seq"] for x in d["delivered"]])'

section "11. 汇总统计"
"${CLI[@]}" stats

echo; echo ">>> 演示完成，临时目录已清理: $WORK"
