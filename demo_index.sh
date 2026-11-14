#!/usr/bin/env bash
# 正文索引演示：本地环回真实收件 → 命令行建索引 → 组合条件查询。
# 全程离线；临时目录结束自动清理。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
DB="$WORK/source.db"
INDEX="$WORK/analysis-index.db"
PORT="${PORT:-18091}"
CLI=(python3 -I "$REPO_ROOT/partner_webhook/cli.py"
     --config "$REPO_ROOT/config.example.json" --db "$DB")
Q=(python3 -I "$REPO_ROOT/partner_webhook/cli.py"
   --config "$REPO_ROOT/config.example.json" --db "$DB"
   index-query --index-db "$INDEX")

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

show() { python3 -c 'import json,sys; d=json.load(sys.stdin); print("total=%d events=%s" % (d["total"], [e["event_id"] for e in d["events"]]))'; }

echo ">>> 工作目录: $WORK"
"${CLI[@]}" init-db >/dev/null
"${CLI[@]}" serve --port "$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1.2

echo
echo "=== 1. 真实收件（同一事件内的测量数组） ==="
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id t20-h80 --sequence 1 \
  --body '{"measurements":[{"metric":"temperature","value":20},{"metric":"humidity","value":80}]}' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id t35 --sequence 2 \
  --body '{"measurements":[{"metric":"temperature","value":35},{"metric":"humidity","value":10}]}' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner acme --key-version v1 \
  --event-id plain-text --sequence 3 --body 'not json at all' >/dev/null
"${CLI[@]}" send --url "http://127.0.0.1:$PORT" --partner globex --key-version g1 \
  --event-id g-t35 --sequence 1 \
  --body '{"measurements":[{"metric":"temperature","value":35}]}' >/dev/null
kill "$SRV_PID" 2>/dev/null || true; SRV_PID=""

echo
echo "=== 2. 建索引（源库只读，索引库独立） ==="
"${CLI[@]}" index-sync --index-db "$INDEX" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print({k:d[k] for k in ("generation","source_events","indexed_events","skipped_events")}); print("skipped:", [(s["event_id"],s["reason_code"]) for s in d["skipped"]])'

EXPR='{"any":{"path":["measurements"],"where":{"and":[{"eq":{"path":["metric"],"value":"temperature"}},{"gt":{"path":["value"],"value":30}}]}}}'
echo
echo "=== 3. 组合条件：同元素 metric=temperature 且 value>30 ==="
echo "--- acme（t20-h80 是反例，不应命中；t35 应命中） ---"
JOINED=$("${Q[@]}" --partner acme --expr "$EXPR")
echo "$JOINED" | show
echo "--- globex（独立合作方） ---"
"${Q[@]}" --partner globex --expr "$EXPR" | show

echo
echo "=== 4. 非法表达式明确报错（退出码 2） ==="
set +e
"${Q[@]}" --partner acme --expr '{"and":[]}' 2>"$WORK/err.txt"
CODE=$?
set -e
echo "exit=$CODE stderr=$(cat "$WORK/err.txt")"

echo
echo "=== 5. 未提交即崩溃：旧代仍可查询 ==="
"${CLI[@]}" index-sync --index-db "$INDEX" >/dev/null
set +e
"${CLI[@]}" index-sync --index-db "$INDEX" --simulate-crash-after-nodes 2>&1
echo "crash-exit=$?"
set -e
"${Q[@]}" --partner acme --expr "$EXPR" | show

echo
echo "=== 6. 源库改名后查询（证明查询只读索引） ==="
mv "$DB" "$DB.hidden"
"${Q[@]}" --partner acme --expr "$EXPR" | show
mv "$DB.hidden" "$DB"

echo
echo ">>> 演示完成。完整独立核对：python3 -I scripts/index_acceptance.py"
