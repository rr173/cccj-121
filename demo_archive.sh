#!/usr/bin/env bash
# 设备档案加工演示：本地环回真实签名收件 → 独立加工库乱序/分支加工 → CLI 读回。
# 全程离线；临时目录结束自动清理。可复跑断言见 scripts/archive_acceptance.py。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
DB="$WORK/source.db"
ARCHIVE="$WORK/archive.db"
PORT="${PORT:-18099}"
CLI=(python3 -I "$REPO_ROOT/partner_webhook/cli.py"
     --config "$REPO_ROOT/config.example.json" --db "$DB")

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo ">>> 工作目录: $WORK"
"${CLI[@]}" init-db >/dev/null
"${CLI[@]}" serve --port "$PORT" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1.2

send() { "${CLI[@]}" send --url "http://127.0.0.1:$PORT" "$@" >/dev/null; }

echo
echo "=== 1. 乱序收件：修订 2 先到，seed 最后到 ==="
send --partner acme --key-version v1 --event-id p2 --sequence 1 \
  --body '{"kind":"patch","document_id":"dev-9","base_revision":1,"revision":2,"operations":[{"op":"replace","path":"/v","value":2}]}'
"${CLI[@]}" archive-sync --archive-db "$ARCHIVE" >/dev/null
echo "--- 等待期处置 ---"
"${CLI[@]}" archive-dispositions --archive-db "$ARCHIVE" \
  | python3 -c 'import json,sys; [print(r["event_id"], r["disposition_text"]) for r in json.load(sys.stdin)]'

send --partner acme --key-version v1 --event-id p1 --sequence 2 \
  --body '{"kind":"patch","document_id":"dev-9","base_revision":0,"revision":1,"operations":[{"op":"replace","path":"/v","value":1}]}'
send --partner acme --key-version v1 --event-id s0 --sequence 3 \
  --body '{"kind":"seed","document_id":"dev-9","revision":0,"document":{"v":0}}'
send --partner acme --key-version v1 --event-id hb --sequence 4 \
  --body '{"kind":"heartbeat"}'
"${CLI[@]}" archive-sync --archive-db "$ARCHIVE" >/dev/null
echo "--- 补齐后当前档案（应到修订 2，v=2） ---"
"${CLI[@]}" archive-document --archive-db "$ARCHIVE" --partner acme --document-id dev-9 \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("revision=",d["current_revision"],"document=",d["document"])'

echo
echo "=== 2. 后来补入第 1 版分支：公布退回第 0 版 ==="
send --partner acme --key-version v1 --event-id p1-alt --sequence 5 \
  --body '{"kind":"patch","document_id":"dev-9","base_revision":0,"revision":1,"operations":[{"op":"replace","path":"/v","value":11}]}'
"${CLI[@]}" archive-sync --archive-db "$ARCHIVE" >/dev/null
"${CLI[@]}" archive-revisions --archive-db "$ARCHIVE" --partner acme --document-id dev-9 \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("current=",d["current_revision"]); [print(e["event_id"],e["disposition_text"]) for e in d["events"]]'

echo
echo "=== 3. 人工选择原 p1：恢复到第 2 版 ==="
"${CLI[@]}" archive-select --archive-db "$ARCHIVE" --partner acme \
  --document-id dev-9 --revision 1 --event-id p1 >/dev/null
"${CLI[@]}" archive-document --archive-db "$ARCHIVE" --partner acme --document-id dev-9 \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("revision=",d["current_revision"],"document=",d["document"],"chain=",[c["event_id"] for c in d["chain"]])'

echo
echo "=== 4. 撤销选择：再次退回第 0 版 ==="
"${CLI[@]}" archive-deselect --archive-db "$ARCHIVE" --partner acme \
  --document-id dev-9 --revision 1 >/dev/null
"${CLI[@]}" archive-document --archive-db "$ARCHIVE" --partner acme --document-id dev-9 \
  | python3 -c 'import json,sys; print("revision=",json.load(sys.stdin)["current_revision"])'

echo
echo "=== 5. 跨合作方同号事件选择被拒（退出码 2，不改状态） ==="
send --partner globex --key-version g1 --event-id g-s0 --sequence 1 \
  --body '{"kind":"seed","document_id":"dev-9","revision":0,"document":{"v":100}}'
"${CLI[@]}" archive-sync --archive-db "$ARCHIVE" >/dev/null
set +e
"${CLI[@]}" archive-select --archive-db "$ARCHIVE" --partner acme \
  --document-id dev-9 --revision 0 --event-id g-s0 2>"$WORK/err.txt"
echo "exit=$? stderr=$(cat "$WORK/err.txt")"
set -e

echo
echo ">>> 演示完成。完整可复跑断言：python3 -I scripts/archive_acceptance.py"
