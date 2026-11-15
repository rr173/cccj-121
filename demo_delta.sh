#!/usr/bin/env bash
# 正文差量交接演示：双方分离、只传签名与差量包，不共享文件系统。
#
# 场景：
#   1. 接收端有旧正文 old.bin；
#   2. 服务端真实收件得到新正文（只改开头少量字节）；
#   3. 接收端生成签名，只把签名复制给发送端；
#   4. 发送端从签名 + 收件库生成差量包（看不到旧文件）；
#   5. 接收端移走源库，仅凭旧文件与差量包还原，并逐字节核对。
set -euo pipefail
cd "$(dirname "$0")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RECV="$WORK/receiver"
SEND="$WORK/sender"
mkdir -p "$RECV" "$SEND"
DB="$RECV/webhook.db"

python3 -I partner_webhook/cli.py --db "$DB" init-db >/dev/null

# 旧正文（接收端本地保存；发送端不应看到它）
python3 - "$RECV/old.bin" "$RECV/new.bin" <<'PY'
import sys
old = (b"device=acme;reading=42;status=ok\n" * 400)
new = b"#" + old  # 开头插入一个字节
open(sys.argv[1], "wb").write(old)
open(sys.argv[2], "wb").write(new)
PY

# 服务端已收到新正文：离线写入与正常收件相同的 accepted_events/raw_bodies 行
python3 - "$DB" "$RECV/new.bin" <<'PY'
import hashlib
import sys
sys.path.insert(0, ".")
from partner_webhook.storage import Storage

db, body_path = sys.argv[1], sys.argv[2]
body = open(body_path, "rb").read()
storage = Storage(db)
digest = storage.store_raw_body(body, 0)
rid = storage.insert_ingest_record(dict(
    received_at=0, partner_id="acme", key_version="v1",
    claimed_timestamp=0, event_id="evt-delta-1", source_seq=1,
    body_sha256=digest, result="accepted", reason=None,
    http_status=200, headers={}))
storage.insert_accepted_event(dict(
    event_id="evt-delta-1", partner_id="acme", source_seq=1,
    key_version="v1", body_sha256=digest, ingest_record_id=rid,
    claimed_timestamp=0, accepted_at=0))
storage.enqueue_outbox(partner_id="acme", event_id="evt-delta-1",
                       source_seq=1, body_sha256=digest, now=0)
storage.commit()
storage.close()
PY

echo "== 1. 接收端为旧文件生成签名，只复制签名给发送端 =="
python3 -I partner_webhook/signature.py --old "$RECV/old.bin" \
    --block-size 64 --out "$RECV/old.sig"
cp "$RECV/old.sig" "$SEND/old.sig"
[ ! -e "$SEND/old.bin" ] && echo "发送端确实没有旧文件"

echo "== 2. 发送端由签名与收件正文生成差量包 =="
python3 -I partner_webhook/delta.py --db "$DB" --partner acme \
    --event-id evt-delta-1 --signature "$SEND/old.sig" \
    --out "$SEND/new.delta"

echo "== 3. 检查差量包（不输出正文） =="
python3 -I partner_webhook/deltainspect.py packet --delta "$SEND/new.delta"

echo "== 4. 接收端移走源库，仅用旧文件与包还原 =="
mv "$DB" "$DB.moved"
rm -f "$DB-wal" "$DB-shm"
python3 -I partner_webhook/apply.py --old "$RECV/old.bin" \
    --delta "$SEND/new.delta" --out "$RECV/restored.bin"

python3 - "$RECV/restored.bin" "$RECV/new.bin" <<'PY'
import hashlib
import sys
a = open(sys.argv[1], "rb").read()
b = open(sys.argv[2], "rb").read()
print("还原长度:", len(a))
print("还原 SHA-256:", hashlib.sha256(a).hexdigest())
assert a == b, "还原内容与事先保存的新正文不一致"
print("逐字节一致：是")
PY
echo "演示完成。"
