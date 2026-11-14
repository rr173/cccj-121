-- 下游 HTTP 投递：合作方接收地址、投递状态/占用、逐次尝试与人工操作审计。
-- 既有 raw_bodies / ingest_records / accepted_events / outbox 不做任何改写；
-- 历史 outbox.status='delivered' 的记录没有状态行，因此不会被新工人重发。
--
-- 注意：CREATE 语句保持紧凑（sqlite_schema 里保存的是语句原文），这样离线
-- 抢救工具在小单条载荷上限下仍能完整解释目录。列语义见 README 与代码。
--
-- delivery_endpoints: 每个合作方一个固定接收地址；触发器禁止原地更换。
-- outbox_delivery.status: in_flight / retry_wait / permanent_failure / delivered
--   attempt_no 本轮连续失败计数（人工重试清零）；total_attempts 含各轮。
-- delivery_attempts: 逐次尝试；接手时旧尝试标 lease_expired_takeover，
--   旧工人迟到回执只写 late_* 字段，绝不覆盖新结果。
-- delivery_operator_actions: 操作者动作（人工重试），与网络尝试分开留痕。

CREATE TABLE IF NOT EXISTS delivery_endpoints(
 partner_id TEXT PRIMARY KEY,
 url TEXT NOT NULL,
 registered_at INTEGER NOT NULL);

CREATE TRIGGER IF NOT EXISTS trg_delivery_endpoint_immutable
BEFORE UPDATE OF partner_id,url ON delivery_endpoints
BEGIN SELECT RAISE(ABORT,'delivery endpoint address is immutable'); END;

CREATE TABLE IF NOT EXISTS outbox_delivery(
 outbox_id INTEGER PRIMARY KEY REFERENCES outbox(id),
 partner_id TEXT NOT NULL,
 status TEXT NOT NULL,
 attempt_no INTEGER NOT NULL DEFAULT 0,
 total_attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at INTEGER,
 lease_owner TEXT,
 lease_token TEXT,
 lease_expires_at INTEGER,
 current_attempt_id INTEGER,
 last_http_status INTEGER,
 last_failure_reason TEXT,
 last_attempt_at INTEGER,
 last_finished_at INTEGER,
 takeover_reason TEXT,
 delivered_at INTEGER,
 updated_at INTEGER NOT NULL);

CREATE INDEX IF NOT EXISTS idx_outbox_delivery_partner
 ON outbox_delivery(partner_id,status,next_attempt_at);

CREATE TABLE IF NOT EXISTS delivery_attempts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 outbox_id INTEGER NOT NULL REFERENCES outbox(id),
 partner_id TEXT NOT NULL,
 event_id TEXT NOT NULL,
 source_seq INTEGER NOT NULL,
 delivery_key TEXT NOT NULL,
 body_sha256 TEXT NOT NULL,
 attempt_no INTEGER NOT NULL,
 worker_id TEXT NOT NULL,
 lease_token TEXT NOT NULL,
 claimed_at INTEGER NOT NULL,
 lease_expires_at INTEGER NOT NULL,
 finished_at INTEGER,
 outcome TEXT,
 http_status INTEGER,
 failure_reason TEXT,
 detail_json TEXT,
 body_bytes_sent INTEGER,
 takeover_reason TEXT,
 previous_attempt_id INTEGER,
 previous_worker_id TEXT,
 late_finished_at INTEGER,
 late_outcome TEXT,
 late_http_status INTEGER,
 late_failure_reason TEXT);

CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_attempts_token
 ON delivery_attempts(lease_token);
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_outbox
 ON delivery_attempts(outbox_id,id);

CREATE TABLE IF NOT EXISTS delivery_operator_actions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 outbox_id INTEGER NOT NULL REFERENCES outbox(id),
 partner_id TEXT NOT NULL,
 event_id TEXT NOT NULL,
 action TEXT NOT NULL,
 acted_at INTEGER NOT NULL,
 detail_json TEXT);

PRAGMA user_version = 2;
