-- 合作方 Webhook 接入服务初始 schema
-- 幂等：可重复执行，已存在的对象不会报错。

-- 原始字节体：按内容哈希去重，保存可重放所需的全部原始数据。
CREATE TABLE IF NOT EXISTS raw_bodies (
    body_sha256   TEXT PRIMARY KEY,
    body_blob     BLOB NOT NULL,
    byte_length   INTEGER NOT NULL,
    first_seen_at INTEGER NOT NULL
);

-- 接收流水：每次投递（含所有拒绝）追加一行，不做唯一约束，
-- 因为同一事件可能因为重复、冲突而多次到达，都必须留痕。
CREATE TABLE IF NOT EXISTS ingest_records (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at        INTEGER NOT NULL,           -- 服务端实际接收时间
    partner_id         TEXT,
    key_version        TEXT,
    claimed_timestamp  INTEGER,
    event_id           TEXT,
    source_seq         INTEGER,
    body_sha256        TEXT,
    result             TEXT NOT NULL,              -- accepted / duplicate / rejected / conflict
    reason             TEXT,                       -- 拒绝或判定原因
    http_status        INTEGER NOT NULL,
    headers_json       TEXT NOT NULL,
    FOREIGN KEY (body_sha256) REFERENCES raw_bodies (body_sha256)
);

CREATE INDEX IF NOT EXISTS idx_ingest_partner_time
    ON ingest_records (partner_id, received_at);
CREATE INDEX IF NOT EXISTS idx_ingest_event
    ON ingest_records (partner_id, event_id);

-- 已接受事件：同一合作方的 event_id 全局唯一。
-- 保存首见时的载荷哈希，用于区分「重复投递」与「同 ID 不同载荷」冲突。
CREATE TABLE IF NOT EXISTS accepted_events (
    event_id           TEXT NOT NULL,
    partner_id         TEXT NOT NULL,
    source_seq         INTEGER NOT NULL,
    key_version        TEXT NOT NULL,
    body_sha256        TEXT NOT NULL,
    ingest_record_id   INTEGER NOT NULL,
    claimed_timestamp  INTEGER NOT NULL,
    accepted_at        INTEGER NOT NULL,
    PRIMARY KEY (partner_id, event_id),
    FOREIGN KEY (body_sha256) REFERENCES raw_bodies (body_sha256),
    FOREIGN KEY (ingest_record_id) REFERENCES ingest_records (id)
);

CREATE INDEX IF NOT EXISTS idx_accepted_partner_seq
    ON accepted_events (partner_id, source_seq);

-- 下游投递 outbox：与事件接收在同一事务写入，
-- 进程崩溃后可重新投递，保证不丢。
CREATE TABLE IF NOT EXISTS outbox (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    partner_id    TEXT NOT NULL,
    event_id      TEXT NOT NULL,
    source_seq    INTEGER NOT NULL,
    body_sha256   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending', -- pending / delivered
    delivered_at  INTEGER,
    UNIQUE (partner_id, event_id)
);

PRAGMA user_version = 1;
