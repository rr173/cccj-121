-- 合作方可验证追加账本（按合作方独立的哈希日志）。
--
-- 只新增账本表，不改写 raw_bodies / ingest_records / accepted_events / outbox
-- 的任何列或行。每个合作方一行 event_logs，log_id 在首次安装时随机生成并
-- 永久固定；log_leaves 保存叶位置与叶哈希，log_nodes 保存已形成的子树节点
-- （level=子树高度，node_index=起始叶/2^level）。正常追加只插入受新叶影响
-- 的节点，已形成的节点不会被改写。
--
-- 事务语义：安装、追加叶子和接收事件共用同一个 SQLite 写事务；两进程并发
-- 收件由 BEGIN IMMEDIATE 的数据库写锁串行化，不依赖进程内线程锁。

CREATE TABLE IF NOT EXISTS event_logs (
    partner_id  TEXT PRIMARY KEY,
    log_id      TEXT NOT NULL UNIQUE,
    protocol    TEXT NOT NULL,
    tree_size   INTEGER NOT NULL,
    root_hash   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    CHECK (tree_size >= 0)
);

CREATE TABLE IF NOT EXISTS log_leaves (
    partner_id  TEXT NOT NULL,
    leaf_index  INTEGER NOT NULL,
    event_id    TEXT NOT NULL,
    source_seq  INTEGER NOT NULL,
    body_sha256 TEXT NOT NULL,
    leaf_hash   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (partner_id, leaf_index),
    UNIQUE (partner_id, event_id),
    FOREIGN KEY (partner_id) REFERENCES event_logs (partner_id)
);

CREATE TABLE IF NOT EXISTS log_nodes (
    partner_id  TEXT NOT NULL,
    level       INTEGER NOT NULL,
    node_index  INTEGER NOT NULL,
    node_hash   TEXT NOT NULL,
    PRIMARY KEY (partner_id, level, node_index),
    FOREIGN KEY (partner_id) REFERENCES event_logs (partner_id)
);

PRAGMA user_version = 3;
