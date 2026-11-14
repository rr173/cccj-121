"""SQLite 持久层。

线程模型：本地服务通过 threading 起服务，所有写入走同一把进程内锁，
并在单个事务内完成「原始体保存 → 流水记录 → 去重/冲突判定 → outbox」，
保证进程崩溃/重启后的一致性。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

# 迁移目录可能位于：
# 1. 仓库布局：<repo>/migrations（包目录的上一级）；
# 2. 打包安装布局：<site-packages>/partner_webhook/migrations（随包数据安装）；
# 3. 运行目录下的 ./migrations（容器部署时挂载）。
_PACKAGE_DIR = Path(__file__).resolve().parent
_CANDIDATE_DIRS = (
    _PACKAGE_DIR.parent / "migrations",
    _PACKAGE_DIR / "migrations",
    Path.cwd() / "migrations",
)
MIGRATIONS_DIR = next((d for d in _CANDIDATE_DIRS if d.is_dir()),
                      _CANDIDATE_DIRS[0])


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL 让查询与写入在重启恢复时更稳，离线单机足够。
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def run_migrations(conn: sqlite3.Connection) -> None:
    """按文件名顺序执行 migrations 目录下全部 SQL（幂等）。"""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    applied = current
    for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
        version = int(sql_file.name.split("_", 1)[0])
        if version <= current:
            continue
        conn.executescript(sql_file.read_text(encoding="utf-8"))
        applied = version
    if applied != current:
        conn.commit()


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = connect(db_path)
        self._lock = threading.RLock()
        with self._lock:
            run_migrations(self.conn)

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ------------------------------------------------------------------ #
    # 接收路径（单事务）
    # ------------------------------------------------------------------ #
    def store_raw_body(self, body: bytes, now: int) -> str:
        import hashlib

        digest = hashlib.sha256(body).hexdigest()
        self.conn.execute(
            "INSERT OR IGNORE INTO raw_bodies "
            "(body_sha256, body_blob, byte_length, first_seen_at) VALUES (?, ?, ?, ?)",
            (digest, body, len(body), now),
        )
        return digest

    def insert_ingest_record(self, record: dict[str, Any]) -> int:
        cur = self.conn.execute(
            "INSERT INTO ingest_records "
            "(received_at, partner_id, key_version, claimed_timestamp, event_id, "
            " source_seq, body_sha256, result, reason, http_status, headers_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["received_at"],
                record.get("partner_id"),
                record.get("key_version"),
                record.get("claimed_timestamp"),
                record.get("event_id"),
                record.get("source_seq"),
                record.get("body_sha256"),
                record["result"],
                record.get("reason"),
                record["http_status"],
                json.dumps(record.get("headers", {}), ensure_ascii=False, sort_keys=True),
            ),
        )
        return int(cur.lastrowid)

    def get_accepted_event(self, partner_id: str, event_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM accepted_events WHERE partner_id = ? AND event_id = ?",
            (partner_id, event_id),
        ).fetchone()

    def insert_accepted_event(self, row: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO accepted_events "
            "(event_id, partner_id, source_seq, key_version, body_sha256, "
            " ingest_record_id, claimed_timestamp, accepted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["event_id"],
                row["partner_id"],
                row["source_seq"],
                row["key_version"],
                row["body_sha256"],
                row["ingest_record_id"],
                row["claimed_timestamp"],
                row["accepted_at"],
            ),
        )

    def enqueue_outbox(self, *, partner_id: str, event_id: str,
                       source_seq: int, body_sha256: str, now: int) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO outbox "
            "(partner_id, event_id, source_seq, body_sha256, created_at, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            (partner_id, event_id, source_seq, body_sha256, now),
        )

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # ------------------------------------------------------------------ #
    # 查询接口
    # ------------------------------------------------------------------ #
    def query_records(
        self,
        *,
        partner_id: str | None = None,
        start_ts: int | None = None,
        end_ts: int | None = None,
        result: str | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM ingest_records WHERE 1=1"
        params: list[Any] = []
        if partner_id:
            sql += " AND partner_id = ?"
            params.append(partner_id)
        if start_ts is not None:
            sql += " AND received_at >= ?"
            params.append(start_ts)
        if end_ts is not None:
            sql += " AND received_at <= ?"
            params.append(end_ts)
        if result:
            sql += " AND result = ?"
            params.append(result)
        sql += " ORDER BY received_at ASC, id ASC LIMIT ?"
        params.append(limit)
        with self._lock:
            return list(self.conn.execute(sql, params).fetchall())

    def get_record(self, record_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM ingest_records WHERE id = ?", (record_id,)
            ).fetchone()

    def get_raw_body(self, body_sha256: str) -> bytes | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT body_blob FROM raw_bodies WHERE body_sha256 = ?",
                (body_sha256,),
            ).fetchone()
            return bytes(row["body_blob"]) if row else None

    def list_events(
        self,
        *,
        partner_id: str | None = None,
        start_ts: int | None = None,
        end_ts: int | None = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM accepted_events WHERE 1=1"
        params: list[Any] = []
        if partner_id:
            sql += " AND partner_id = ?"
            params.append(partner_id)
        if start_ts is not None:
            sql += " AND accepted_at >= ?"
            params.append(start_ts)
        if end_ts is not None:
            sql += " AND accepted_at <= ?"
            params.append(end_ts)
        sql += " ORDER BY partner_id ASC, source_seq ASC LIMIT ?"
        params.append(limit)
        with self._lock:
            return list(self.conn.execute(sql, params).fetchall())

    def stats(self) -> dict[str, Any]:
        with self._lock:
            records = dict(
                self.conn.execute(
                    "SELECT result, COUNT(*) FROM ingest_records GROUP BY result"
                ).fetchall()
            )
            outbox = dict(
                self.conn.execute(
                    "SELECT status, COUNT(*) FROM outbox GROUP BY status"
                ).fetchall()
            )
            return {
                "ingest": records,
                "outbox": outbox,
                "accepted_events": self.conn.execute(
                    "SELECT COUNT(*) FROM accepted_events"
                ).fetchone()[0],
            }

    # ------------------------------------------------------------------ #
    # outbox 投递（下游占位：标记 delivered，可被替换为真实下游）
    # ------------------------------------------------------------------ #
    def pending_outbox(self, limit: int = 100) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self.conn.execute(
                    "SELECT * FROM outbox WHERE status = 'pending' "
                    "ORDER BY partner_id ASC, source_seq ASC, id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
            )

    def mark_delivered(self, outbox_id: int, now: int) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE outbox SET status = 'delivered', delivered_at = ? WHERE id = ?",
                (now, outbox_id),
            )
            self.conn.commit()

    def iter_all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(sql, list(params)).fetchall())
