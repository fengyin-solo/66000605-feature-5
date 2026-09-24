"""审计结果持久化层（SQLite）。

服务重启后历史结论仍可查询；短时间内重复提交同一份合约时，
由上层配合 find_recent 沿用上一次结论，不重复落库。
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import List, Optional

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "audits.db",
)


class AuditStore:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("AUDIT_DB_PATH", DEFAULT_DB_PATH)
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # “查重 -> 生成结论 -> 落库”整段加锁，避免并发重复提交产生重复记录
        self.lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audits (
                    id           TEXT PRIMARY KEY,
                    code_hash    TEXT NOT NULL,
                    filename     TEXT NOT NULL,
                    code         TEXT NOT NULL,
                    status       TEXT NOT NULL,
                    score        INTEGER,
                    error        TEXT,
                    result_json  TEXT NOT NULL,
                    created_at   TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audits_hash_time "
                "ON audits(code_hash, created_at)"
            )

    def save(self, record: dict) -> None:
        """落库一次审计（成功或失败）。record 由 main 层组装。"""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audits
                    (id, code_hash, filename, code, status, score, error, result_json, created_at)
                VALUES
                    (:id, :code_hash, :filename, :code, :status, :score, :error, :result_json, :created_at)
                """,
                {
                    "id": record["id"],
                    "code_hash": record["code_hash"],
                    "filename": record["filename"],
                    "code": record["code"],
                    "status": record["status"],
                    "score": record.get("score"),
                    "error": record.get("error"),
                    "result_json": json.dumps(record["result"], ensure_ascii=False),
                    "created_at": record["created_at"],
                },
            )

    def _row_to_record(self, row: sqlite3.Row) -> dict:
        record = {
            "id": row["id"],
            "code_hash": row["code_hash"],
            "filename": row["filename"],
            "code": row["code"],
            "status": row["status"],
            "score": row["score"],
            "error": row["error"],
            "created_at": row["created_at"],
            "result": json.loads(row["result_json"]),
        }
        return record

    def find_recent(self, code_hash: str, within_seconds: int) -> Optional[dict]:
        """返回该合约在时间窗口内最近一次审计（成功或失败），没有则 None。"""
        threshold = (datetime.now() - timedelta(seconds=within_seconds)).isoformat(
            timespec="seconds"
        )
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM audits
                WHERE code_hash = ? AND created_at >= ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (code_hash, threshold),
            ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def list_history(self, limit: int = 100) -> List[dict]:
        """按时间倒序返回审计摘要（不含合约源码）。"""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, filename, code, status, score, error, result_json, created_at
                FROM audits
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        items = []
        for row in rows:
            result = json.loads(row["result_json"])
            items.append(
                {
                    "id": row["id"],
                    "filename": row["filename"],
                    "status": row["status"],
                    "score": row["score"],
                    "error": row["error"],
                    "timestamp": row["created_at"],
                    "vulnCount": len(result.get("vulnerabilities", [])),
                    "gasCount": len(result.get("gasIssues", [])),
                }
            )
        return items

    def get(self, audit_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM audits WHERE id = ?", (audit_id,)
            ).fetchone()
        return self._row_to_record(row) if row is not None else None
