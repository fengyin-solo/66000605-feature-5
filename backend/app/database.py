"""SQLite 持久层：审计记录的存取。

数据库文件默认位于 backend/audit.db，可通过环境变量 AUDIT_DB_PATH 覆盖。
所有记录写入后即持久化，服务重启后历史结论、漏洞清单与建议仍可原样查回。
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import List, Optional

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit.db"
)


def get_db_path() -> str:
    return os.environ.get("AUDIT_DB_PATH", DEFAULT_DB_PATH)


@contextmanager
def get_conn():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audits (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                code TEXT NOT NULL,
                status TEXT NOT NULL,
                score INTEGER,
                vulnerabilities TEXT NOT NULL DEFAULT '[]',
                gas_issues TEXT NOT NULL DEFAULT '[]',
                error TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audits_code_hash ON audits(code_hash)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits(created_at)"
        )


def _row_to_dict(row: sqlite3.Row) -> dict:
    """数据库行 -> 对外 API 视图（不含合约原文）。"""
    return {
        "id": row["id"],
        "filename": row["filename"],
        "codeHash": row["code_hash"],
        "status": row["status"],
        "score": row["score"],
        "vulnerabilities": json.loads(row["vulnerabilities"]),
        "gasIssues": json.loads(row["gas_issues"]),
        "error": row["error"],
        "timestamp": row["created_at"],
    }


def public_view(record: dict) -> dict:
    """内存中的完整记录 -> 对外 API 视图。"""
    return {
        "id": record["id"],
        "filename": record["filename"],
        "codeHash": record["codeHash"],
        "status": record["status"],
        "score": record["score"],
        "vulnerabilities": record["vulnerabilities"],
        "gasIssues": record["gasIssues"],
        "error": record["error"],
        "timestamp": record["timestamp"],
    }


def insert_audit(record: dict) -> dict:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audits
                (id, filename, code_hash, code, status, score,
                 vulnerabilities, gas_issues, error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["id"],
                record["filename"],
                record["codeHash"],
                record["code"],
                record["status"],
                record["score"],
                json.dumps(record["vulnerabilities"], ensure_ascii=False),
                json.dumps(record["gasIssues"], ensure_ascii=False),
                record["error"],
                record["timestamp"],
            ),
        )
    return record


def find_recent_success(code_hash: str, window_seconds: int) -> Optional[dict]:
    """查找时间窗口内同一份合约（同哈希）的成功审计记录，用于去重。"""
    cutoff = (datetime.now() - timedelta(seconds=window_seconds)).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM audits
            WHERE code_hash = ? AND status = 'success' AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (code_hash, cutoff),
        ).fetchone()
    return _row_to_dict(row) if row else None


def list_audits() -> List[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audits ORDER BY created_at DESC"
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_audit(audit_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None
