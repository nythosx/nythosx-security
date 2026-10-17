"""Cross-target evidence warehouse.

SQLite + FTS5 index over every evidence blob, artifact, and finding so
you can answer "show every endpoint across all targets that leaked a
specific email" without grepping per-target files.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent.absolute()
DB_PATH = ROOT / "findings" / "warehouse.db"

_lock = threading.Lock()
_conn = None


def _ensure_schema(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS evidence ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts TEXT, target TEXT, endpoint TEXT, kind TEXT, "
        "status INTEGER, chain_id TEXT, body TEXT)"
    )
    try:
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts "
            "USING fts5(body, endpoint, target)"
        )
        conn.commit()
        return "fts5"
    except sqlite3.OperationalError:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence_fts ("
            "body TEXT, endpoint TEXT, target TEXT)"
        )
        conn.commit()
        return "plain"


def _get_conn():
    global _conn
    if _conn is not None:
        return _conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    _ensure_schema(_conn)
    return _conn


def _body_str(body):
    if isinstance(body, str):
        return body[:50000]
    try:
        return json.dumps(body, default=str)[:50000]
    except Exception:
        return str(body)[:50000]


def ingest(target, endpoint, kind, status, body, chain_id=""):
    if not target:
        return False
    payload = _body_str(body)
    with _lock:
        try:
            conn = _get_conn()
            ts = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO evidence "
                "(ts, target, endpoint, kind, status, chain_id, body) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, target, endpoint or "", kind or "", int(status or 0),
                 chain_id or "", payload),
            )
            conn.execute(
                "INSERT INTO evidence_fts (body, endpoint, target) "
                "VALUES (?, ?, ?)",
                (payload, endpoint or "", target),
            )
            conn.commit()
            return True
        except Exception:
            return False


def search(query, limit=100):
    if not query:
        return []
    with _lock:
        try:
            conn = _get_conn()
        except Exception:
            return []
        try:
            rows = conn.execute(
                "SELECT e.target, e.endpoint, e.status, e.body "
                "FROM evidence e "
                "WHERE e.rowid IN ("
                "  SELECT rowid FROM evidence_fts "
                "  WHERE evidence_fts MATCH ?) "
                "LIMIT ?",
                (query, int(limit)),
            ).fetchall()
            if rows:
                return rows
        except sqlite3.OperationalError:
            pass
        try:
            like = f"%{query}%"
            return conn.execute(
                "SELECT target, endpoint, status, body FROM evidence "
                "WHERE body LIKE ? OR endpoint LIKE ? OR target LIKE ? "
                "LIMIT ?",
                (like, like, like, int(limit)),
            ).fetchall()
        except Exception:
            return []


def close():
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None


def reset_for_test(path=None):
    global _conn, DB_PATH
    close()
    if path is not None:
        DB_PATH = Path(path)
    return True
