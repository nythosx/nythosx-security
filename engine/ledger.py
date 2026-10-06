import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent.absolute()
DB_PATH = ROOT / "findings" / "ledger.db"


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            engagement_id TEXT,
            target TEXT,
            pattern_id TEXT,
            category TEXT,
            verdict TEXT,
            severity TEXT,
            reason TEXT,
            wstg_id TEXT,
            cwe_id TEXT,
            evidence_path TEXT,
            evidence_json TEXT,
            duration_ms REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            engagement_id TEXT,
            target TEXT,
            pattern_count INTEGER,
            vulnerable_count INTEGER,
            duration_ms REAL
        )
        """
    )
    conn.commit()
    return conn


def record_finding(pattern_id, target, verdict, severity, reason, evidence_path,
                    evidence_json, category="", wstg_id="", cwe_id="",
                    duration_ms=0, engagement_id=""):
    conn = _connect()
    conn.execute(
        """
        INSERT INTO findings (timestamp, engagement_id, target, pattern_id, category,
                              verdict, severity, reason, wstg_id, cwe_id,
                              evidence_path, evidence_json, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            engagement_id, target, pattern_id, category,
            verdict, severity, reason, wstg_id, cwe_id,
            evidence_path, json.dumps(evidence_json, default=str), duration_ms,
        ),
    )
    conn.commit()
    conn.close()


def record_run(target, pattern_count, vulnerable_count, duration_ms, engagement_id=""):
    conn = _connect()
    conn.execute(
        """
        INSERT INTO runs (timestamp, engagement_id, target, pattern_count,
                          vulnerable_count, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            engagement_id, target, pattern_count, vulnerable_count, duration_ms,
        ),
    )
    conn.commit()
    conn.close()


def recent_findings(limit=30, target=None):
    conn = _connect()
    if target:
        rows = conn.execute(
            "SELECT id, timestamp, pattern_id, target, verdict, severity, reason "
            "FROM findings WHERE target = ? ORDER BY id DESC LIMIT ?",
            (target, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, timestamp, pattern_id, target, verdict, severity, reason "
            "FROM findings ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return rows


def findings_for_target(target):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, timestamp, pattern_id, category, verdict, severity, reason, "
        "wstg_id, cwe_id, evidence_path, duration_ms "
        "FROM findings WHERE target = ? "
        "ORDER BY CASE severity "
        "WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
        "WHEN 'low' THEN 2 ELSE 1 END DESC, id DESC",
        (target,),
    ).fetchall()
    conn.close()
    return rows


def all_targets():
    conn = _connect()
    rows = conn.execute(
        "SELECT DISTINCT target FROM findings ORDER BY target"
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]
