import sqlite3
import json
import threading

from . import redact
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent.absolute()
DB_PATH = ROOT / "findings" / "ledger.db"

_write_lock = threading.Lock()


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
        CREATE TABLE IF NOT EXISTS chain_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            engagement_id TEXT,
            chain_id TEXT,
            step_id TEXT,
            tool TEXT,
            verdict TEXT,
            duration_ms REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS extracted_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            engagement_id TEXT,
            target TEXT,
            endpoint TEXT,
            method TEXT,
            auth_used TEXT,
            status INTEGER,
            total_rows INTEGER,
            extracted INTEGER,
            rows_json TEXT,
            source_pattern TEXT
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
    reason = redact.redact_text(reason) if isinstance(reason, str) else reason
    evidence_json = redact.redact_dict(evidence_json)
    with _write_lock:
        conn = _connect()
        try:
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
                    evidence_path, json.dumps(evidence_json, default=str),
                    duration_ms,
                ),
            )
            conn.commit()
        finally:
            conn.close()


def record_extracted(target, endpoint, method, auth_used, status,
                      total_rows, extracted, rows, source_pattern="",
                      engagement_id=""):
    if not endpoint:
        return
    safe_rows = redact.redact_dict(list(rows or []))
    with _write_lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO extracted_data
                    (timestamp, engagement_id, target, endpoint, method,
                     auth_used, status, total_rows, extracted, rows_json,
                     source_pattern)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    engagement_id, target, endpoint, method,
                    auth_used, int(status or 0), int(total_rows or 0),
                    int(extracted or 0),
                    json.dumps(safe_rows, default=str),
                    source_pattern,
                ),
            )
            conn.commit()
        finally:
            conn.close()


def extracted_for_target(target):
    conn = _connect()
    rows = conn.execute(
        "SELECT id, timestamp, endpoint, method, auth_used, status, "
        "total_rows, extracted, rows_json, source_pattern "
        "FROM extracted_data WHERE target = ? ORDER BY id DESC",
        (target,),
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        try:
            parsed = json.loads(r[8]) if r[8] else []
        except Exception:
            parsed = []
        out.append({
            "id": r[0], "timestamp": r[1], "endpoint": r[2], "method": r[3],
            "auth_used": r[4], "status": r[5], "total_rows": r[6],
            "extracted": r[7], "rows": parsed, "source_pattern": r[9],
        })
    return out


def extracted_stats(target):
    conn = _connect()
    row = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(extracted), 0), "
        "COUNT(DISTINCT endpoint) FROM extracted_data WHERE target = ?",
        (target,),
    ).fetchone()
    conn.close()
    if not row:
        return {"records": 0, "total_extracted": 0, "endpoints": 0}
    return {"records": int(row[0] or 0),
            "total_extracted": int(row[1] or 0),
            "endpoints": int(row[2] or 0)}


def record_run(target, pattern_count, vulnerable_count, duration_ms, engagement_id=""):
    with _write_lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO runs (timestamp, engagement_id, target, pattern_count,
                                  vulnerable_count, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    engagement_id, target, pattern_count, vulnerable_count,
                    duration_ms,
                ),
            )
            conn.commit()
        finally:
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
        "wstg_id, cwe_id, evidence_path, duration_ms, evidence_json "
        "FROM findings WHERE target = ? "
        "ORDER BY CASE severity "
        "WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
        "WHEN 'low' THEN 2 ELSE 1 END DESC, id DESC",
        (target,),
    ).fetchall()
    conn.close()
    return rows


def record_chain_step(chain_id, step_id, tool, verdict,
                        duration_ms=0, engagement_id=""):
    with _write_lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO chain_runs
                    (timestamp, engagement_id, chain_id, step_id, tool,
                     verdict, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    engagement_id, chain_id, step_id, tool, verdict,
                    float(duration_ms or 0),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def chain_stats(limit=0):
    conn = _connect()
    rows = conn.execute(
        "SELECT chain_id, verdict, duration_ms FROM chain_runs"
    ).fetchall()
    conn.close()
    by_chain = {}
    for cid, verdict, dur in rows:
        e = by_chain.setdefault(cid, {
            "chain_id": cid, "runs": 0, "vulnerable": 0,
            "suspicious": 0, "pass_count": 0, "unknown": 0,
            "total_duration_ms": 0.0,
        })
        e["runs"] += 1
        v = (verdict or "UNKNOWN").upper()
        if v == "VULNERABLE":
            e["vulnerable"] += 1
        elif v == "SUSPICIOUS":
            e["suspicious"] += 1
        elif v == "PASS":
            e["pass_count"] += 1
        else:
            e["unknown"] += 1
        e["total_duration_ms"] += float(dur or 0)
    chains = []
    for e in by_chain.values():
        runs = e["runs"] or 1
        e["avg_duration_ms"] = e["total_duration_ms"] / runs
        del e["total_duration_ms"]
        chains.append(e)
    chains.sort(key=lambda x: (-x["vulnerable"], -x["runs"]))
    if limit:
        chains = chains[:limit]
    return {"chains": chains,
            "total_runs": sum(c["runs"] for c in chains)}


def all_targets():
    conn = _connect()
    rows = conn.execute(
        "SELECT DISTINCT target FROM findings ORDER BY target"
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]
