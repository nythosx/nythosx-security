import json
from pathlib import Path

from . import redact
from datetime import datetime, timezone
from .util import safe_name

ROOT = Path(__file__).parent.parent.absolute()
EVIDENCE_DIR = ROOT / "evidence"


def _safe(s):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:80]


def _save_evidence_impl(pattern_id, target, context, verdict, oracle_result,
                  engine_cfg=None):
    if engine_cfg is None:
        from .config import load_engine
        engine_cfg = load_engine()
    ev_cfg = engine_cfg.get("evidence", {}) or {}
    save_raw_bodies = ev_cfg.get("save_raw_bodies", True)
    max_bytes = int(ev_cfg.get("max_body_size_kb", 100)) * 1024
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    dir_path = EVIDENCE_DIR / f"{ts}_{pattern_id}_{safe_name(target)}"
    dir_path.mkdir(parents=True, exist_ok=True)
    summary = {
        "timestamp": ts,
        "pattern": pattern_id,
        "target": target,
        "verdict": verdict,
        "reason": oracle_result.get("reason"),
        "evidence": oracle_result.get("evidence", {}),
        "total_steps": len(context.get("steps", [])),
    }
    summary = redact.redact_dict(summary)
    (dir_path / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    raw = []
    for s in context.get("steps", [])[:500]:
        body = s.get("body") or ""
        raw.append({
            "step_name": s.get("step_name"),
            "loop_index": s.get("loop_index"),
            "status": s.get("status"),
            "time_ms": s.get("time_ms"),
            "body_hash": s.get("body_hash"),
            "url": s.get("url"),
            "error": s.get("error"),
            "headers": s.get("headers"),
            "body_preview": body[:max_bytes] if save_raw_bodies else "",
        })
    raw = redact.redact_dict(raw)
    (dir_path / "raw.json").write_text(
        json.dumps(raw, indent=2, default=str), encoding="utf-8"
    )
    return str(dir_path)

def save_evidence(pattern_id, target, context, verdict, oracle_result,
                  engine_cfg=None, author=None, confidence=None,
                  chain_ids=None):
    import json
    from pathlib import Path as _Path
    path = _save_evidence_impl(pattern_id, target, context, verdict,
                               oracle_result, engine_cfg=engine_cfg)
    summary_path = _Path(path) / "summary.json"
    if summary_path.exists():
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if author is not None:
            data["author"] = author
        else:
            data.setdefault("author", "system")
        if confidence is not None:
            data["confidence"] = confidence
        else:
            data.setdefault("confidence", 0.5)
        if chain_ids is not None:
            data["chain_ids"] = list(chain_ids)
        else:
            data.setdefault("chain_ids", [])
        summary_path.write_text(json.dumps(data, indent=2, default=str),
                                encoding="utf-8")
    try:
        from . import evidence_warehouse as _wh
        _wh.ingest(
            target=target,
            endpoint=str(path),
            kind=f"evidence:{pattern_id}",
            status=0,
            body=json.dumps({
                "verdict": verdict,
                "reason": oracle_result.get("reason", ""),
                "evidence": oracle_result.get("evidence", {}),
            }, default=str),
            chain_id=",".join(chain_ids or []),
        )
    except Exception:
        pass
    return path

def bundle_evidence(target, extra_paths=None):
    """Zip every evidence file for the target into one archive."""
    import zipfile
    from datetime import datetime as _dt
    from datetime import timezone as _tz
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:80]
    stamp = _dt.now(_tz.utc).strftime("%Y%m%dT%H%M%S")
    out_dir = ROOT / "findings" / "bundles"
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{stamp}_{safe}_evidence.zip"
    included = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        if EVIDENCE_DIR.exists():
            for p in EVIDENCE_DIR.rglob("*"):
                if p.is_file():
                    try:
                        z.write(p, p.relative_to(EVIDENCE_DIR.parent))
                        included += 1
                    except Exception:
                        continue
        audit = ROOT / "findings" / "audit.jsonl"
        if audit.exists():
            try:
                z.write(audit, "findings/audit.jsonl")
                included += 1
            except Exception:
                pass
        ledger_db = ROOT / "findings" / "ledger.db"
        if ledger_db.exists():
            try:
                z.write(ledger_db, "findings/ledger.db")
                included += 1
            except Exception:
                pass
        for extra in (extra_paths or []):
            try:
                p = Path(extra)
                if p.exists() and p.is_file():
                    z.write(p, "extra/" + p.name)
                    included += 1
            except Exception:
                continue
    return {"zip_path": str(zip_path), "files_included": included}
