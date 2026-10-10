import json
from pathlib import Path
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
    return path
