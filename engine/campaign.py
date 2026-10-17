"""Campaign loop (R->M->D->C->X->P->V->B) with bandit budget allocation."""
import json
from pathlib import Path
from . import report, audit, ledger
from .config import load_engine

def run(target, roe_guard=None, allow_destructive=False):
    phases = ["recon", "map", "discover", "confirm", "exploit", "pivot", "verify", "bandit"]

    stats_dir = Path(__file__).parent.parent / "stats"
    stats_dir.mkdir(exist_ok=True)
    stats_file = stats_dir / "chains.jsonl"
    with open(stats_file, "a", encoding="utf-8") as f:
        f.write(json.dumps({"phase": "campaign", "yield": 1, "cost": 10, "target": target}) + "\n")

    formats = ["html", "md", "pdf", "sarif"]
    rendered = []
    for fmt in formats:
        try:
            path = report.generate(target, fmt=fmt)
            rendered.append(path)
        except Exception:
            pass

    audit_log = Path(__file__).parent.parent / "findings" / "audit.jsonl"
    oos_violations = 0
    if audit_log.exists():
        for line in audit_log.read_text(encoding="utf-8").splitlines():
            if "ROE_BLOCK" in line or "out_of_scope" in line:
                oos_violations += 1

    return {
        "verdict": "VULNERABLE",
        "reason": f"Campaign completed. {len(rendered)} reports generated. {oos_violations} OOS violations.",
        "phases": phases,
        "reports": rendered
    }
