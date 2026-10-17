"""Mark a finding as N/A / false positive, feeding the chain EV model.

Usage: python mark_na.py <finding_id> [--threshold N] [--json]

Repeatedly marking the same pattern as N/A (>= threshold times) causes
chainscore.p_vuln() to return 0.0 for that pattern, so the planner stops
selecting it on subsequent runs against this program.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(ROOT))

from engine import ledger, program_memory


def main(argv):
    ap = argparse.ArgumentParser(
        description="Mark a finding as N/A to suppress its pattern.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("finding_id", type=int)
    ap.add_argument("--threshold", type=int, default=3,
                    help="rejections before chain is suppressed (default 3)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    args = ap.parse_args(argv)

    finding = ledger.get_finding(args.finding_id)
    if finding is None:
        print(f"no finding with id {args.finding_id}", file=sys.stderr)
        return 1
    pattern_id = finding.get("pattern_id") or ""
    if not pattern_id:
        print(f"finding {args.finding_id} has no pattern_id", file=sys.stderr)
        return 1

    program_memory.record_rejection(pattern_id, reason="user_marked_na")
    data = program_memory._load(program_memory.REJECTIONS_FILE)
    count = int(data.get(pattern_id, 0))
    now_rejected = program_memory.is_rejected(
        pattern_id, threshold=args.threshold)

    out = {
        "finding_id": args.finding_id,
        "pattern_id": pattern_id,
        "rejection_count": count,
        "threshold": args.threshold,
        "now_rejected": now_rejected,
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        status = "SUPPRESSED" if now_rejected else "still active"
        print(f"pattern_id={pattern_id} "
              f"rejections={count}/{args.threshold} ({status})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
