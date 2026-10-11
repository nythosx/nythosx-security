"""Inline SVG rendering of attack chains for HTML reports."""
import html


VERDICT_COLORS = {
    "VULNERABLE": "#f85149",
    "SUSPICIOUS": "#d29922",
    "PASS": "#3fb950",
    "UNKNOWN": "#8d949e",
}

CHAIN_VERDICT_STROKE = {
    "CONFIRMED": "#f85149",
    "LIKELY": "#d29922",
    "THEORETICAL": "#58a6ff",
    "INCOMPLETE": "#30363d",
}


def _esc(s):
    return html.escape(str(s or ""))


def render_chain_svg(chains, width=1100, box_w=160, box_h=48,
                     gap_x=36, gap_y=18, padding=24):
    """Return an inline <svg> string. Empty string if no chains."""
    if not chains:
        return ""
    rows = []
    y = padding
    max_x = 0
    for c in chains:
        matched = c.get("matched") or []
        steps = matched or [{"pattern_id": "(no matches)",
                             "verdict": "UNKNOWN"}]
        stroke = CHAIN_VERDICT_STROKE.get(c.get("verdict", ""), "#30363d")
        rows.append(
            f'<rect x="{padding - 8}" y="{y - 6}" '
            f'width="{len(steps) * (box_w + gap_x) + 16}" '
            f'height="{box_h + 24}" fill="transparent" '
            f'stroke="{stroke}" stroke-width="1" rx="8" '
            f'stroke-dasharray="3 3"/>'
        )
        rows.append(
            f'<text x="{padding}" y="{y + 12}" fill="#8b949e" '
            f'font-family="monospace" font-size="11">'
            f'{_esc(c.get("name", c.get("id", "chain")))} — '
            f'{_esc(c.get("verdict", "UNKNOWN"))}</text>'
        )
        bx = padding
        by = y + 24
        for i, s in enumerate(steps):
            v = s.get("verdict", "UNKNOWN")
            color = VERDICT_COLORS.get(v, "#8d949e")
            pid = s.get("pattern_id") or s.get("id") or "?"
            rows.append(
                f'<rect x="{bx}" y="{by}" width="{box_w}" '
                f'height="{box_h}" rx="6" fill="#161b22" '
                f'stroke="{color}" stroke-width="1.5"/>'
            )
            rows.append(
                f'<text x="{bx + 10}" y="{by + 20}" fill="#e6edf3" '
                f'font-family="monospace" font-size="11">'
                f'{_esc(pid)[:22]}</text>'
            )
            rows.append(
                f'<text x="{bx + 10}" y="{by + 38}" fill="{color}" '
                f'font-family="monospace" font-size="10">'
                f'{_esc(v)}</text>'
            )
            max_x = max(max_x, bx + box_w)
            if i < len(steps) - 1:
                ax1 = bx + box_w
                ax2 = bx + box_w + gap_x
                ay = by + box_h / 2
                rows.append(
                    f'<line x1="{ax1}" y1="{ay}" x2="{ax2 - 6}" '
                    f'y2="{ay}" stroke="#8b949e" stroke-width="1"/>'
                )
                rows.append(
                    f'<polygon points="{ax2 - 6},{ay - 4} {ax2},{ay} '
                    f'{ax2 - 6},{ay + 4}" fill="#8b949e"/>'
                )
            bx += box_w + gap_x
        y += box_h + gap_y + 34
    total_h = y + padding
    total_w = max(width, max_x + padding * 2)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {total_w} {total_h}" width="100%" '
        f'style="background:#0d1117;border-radius:8px;">'
        + "".join(rows) + '</svg>'
    )


__all__ = ["render_chain_svg", "VERDICT_COLORS", "CHAIN_VERDICT_STROKE"]
