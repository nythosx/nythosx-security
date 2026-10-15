import re
from typing import Optional


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}

_AV2 = {"L": 0.395, "A": 0.646, "N": 1.0}
_AC2 = {"H": 0.35, "M": 0.61, "L": 0.71}
_AU2 = {"M": 0.45, "S": 0.56, "N": 0.704}
_CIA2 = {"N": 0.0, "P": 0.275, "C": 0.660}

_SEVERITY_BANDS = (
    (0.0, 0.1, "none"),
    (0.1, 4.0, "low"),
    (4.0, 7.0, "medium"),
    (7.0, 9.0, "high"),
    (9.0, 10.1, "critical"),
)

_METRIC_RE = re.compile(r"([A-Za-z]{1,4}):([A-Za-z])")


def cvss_vector_to_score(vector):
    if not vector:
        return None
    v = str(vector).strip()
    if not v:
        return None
    if v.startswith("CVSS:3.1/") or v.startswith("CVSS:3.0/"):
        return _parse_v3(v)
    if v.startswith("CVSS:2.0/"):
        return _parse_v2(v)
    if "Au:" in v:
        return _parse_v2(v)
    if any(m in v for m in ("PR:", "UI:", "S:")):
        return _parse_v3(v)
    r = _parse_v3(v)
    if r is not None:
        return r
    return _parse_v2(v)


def _parse_v3(vector):
    metrics = dict(_METRIC_RE.findall(vector))
    av = metrics.get("AV")
    ac = metrics.get("AC")
    pr = metrics.get("PR")
    ui = metrics.get("UI")
    scope = metrics.get("S")
    c = metrics.get("C")
    i = metrics.get("I")
    a = metrics.get("A")
    if not all((av, ac, pr, ui, scope, c, i, a)):
        return None
    try:
        av_val = _AV[av]
        ac_val = _AC[ac]
        pr_val = _PR_U[pr] if scope == "U" else _PR_C[pr]
        ui_val = _UI[ui]
        c_val = _CIA[c]
        i_val = _CIA[i]
        a_val = _CIA[a]
    except KeyError:
        return None

    iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if scope == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    return round(_round_up(raw), 1)


def _round_up(value):
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int(int_input / 10000) + 1) / 10.0


def _parse_v2(vector):
    metrics = dict(_METRIC_RE.findall(vector))
    av = metrics.get("AV")
    ac = metrics.get("AC")
    au = metrics.get("Au")
    c = metrics.get("C")
    i = metrics.get("I")
    a = metrics.get("A")
    if not all((av, ac, au, c, i, a)):
        return None
    av_val = _AV2.get(av)
    ac_val = _AC2.get(ac)
    au_val = _AU2.get(au)
    c_val = _CIA2.get(c)
    i_val = _CIA2.get(i)
    a_val = _CIA2.get(a)
    if None in (av_val, ac_val, au_val, c_val, i_val, a_val):
        return None

    impact = 10.41 * (1 - (1 - c_val) * (1 - i_val) * (1 - a_val))
    exploitability = 20 * av_val * ac_val * au_val
    f_impact = 0.0 if impact == 0 else 1.176

    raw = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return round(raw, 1)


def score_to_severity(score):
    if score is None:
        return "unknown"
    for lo, hi, sev in _SEVERITY_BANDS:
        if lo <= score < hi:
            return sev
    return "unknown"


__all__ = ["cvss_vector_to_score", "score_to_severity"]
