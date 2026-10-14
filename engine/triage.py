from __future__ import annotations

import re
from urllib.parse import urlparse


CATEGORY_KEYWORDS = [
    ("sensitive", ("setting", "config", "user", "account", "admin", "role",
                   "permission", "auth", "password", "token", "secret", "key",
                   "payment", "order", "invoice", "customer", "billing",
                   "profile", "session", "credential")),
    ("content", ("project", "article", "post", "page", "service",
                 "certification", "education", "experience", "technology",
                 "case-stud", "portfolio", "blog", "product", "review",
                 "comment", "media", "upload", "gallery")),
    ("form", ("form", "contact", "testimonial", "subscribe", "newsletter",
              "feedback", "lead", "signup", "sign-up", "waitlist", "inquiry",
              "apply", "support")),
    ("telemetry", ("analytic", "telemetry", "track", "beacon", "event",
                   "metric", "stat", "view", "visit", "engaged", "impression",
                   "click", "ping", "heartbeat")),
]

WRITE_SEVERITY = {
    "sensitive": ("CRITICAL",
                  "Unauth write to a sensitive/config/account resource. Require authentication AND per-object authorization before any mutation."),
    "content": ("HIGH",
                "Unauth write to a content resource. Require authentication for create/update/delete; a visitor should never modify site content."),
    "form": ("LOW",
             "Public form submission is expected. Enforce a strict body schema (reject unknown fields), add anti-spam (CAPTCHA) and per-IP rate limiting."),
    "telemetry": ("LOW",
                  "Public telemetry is expected. Enforce a strict body schema and per-IP rate limiting to prevent analytics poisoning/flooding."),
    "unknown": ("MEDIUM",
                "Unauth write to an unclassified endpoint. Verify manually whether anonymous writes are intended."),
}

BY_DESIGN_CATEGORIES = ("telemetry", "form")

KEY_CATEGORY_HINTS = [
    ("sensitive", ("email", "password", "passwd", "token", "secret", "apikey",
                   "api_key", "ssn", "iban", "card", "cvv", "pan", "account",
                   "balance", "dob", "phone", "address", "role", "permission",
                   "isadmin", "is_admin", "owner", "userid", "user_id",
                   "sessionid", "session_id", "ip", "credential")),
    ("content", ("title", "slug", "body", "content", "excerpt", "coverimage",
                 "published", "author", "category", "tags", "description",
                 "image", "thumbnail")),
    ("telemetry", ("event", "visit", "pageview", "referrer", "useragent",
                   "user_agent", "duration", "timestamp", "metric", "count")),
]


def _norm(k):
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def category_from_keys(keys):
    if not keys:
        return None
    norm = {_norm(k) for k in keys}
    scores = {}
    for category, hints in KEY_CATEGORY_HINTS:
        hits = sum(1 for h in hints if any(h in n or n in h for n in norm))
        if hits:
            scores[category] = hits
    if not scores:
        return None
    return max(scores, key=scores.get)


def classify_detailed(url_or_path, sample_keys=None):
    path = _path_of(url_or_path).lower()
    path_cat = None
    for category, keywords in CATEGORY_KEYWORDS:
        if any(k in path for k in keywords):
            path_cat = category
            break
    shape_cat = category_from_keys(sample_keys)
    if path_cat and shape_cat:
        if path_cat == shape_cat:
            return {"category": path_cat, "confidence": "high", "basis": "path+shape"}
        return {"category": path_cat, "confidence": "medium", "basis": "path (shape disagrees)"}
    if path_cat:
        return {"category": path_cat, "confidence": "medium", "basis": "path"}
    if shape_cat:
        return {"category": shape_cat, "confidence": "medium", "basis": "shape"}
    return {"category": "unknown", "confidence": "low", "basis": "none"}


def _path_of(url_or_path):
    s = str(url_or_path or "")
    if "://" in s:
        return urlparse(s).path or "/"
    return s


def classify_endpoint(url_or_path, sample_keys=None):
    return classify_detailed(url_or_path, sample_keys)["category"]


def classify_write(url_or_path, sample_keys=None, reflected=None):
    det = classify_detailed(url_or_path, sample_keys)
    category = det["category"]
    severity, recommendation = WRITE_SEVERITY[category]
    confidence = det["confidence"]
    if reflected is True:
        confidence = "high"
    elif reflected is False and confidence == "high":
        confidence = "medium"
    return {
        "category": category,
        "severity": severity,
        "recommendation": recommendation,
        "accepts_unknown_fields": True,
        "confidence": confidence,
        "basis": det["basis"],
        "reflected": reflected,
    }


def triage_finding(url_or_path, verdict=None, pattern_id=None, sample_keys=None):
    det = classify_detailed(url_or_path, sample_keys)
    category = det["category"]
    by_design = category in BY_DESIGN_CATEGORIES
    severity, recommendation = WRITE_SEVERITY[category]
    note = None
    if by_design:
        note = ("endpoint is public-by-design (" + category
                + "); verify this finding is a real authz gap, not expected behaviour")
    return {
        "category": category,
        "severity_hint": severity,
        "by_design": by_design,
        "recommendation": recommendation,
        "note": note,
        "confidence": det["confidence"],
        "basis": det["basis"],
    }


__all__ = [
    "classify_endpoint", "classify_write", "triage_finding",
    "CATEGORY_KEYWORDS", "WRITE_SEVERITY", "BY_DESIGN_CATEGORIES",
]
