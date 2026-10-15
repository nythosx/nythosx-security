"""Phase 7 Part B — Drupal / University-CMS chains.

Chains purpose-built for Drupal-based institutions (the dominant CMS class
among PH universities): /user/{uid} enumeration, REST/JSON:API exposure,
views/ajax endpoints, maintenance endpoints, public file storage, config
leaks, and org-structure recon.

All requests route through engine.http (scope gate + rate limiter). GET-only
probing, hard per-chain request caps, soft-404 fingerprinting before any
flag, and no destructive / brute-force / DoS patterns. URLs are never probed
outside the ROE allowlist.
"""
from .chains import (
    run_all, make_send, soft404_fingerprint,
    user_idor_chain, rest_exposure_chain, views_ajax_chain,
    updatephp_install_chain, file_storage_chain, config_exposure_chain,
    org_recon_chain, USER_IDOR_MAX, FILE_STORAGE_MAX,
)

__all__ = [
    "run_all", "make_send", "soft404_fingerprint",
    "user_idor_chain", "rest_exposure_chain", "views_ajax_chain",
    "updatephp_install_chain", "file_storage_chain", "config_exposure_chain",
    "org_recon_chain", "USER_IDOR_MAX", "FILE_STORAGE_MAX",
]
