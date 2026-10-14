"""SEC-CHECKER engine package.

Importing engine triggers registration of the banking capability
modules so their tool handlers are available to ChainOrchestrator
without any edit to chain_engine.py.
"""

for _name in (
    "banking_recon",
    "data_extractor",
    "unauth_exposure",
    "bola_scanner",
    "rate_limit_bypass",
    "blind_extract",
    "xxe_harvest",
    "ssrf_harvest",
    "ssti_harvest",
    "mcp_security",
    "session_fixation",
    "postmessage_probe",
    "ci_cd_probe",
    "npmrc_probe",
    "firebase_probe",
    "oracles_phase4",
    "graphql_schema",
    "llm_security",
):
    try:
        __import__(f"engine.{_name}")
    except Exception as _e:
        import sys as _sys
        _sys.stderr.write(
            f"[engine] optional module {_name!r} failed to import: "
            f"{type(_e).__name__}: {_e}\n")
