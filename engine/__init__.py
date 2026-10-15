import sys as _sys

LOAD_ERRORS = []

_MODULES = (
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
)

_MAX_SILENT_FAILURES = 3

for _name in _MODULES:
    try:
        __import__(f"engine.{_name}")
    except Exception as _e:
        _err = f"{_name}: {type(_e).__name__}: {_e}"
        LOAD_ERRORS.append(_err)
        _sys.stderr.write(f"[engine] module {_name!r} failed to import: {_err}\n")

if len(LOAD_ERRORS) > _MAX_SILENT_FAILURES:
    raise RuntimeError(
        f"engine: {len(LOAD_ERRORS)} capability modules failed to import; "
        f"refusing to start with a degraded tool registry. "
        f"Failures: " + "; ".join(LOAD_ERRORS)
    )
