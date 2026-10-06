raise ImportError(
    "engine.session is deprecated and unused. "
    "Use engine.auth_flow + engine.config.save_session/load_session instead."
)
