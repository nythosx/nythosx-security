def test_discovery_budget_dead_is_budget_is_dead():
    from engine import discovery, budget
    assert discovery._budget_dead is budget.is_dead


def test_banking_recon_budget_dead_is_budget_is_dead():
    from engine import banking_recon, budget
    assert banking_recon._budget_dead is budget.is_dead


def test_unauth_exposure_budget_dead_is_budget_is_dead():
    from engine import unauth_exposure, budget
    assert unauth_exposure._budget_dead is budget.is_dead


def test_route_enum_budget_dead_is_budget_is_dead():
    from engine import route_enum, budget
    assert route_enum._budget_dead is budget.is_dead


def test_budget_is_dead_no_reason_returns_false():
    from engine import budget
    budget.configure()
    assert budget.is_dead() is False


def test_budget_is_dead_reflects_exhausted_state():
    from engine import budget
    try:
        budget.configure(max_requests=1, max_per_host=None,
                         max_duration_seconds=None)
        try:
            budget.record("http://x.test")
            budget.record("http://x.test")
        except Exception:
            pass
        assert budget.is_dead() is True
    finally:
        budget.configure()


def test_budget_disable_then_re_enable_cycle():
    from engine import budget
    budget.configure()
    budget.disable()
    budget.enable()
    assert budget.is_dead() is False
    budget.configure()
