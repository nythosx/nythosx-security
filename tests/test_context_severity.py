from engine import context


def test_escalates_info_to_critical_on_admin_path():
    assert context.context_severity(
        "http://x/api/admin/users", "info") == "critical"


def test_escalates_info_to_high_on_user_path():
    assert context.context_severity("http://x/api/users", "info") == "high"


def test_escalates_info_to_high_on_me():
    assert context.context_severity("http://x/api/me", "info") == "high"


def test_never_downgrades():
    assert context.context_severity("http://x/health", "high") == "high"
    assert context.context_severity("http://x/", "critical") == "critical"


def test_plain_path_unchanged():
    assert context.context_severity("http://x/", "medium") == "medium"


def test_unknown_path_unchanged():
    assert context.context_severity("http://x/something/odd", "low") == "low"


def test_graphql_medium():
    assert context.context_severity("http://x/graphql", "info") == "medium"


def test_low_path_does_not_lower_critical():
    assert context.context_severity("http://x/health", "critical") == "critical"


def test_url_with_query_and_fragment():
    assert context.context_severity(
        "http://x/api/admin/users?page=1#top", "info") == "critical"


def test_malformed_url_safe():
    assert context.context_severity("not-a-url", "low") == "low"


def test_billing_escalates_to_critical():
    assert context.context_severity("http://x/billing", "info") == "critical"


def test_orders_escalates_to_high():
    assert context.context_severity("http://x/api/orders", "info") == "high"


def test_oauth_escalates_to_high():
    assert context.context_severity("http://x/oauth/authorize", "info") == "high"


def test_search_escalates_to_medium():
    assert context.context_severity("http://x/search", "info") == "medium"
