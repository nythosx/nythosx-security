
def test_module_imports():
    from engine import webui_chart
    assert hasattr(webui_chart, "apply")
    assert callable(webui_chart.apply)


def test_apply_is_idempotent():
    from engine import webui_chart
    sample = "<html><head></head><body></body></html>"
    once = webui_chart.apply(sample)
    twice = webui_chart.apply(once)
    assert once.count('id="sc-chart-v1"') == 1
    assert twice.count('id="sc-chart-v1"') == 1
    assert once.count('id="sc-chart-js"') == 1
    assert twice.count('id="sc-chart-js"') == 1


def test_apply_injects_dash_flow():
    from engine import webui_chart
    out = webui_chart.apply("<html><head></head><body></body></html>")
    assert "scDashFlow" in out
    assert "conn-line.active" in out
    assert "stroke-dasharray: 9 7" in out


def test_apply_injects_node_pulse():
    from engine import webui_chart
    out = webui_chart.apply("<html><head></head><body></body></html>")
    assert "scNodePulse" in out
    assert "tool-node.active" in out


def test_apply_injects_brain_pulse_rings():
    from engine import webui_chart
    out = webui_chart.apply("<html><head></head><body></body></html>")
    assert "scBrainPulse" in out
    assert "brain-pulse" in out
    assert "injectPulseRings" in out


def test_apply_injects_query_burst():
    from engine import webui_chart
    out = webui_chart.apply("<html><head></head><body></body></html>")
    assert "sc-ai-queried" in out
    assert "queryBurst" in out


def test_apply_injects_chart_glow():
    from engine import webui_chart
    out = webui_chart.apply("<html><head></head><body></body></html>")
    assert "radial-gradient" in out
    assert "repeating-linear-gradient" in out


def test_apply_handles_non_string():
    from engine import webui_chart
    assert webui_chart.apply(None) is None
    assert webui_chart.apply(b"bytes") == b"bytes"
    assert webui_chart.apply(42) == 42


def test_real_page_has_chart_markers():
    from engine import webui
    assert 'id="sc-chart-v1"' in webui.PAGE
    assert 'id="sc-chart-js"' in webui.PAGE
    assert "scDashFlow" in webui.PAGE
    assert "scNodePulse" in webui.PAGE
    assert "scBrainPulse" in webui.PAGE
    assert "sc-ai-queried" in webui.PAGE


def test_real_page_still_has_prior_markers():
    from engine import webui
    assert 'id="sc-theme-v1"' in webui.PAGE
    assert 'id="sc-llm-v1"' in webui.PAGE
    assert 'id="scDock"' in webui.PAGE
    assert 'id="url"' in webui.PAGE
    assert "window.scLLM" in webui.PAGE
    assert "handleEvent" in webui.PAGE


def test_classic_page_not_touched():
    from engine import webui
    assert 'id="sc-chart-v1"' not in webui.PAGE_CLASSIC
    assert 'id="sc-chart-js"' not in webui.PAGE_CLASSIC
