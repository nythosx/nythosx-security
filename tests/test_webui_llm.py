
def test_module_imports():
    from engine import webui_llm
    assert hasattr(webui_llm, "apply")
    assert callable(webui_llm.apply)


def test_apply_is_idempotent():
    from engine import webui_llm
    sample = (
        "<html><head></head><body>"
        '<div class="findings-list" id="findingsList"></div>'
        "<script>handleEvent(ev);</script>"
        "</body></html>"
    )
    once = webui_llm.apply(sample)
    twice = webui_llm.apply(once)
    assert once.count('id="sc-llm-v1"') == 1
    assert twice.count('id="sc-llm-v1"') == 1
    assert once.count('id="sc-llm-js"') == 1
    assert twice.count('id="sc-llm-js"') == 1
    assert once.count('id="scAiStatus"') == 1
    assert twice.count('id="scAiStatus"') == 1


def test_apply_injects_css():
    from engine import webui_llm
    sample = "<html><head></head><body></body></html>"
    out = webui_llm.apply(sample)
    assert "sc-ai-panel" in out
    assert "sc-cap-chip" in out
    assert "sc-trace-log" in out
    assert "sc-flash-vuln" in out
    assert "sc-data-label" in out
    assert "#transcript .tr.sub" in out


def test_apply_injects_ai_panel():
    from engine import webui_llm
    sample = (
        "<html><head></head><body>"
        '<div class="findings-list" id="findingsList"></div>'
        "</body></html>"
    )
    out = webui_llm.apply(sample)
    assert "scAiStatus" in out
    assert "scAiLabel" in out
    assert "scAiSub" in out
    assert "scTraceLog" in out
    assert 'data-cap="payload_author"' in out
    assert 'data-cap="bundle_analyst"' in out
    assert 'data-cap="response_triage"' in out
    assert 'data-cap="chain_synth"' in out
    assert 'data-cap="exploit_plan"' in out
    assert 'data-cap="narrative"' in out


def test_apply_injects_sse_hook():
    from engine import webui_llm
    sample = (
        "<html><head></head><body>"
        "<script>handleEvent(ev);</script>"
        "</body></html>"
    )
    out = webui_llm.apply(sample)
    assert "scLLM.onEvent" in out
    assert "handleEvent(ev);" in out


def test_apply_injects_js():
    from engine import webui_llm
    sample = "<html><head></head><body></body></html>"
    out = webui_llm.apply(sample)
    assert "window.scLLM" in out
    assert "trStep" in out
    assert "trSub" in out
    assert "trSummary" in out
    assert "appendTrace" in out
    assert "bumpCap" in out
    assert "setAIPanel" in out
    assert "setAIState" in out
    assert "showLabel" in out
    assert "flash" in out


def test_apply_handles_non_string():
    from engine import webui_llm
    assert webui_llm.apply(None) is None
    assert webui_llm.apply(b"bytes") == b"bytes"
    assert webui_llm.apply(42) == 42


def test_apply_missing_anchors_is_safe():
    from engine import webui_llm
    sample = "<html><head></head><body>no anchors here</body></html>"
    out = webui_llm.apply(sample)
    assert 'id="sc-llm-v1"' in out
    assert 'id="sc-llm-js"' in out
    assert 'id="scAiStatus"' not in out
    assert "scLLM.onEvent" not in out


def test_real_page_has_llm_markers():
    from engine import webui
    assert 'id="sc-llm-v1"' in webui.PAGE
    assert 'id="sc-llm-js"' in webui.PAGE
    assert "window.scLLM" in webui.PAGE
    assert "scAiStatus" in webui.PAGE


def test_real_page_still_has_base_markers():
    from engine import webui
    assert 'id="sc-theme-v1"' in webui.PAGE
    assert 'id="scDock"' in webui.PAGE
    assert 'id="url"' in webui.PAGE
    assert 'id="logRibbon"' in webui.PAGE
    assert "handleEvent" in webui.PAGE
    assert "EventSource" in webui.PAGE


def test_classic_page_not_touched():
    from engine import webui
    assert 'id="sc-llm-v1"' not in webui.PAGE_CLASSIC
    assert 'id="sc-llm-js"' not in webui.PAGE_CLASSIC
    assert "window.scLLM" not in webui.PAGE_CLASSIC


def test_js_queries_ai_status_endpoint():
    from engine import webui_llm
    assert "/api/ai_status" in webui_llm._JS
    assert "checkAIStatus" in webui_llm._JS
    assert webui_llm._JS.count("checkAIStatus()") >= 1


def test_js_does_not_hardcode_offline_as_final_state():
    from engine import webui_llm
    assert "s.configured" in webui_llm._JS
    assert "AI ONLINE" in webui_llm._JS
    assert "s.provider" in webui_llm._JS
    assert "s.model" in webui_llm._JS
