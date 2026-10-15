
def test_module_imports():
    from engine import webui_theme
    assert hasattr(webui_theme, "apply")
    assert callable(webui_theme.apply)


def test_apply_is_idempotent():
    from engine import webui_theme
    sample = (
        "<html><head></head><body>"
        '<button class="btn" id="resetBtn">r</button>'
        '<div class="log-ribbon" id="logRibbon"></div>'
        "</body></html>"
    )
    once = webui_theme.apply(sample)
    twice = webui_theme.apply(once)
    assert once.count('id="sc-theme-v1"') == 1
    assert twice.count('id="sc-theme-v1"') == 1
    assert once.count('id="sc-theme-js"') == 1
    assert twice.count('id="sc-theme-js"') == 1
    assert once.count('id="scDock"') == 1
    assert twice.count('id="scDock"') == 1


def test_apply_inserts_theme_css():
    from engine import webui_theme
    sample = "<html><head></head><body></body></html>"
    out = webui_theme.apply(sample)
    assert "theme-dark" in out
    assert "theme-light" in out
    assert "--ph-line" in out
    assert "--bg: #0a0c10" in out


def test_apply_inserts_header_buttons():
    from engine import webui_theme
    sample = (
        "<html><head></head><body>"
        '<button class="btn" id="resetBtn">r</button>'
        "</body></html>"
    )
    out = webui_theme.apply(sample)
    assert "scThemeBtn" in out
    assert "scDockBtn" in out
    assert "scSideBtn" in out


def test_apply_inserts_dock():
    from engine import webui_theme
    sample = (
        "<html><head></head><body>"
        '<div class="log-ribbon" id="logRibbon"></div>'
        "</body></html>"
    )
    out = webui_theme.apply(sample)
    assert "scDockChev" in out
    assert "NARRATOR" in out
    assert "CONSOLE" in out
    assert "FINDINGS" in out
    assert out.count('id="logRibbon"') == 1


def test_apply_sets_body_class():
    from engine import webui_theme
    sample = "<html><head></head><body></body></html>"
    out = webui_theme.apply(sample)
    assert '<body class="theme-dark">' in out


def test_real_page_has_theme():
    from engine import webui
    assert 'id="sc-theme-v1"' in webui.PAGE
    assert 'id="sc-theme-js"' in webui.PAGE
    assert "theme-dark" in webui.PAGE
    assert "scThemeBtn" in webui.PAGE
    assert "scDock" in webui.PAGE
    assert '<body class="theme-dark">' in webui.PAGE


def test_real_page_still_has_scan_ui():
    from engine import webui
    assert 'id="url"' in webui.PAGE
    assert "Analyze" in webui.PAGE
    assert "handleEvent" in webui.PAGE
    assert "EventSource" in webui.PAGE
    assert 'id="resetBtn"' in webui.PAGE
    assert 'id="logRibbon"' in webui.PAGE


def test_classic_page_not_themed():
    from engine import webui
    assert 'id="sc-theme-v1"' not in webui.PAGE_CLASSIC
    assert '<body class="theme-dark">' not in webui.PAGE_CLASSIC


def test_apply_handles_non_string():
    from engine import webui_theme
    assert webui_theme.apply(None) is None
    assert webui_theme.apply(b"bytes") == b"bytes"
    assert webui_theme.apply(42) == 42
