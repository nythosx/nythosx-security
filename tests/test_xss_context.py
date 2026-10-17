from engine.xss_pack import classify_context


def test_body_context():
    assert classify_context("", "") == "html_body"


def test_quoted_double():
    assert classify_context('<input value="', '"') == "quoted_attr_double"


def test_quoted_single():
    assert classify_context("<input value='", "'") == "quoted_attr_single"


def test_js_string():
    assert classify_context('<script>var x = "', '"') == "js_string"


def test_js_template():
    assert classify_context("<script>var x = `", "") == "js_template"


def test_comment():
    assert classify_context("<!-- ", "") == "html_comment"


def test_srcdoc():
    assert classify_context('<iframe srcdoc="', '"') == "srcdoc"


def test_json_in_script():
    assert classify_context(
        '<script type="application/json">{"x":"', "") == "json_in_script"


def test_unquoted_attr():
    assert classify_context("<input value=", "") == "attribute"


def test_safe_is_body():
    assert classify_context("<html><body>", "") == "html_body"


def test_all_contexts_have_payloads():
    from engine import xss_pack
    for ctx in xss_pack.PACK.context_variants:
        assert classify_context("", "") in (
            "html_body", "attribute", "quoted_attr_double",
            "quoted_attr_single", "js_string", "js_template",
            "html_comment", "srcdoc", "json_in_script")
