import asyncio


def _get_handler(tool_obj):
    for name in ("handler", "call", "run", "invoke", "fn", "func",
                 "__call__"):
        h = getattr(tool_obj, name, None)
        if callable(h):
            return h
    if callable(tool_obj):
        return tool_obj
    raise TypeError(
        "cannot extract handler from %s" % type(tool_obj).__name__)


def _invoke(args):
    from sec_checker_tools import approval as mod
    tool_obj = mod.tool_sec_requires_approval
    handler = _get_handler(tool_obj)
    result = handler(args)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result


def test_missing_capability_errors():
    r = _invoke({})
    assert r.get("isError") is True


def test_unknown_capability_no_approval():
    from engine import registry
    registry.reset()
    r = _invoke({"capability": "zzz_unknown_zzz"})
    assert r["structuredContent"]["required"] is False


def test_non_destructive_capability_no_approval():
    from engine import registry
    registry.reset()
    r = _invoke({"capability": "sec_route",
                  "url": "https://x.test/api/v1/x"})
    assert r["structuredContent"]["required"] is False


def test_destructive_capability_requires_approval():
    from engine import registry
    registry.reset()
    r = _invoke({"capability": "upload_scan",
                  "url": "https://x.test/anything"})
    assert r["structuredContent"]["required"] is True


def test_destructive_in_scoped_path_requires_approval():
    from engine import registry
    registry.reset()
    r = _invoke({"capability": "race_scan",
                  "url": "https://x.test/api/v1/cart"})
    assert r["structuredContent"]["required"] is True


def test_destructive_out_of_scoped_path_no_approval():
    from engine import registry
    registry.reset()
    r = _invoke({"capability": "race_scan",
                  "url": "https://x.test/public"})
    assert r["structuredContent"]["required"] is False


def test_output_text_format():
    from engine import registry
    registry.reset()
    r = _invoke({"capability": "upload_scan",
                  "url": "https://x.test/x"})
    assert r["content"][0]["text"] == "requires_approval=true"


def test_handler_extraction_finds_something():
    from sec_checker_tools import approval as mod
    h = _get_handler(mod.tool_sec_requires_approval)
    assert callable(h)
