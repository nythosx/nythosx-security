def test_all_capabilities_dict():
    from engine import registry
    caps = registry.all_capabilities()
    assert isinstance(caps, dict)
    assert len(caps) >= 20


def test_capability_fields():
    from engine import registry
    from engine.contract import Capability
    caps = registry.all_capabilities()
    for name, cap in caps.items():
        assert isinstance(cap, Capability), name
        assert cap.name, name
        assert cap.description, name
        assert cap.category, name
        assert cap.cost in ("low", "medium", "high"), name
        assert isinstance(cap.destructive, bool), name
        assert isinstance(cap.idempotent, bool), name
        assert isinstance(cap.default_on, bool), name


def test_registry_get():
    from engine import registry
    cap = registry.get("sec_scan")
    assert cap is not None
    assert cap.name == "sec_scan"


def test_registry_get_missing():
    from engine import registry
    assert registry.get("does-not-exist") is None


def test_manifest_serializable():
    import json
    from engine import registry
    m = registry.manifest()
    text = json.dumps(m)
    assert "sec_scan" in text


def test_bundles_exist():
    from engine import registry
    b = registry.bundles()
    for key in ("safe", "auth", "recon", "full", "destructive"):
        assert key in b
        assert isinstance(b[key], list)


def test_safe_bundle_excludes_destructive():
    from engine import registry
    safe = registry.get_bundle("safe")
    for name in safe:
        cap = registry.get(name)
        assert not cap.destructive, f"{name} is destructive but in safe bundle"
        assert cap.default_on, f"{name} is default_off but in safe bundle"


def test_destructive_bundle_only_destructive():
    from engine import registry
    dest = registry.get_bundle("destructive")
    for name in dest:
        cap = registry.get(name)
        assert cap.destructive


def test_register_extends_registry():
    from engine import registry
    from engine.contract import Capability
    cap = Capability(name="test_custom_cap", description="custom",
                     category="meta")
    registry.register(cap)
    assert registry.get("test_custom_cap") is not None
    registry.reset()


def test_register_rejects_non_capability():
    from engine import registry
    import pytest
    with pytest.raises(TypeError):
        registry.register({"name": "x"})
