from engine.graph import SurfaceGraph, fields_from_json, fields_from_body


def test_fields_from_json_flat():
    fields = fields_from_json({"id": 1, "name": "x"})
    assert {"id", "name"} <= fields


def test_fields_from_json_nested():
    fields = fields_from_json({"user": {"email": "a", "role": "admin"}})
    assert "user" in fields and "email" in fields and "role" in fields


def test_fields_from_json_list():
    fields = fields_from_json([{"a": 1}, {"b": 2}])
    assert "a" in fields


def test_fields_from_body_json_ct():
    fields = fields_from_body('{"x": 1}', "application/json")
    assert "x" in fields


def test_fields_from_body_json_sniff():
    fields = fields_from_body('{"y": 2}', "")
    assert "y" in fields


def test_fields_from_body_html_empty():
    assert fields_from_body("<html>hi</html>", "text/html") == set()


def test_graph_add_endpoint():
    g = SurfaceGraph()
    g.add_endpoint("http://x/a", status_anon=401, status_auth=200,
                   request_fields=["q"], response_fields=["id", "email"])
    assert g.stats()["endpoints"] == 1
    assert "id" in g.parameters


def test_graph_field_flow_edge():
    g = SurfaceGraph()
    g.add_endpoint("http://x/public", status_anon=200, status_auth=200,
                   response_fields=["user_id"])
    g.add_endpoint("http://x/private", status_anon=401, status_auth=200,
                   request_fields=["user_id"])
    g.build()
    flows = [e for e in g.edges if e["type"] == "field_flow"]
    assert any(e["field"] == "user_id" for e in flows)


def test_graph_sibling_edge():
    g = SurfaceGraph()
    # Same path shape (/api/orders/{id}) but different ids → siblings.
    g.add_endpoint("http://x/api/orders/1", status_anon=401, status_auth=200)
    g.add_endpoint("http://x/api/orders/2", status_anon=401, status_auth=200)
    g.build()
    sibs = [e for e in g.edges if e["type"] == "sibling_resource"]
    assert len(sibs) >= 2


def test_graph_no_siblings_across_different_shapes():
    g = SurfaceGraph()
    g.add_endpoint("http://x/api/orders/1", status_anon=401, status_auth=200)
    g.add_endpoint("http://x/api/invoices/2", status_anon=401, status_auth=200)
    g.build()
    sibs = [e for e in g.edges if e["type"] == "sibling_resource"]
    assert sibs == []


def test_graph_public_sensitive_field():
    g = SurfaceGraph()
    g.add_endpoint("http://x/api/list", status_anon=200,
                   response_fields=["email", "username"])
    g.build()
    pub = [e for e in g.edges if e["type"] == "public_sensitive_field"]
    assert any(e["field"] == "email" for e in pub)


def test_graph_hypotheses():
    g = SurfaceGraph()
    g.add_endpoint("http://x/public", status_anon=200, status_auth=200,
                   response_fields=["user_id"])
    g.add_endpoint("http://x/private", status_anon=401, status_auth=200,
                   request_fields=["user_id"])
    g.build()
    hyps = g.hypotheses()
    kinds = {h["kind"] for h in hyps}
    assert "bola_field_flow" in kinds


def test_graph_to_dict():
    g = SurfaceGraph()
    g.add_endpoint("http://x/a", status_anon=200, response_fields=["id"])
    g.build()
    d = g.to_dict()
    assert "endpoints" in d and "edges" in d and "hypotheses" in d
