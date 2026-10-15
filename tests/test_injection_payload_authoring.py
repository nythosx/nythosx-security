from engine.injection import ssti, xxe, crlf, nosql
from engine.injection.payloads import (SSTI_PAYLOADS, XXE_FILE_PAYLOADS,
                                        CRLF_PAYLOADS, NOSQL_PAYLOADS)
from engine import llm_service


def _noai(monkeypatch):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: None)


def _ai(monkeypatch, payload):
    monkeypatch.setattr(llm_service, "get_client",
                        lambda capability=None, cfg=None: (lambda p: payload))


def test_ssti_noai_is_base(monkeypatch):
    _noai(monkeypatch)
    assert ssti._augmented_ssti_payloads("http://t") == list(SSTI_PAYLOADS)


def test_ssti_ai_valid_only(monkeypatch):
    _ai(monkeypatch,
        '[{"expr":"@{7*7}","marker":"49","engine":"blade"},{"bad":1}]')
    out = ssti._augmented_ssti_payloads("http://t")
    assert out[0] == ("@{7*7}", "49", "blade")
    assert len(out) == len(SSTI_PAYLOADS) + 1


def test_xxe_noai_is_base(monkeypatch):
    _noai(monkeypatch)
    assert xxe._augmented_xxe_paths("http://t") == list(XXE_FILE_PAYLOADS)


def test_xxe_ai_path_validated(monkeypatch):
    _ai(monkeypatch,
        '[{"path":"/etc/shadow","marker":"root:","label":"x"},{"path":"nope"}]')
    out = xxe._augmented_xxe_paths("http://t")
    assert out[0][0] == "/etc/shadow"
    assert len(out) == len(XXE_FILE_PAYLOADS) + 1


def test_crlf_noai_is_base(monkeypatch):
    _noai(monkeypatch)
    assert crlf._augmented_crlf_payloads("http://t") == list(CRLF_PAYLOADS)


def test_crlf_ai_marker_filtered(monkeypatch):
    _ai(monkeypatch,
        '["%0d%0aX-Injected: payload-v2","%0d%0aX-Other: y"]')
    out = crlf._augmented_crlf_payloads("http://t")
    assert out[0][1] == "%0d%0aX-Injected: payload-v2"
    assert len(out) == len(CRLF_PAYLOADS) + 1


def test_nosql_noai_is_base(monkeypatch):
    _noai(monkeypatch)
    assert nosql._augmented_nosql_payloads("http://t") == list(NOSQL_PAYLOADS)


def test_nosql_ai_dict_validated(monkeypatch):
    _ai(monkeypatch,
        '[{"label":"regex2","op":{"$regex":"^a"}},{"label":"bad","op":{"noop":1}}]')
    out = nosql._augmented_nosql_payloads("http://t")
    assert out[0] == ("regex2", {"$regex": "^a"})
    assert len(out) == len(NOSQL_PAYLOADS) + 1
