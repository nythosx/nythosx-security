import pytest

from engine.util import (
    ProbeOutcome,
    any_handler_reached,
    classify_probe_outcome,
    is_reflection,
    matches_hostname,
    response_is_success,
)


def test_outcome_2xx_handler_reached():
    assert classify_probe_outcome(200) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(201) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(204) is ProbeOutcome.HANDLER_REACHED


def test_outcome_3xx_handler_reached():
    assert classify_probe_outcome(301) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(302) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(308) is ProbeOutcome.HANDLER_REACHED


def test_outcome_404_not_reached():
    assert classify_probe_outcome(404) is ProbeOutcome.NOT_FOUND
    assert classify_probe_outcome(410) is ProbeOutcome.NOT_FOUND


def test_outcome_405_501_method_rejected():
    assert classify_probe_outcome(405) is ProbeOutcome.METHOD_REJECTED
    assert classify_probe_outcome(501) is ProbeOutcome.METHOD_REJECTED


def test_outcome_5xx_server_error():
    assert classify_probe_outcome(500) is ProbeOutcome.SERVER_ERROR
    assert classify_probe_outcome(502) is ProbeOutcome.SERVER_ERROR
    assert classify_probe_outcome(503) is ProbeOutcome.SERVER_ERROR
    assert classify_probe_outcome(599) is ProbeOutcome.SERVER_ERROR


def test_outcome_4xx_other_reached():
    assert classify_probe_outcome(400) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(401) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(403) is ProbeOutcome.HANDLER_REACHED
    assert classify_probe_outcome(422) is ProbeOutcome.HANDLER_REACHED


def test_outcome_unreachable():
    assert classify_probe_outcome(None) is ProbeOutcome.UNREACHABLE
    assert classify_probe_outcome(None, "timeout") is ProbeOutcome.UNREACHABLE
    assert classify_probe_outcome(200, "refused") is ProbeOutcome.UNREACHABLE


def test_any_handler_reached_true():
    attempts = [{"status": 404}, {"status": 200}, {"status": 404}]
    assert any_handler_reached(attempts)


def test_any_handler_reached_false():
    attempts = [{"status": 404}, {"status": 404}, {"status": None, "error": "timeout"}]
    assert not any_handler_reached(attempts)


def test_matches_hostname_exact():
    assert matches_hostname("attacker.example.com",
                            "https://attacker.example.com/x")


def test_matches_hostname_subdomain():
    assert matches_hostname("attacker.example.com",
                            "https://sub.attacker.example.com/x")


def test_matches_hostname_not_suffix():
    assert not matches_hostname("attacker.example.com",
                                "https://notattacker.example.com/")


def test_matches_hostname_bare():
    assert matches_hostname("attacker.example.com", "attacker.example.com")


def test_matches_hostname_empty():
    assert not matches_hostname("", "x")
    assert not matches_hostname("x", "")


def test_matches_hostname_with_port():
    assert matches_hostname("attacker.example.com",
                            "https://attacker.example.com:8443/x")


def test_reflection_verbatim():
    assert is_reflection("prefix UNION SELECT marker suffix",
                         "UNION SELECT marker")


def test_reflection_absent():
    assert not is_reflection("nothing here", "UNION SELECT marker")


def test_reflection_empty():
    assert not is_reflection("", "x")
    assert not is_reflection("x", "")


def test_success_true():
    assert response_is_success('{"ok": true}')


def test_success_nested_error():
    assert not response_is_success('{"data": {"error": "nope"}}')


def test_success_deep_error():
    assert not response_is_success('{"a": {"b": {"c": {"error": "x"}}}}')


def test_success_false_flag():
    assert not response_is_success('{"success": false}')


def test_success_status_error():
    assert not response_is_success('{"status": "error"}')


def test_success_status_500():
    assert not response_is_success('{"status": 500}')


def test_success_garbage():
    assert not response_is_success("not json")


def test_success_empty():
    assert not response_is_success("")


def test_success_array():
    assert response_is_success('[{"id": 1}, {"id": 2}]')


def test_success_array_with_error():
    assert not response_is_success('[{"id": 1}, {"error": "x"}]')


def test_success_depth_bound():
    nested = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"error": "x"}}}}}}}}
    import json as _json
    assert response_is_success(_json.dumps(nested))
