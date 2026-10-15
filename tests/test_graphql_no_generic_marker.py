from engine.graphql_security import GRAPHQL_ERROR_SIGNATURES, _looks_like_graphql_errors


def test_generic_word_removed():
    assert "graphql" not in GRAPHQL_ERROR_SIGNATURES


def test_specific_signatures_kept():
    assert "cannot query field" in GRAPHQL_ERROR_SIGNATURES
    assert "unknown field" in GRAPHQL_ERROR_SIGNATURES
    assert "field '" in GRAPHQL_ERROR_SIGNATURES


def test_plain_text_graphql_word_is_not_an_error_list():
    assert not _looks_like_graphql_errors(["this is a graphql page"])


def test_string_error_not_a_list():
    assert not _looks_like_graphql_errors("graphql")
    assert not _looks_like_graphql_errors(None)


def test_real_graphql_error_still_matches():
    errors = [{"message": "Cannot query field 'x' on type 'Query'"},]
    assert _looks_like_graphql_errors(errors)


def test_error_with_location_metadata_matches():
    errors = [{"message": "syntax error",
               "locations": [{"line": 1, "column": 1}]}]
    assert _looks_like_graphql_errors(errors)
