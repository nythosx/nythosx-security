from engine.triage import _token_match, category_from_keys


def test_exact_token_match():
    assert _token_match("user", "user")


def test_token_with_underscore_suffix():
    assert _token_match("user", "user_id")


def test_token_with_underscore_prefix():
    assert _token_match("user", "sys_user")


def test_substring_does_not_match():
    assert not _token_match("user", "username")


def test_substring_symmetric_does_not_match():
    assert not _token_match("username", "user")


def test_category_user_id_sensitive():
    assert category_from_keys(["user_id", "email"]) == "sensitive"


def test_category_title_content():
    assert category_from_keys(["title", "body", "slug"]) == "content"


def test_category_username_not_misclassified_as_user_token():
    cat = category_from_keys(["username"])
    assert cat != "content"


def test_category_empty_keys():
    assert category_from_keys([]) is None
    assert category_from_keys(None) is None
