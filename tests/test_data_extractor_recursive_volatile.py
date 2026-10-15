from engine.data_extractor import _row_hash


def test_top_level_volatile_stripped():
    a = {"id": 1, "name": "x", "updated_at": "2026-01-01"}
    b = {"id": 1, "name": "x", "updated_at": "2026-10-15"}
    assert _row_hash(a) == _row_hash(b)


def test_nested_volatile_stripped():
    a = {"id": 1, "meta": {"updated_at": "2026-01-01", "x": 1}}
    b = {"id": 1, "meta": {"updated_at": "2026-10-15", "x": 1}}
    assert _row_hash(a) == _row_hash(b)


def test_deeply_nested_volatile_stripped():
    a = {"id": 1, "meta": {"inner": {"modified_at": "2026-01-01"}}}
    b = {"id": 1, "meta": {"inner": {"modified_at": "2026-10-15"}}}
    assert _row_hash(a) == _row_hash(b)


def test_volatile_in_list_stripped():
    a = {"id": 1, "items": [{"ts": 1, "v": "x"}]}
    b = {"id": 1, "items": [{"ts": 2, "v": "x"}]}
    assert _row_hash(a) == _row_hash(b)


def test_different_real_fields_produce_different_hashes():
    a = {"name": "alice", "total": 100}
    b = {"name": "bob", "total": 100}
    assert _row_hash(a) != _row_hash(b)


def test_stable_id_overrides_content_changes():
    a = {"id": 1, "name": "alice"}
    b = {"id": 1, "name": "bob"}
    assert _row_hash(a) == _row_hash(b)


def test_different_stable_ids_produce_different_hashes():
    a = {"id": 1, "name": "x"}
    b = {"id": 2, "name": "x"}
    assert _row_hash(a) != _row_hash(b)


def test_stable_id_short_circuits():
    a = {"id": 42, "updated_at": "x"}
    b = {"id": 42, "updated_at": "y"}
    assert _row_hash(a) == _row_hash(b)
