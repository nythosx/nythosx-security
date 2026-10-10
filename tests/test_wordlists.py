from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
WORDLISTS = ROOT / "wordlists"

ADAPTER_WORDLISTS = [
    "paths_laravel", "paths_django", "paths_rails", "paths_nextjs",
    "paths_nuxt", "paths_wordpress", "paths_spring", "paths_graphql",
    "paths_aspnet", "paths_express", "paths_fastapi",
    "weak_passwords_top100",
]


def _lines(name):
    p = WORDLISTS / f"{name}.txt"
    assert p.exists(), f"missing wordlist: {name}"
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]


@pytest.mark.parametrize("name", ADAPTER_WORDLISTS)
def test_wordlist_exists_and_nonempty(name):
    lines = _lines(name)
    assert lines, f"{name} is empty"


@pytest.mark.parametrize("name", ADAPTER_WORDLISTS)
def test_no_duplicates(name):
    lines = _lines(name)
    assert len(lines) == len(set(lines)), f"duplicates in {name}"


@pytest.mark.parametrize("name", ADAPTER_WORDLISTS)
def test_no_whitespace_or_tabs(name):
    for line in _lines(name):
        assert " " not in line, f"space in {name}: {line}"
        assert "\t" not in line, f"tab in {name}: {line}"


def test_adapter_wordlist_names_match_files():
    import yaml
    for adapter in (ROOT / "adapters").glob("*.yaml"):
        data = yaml.safe_load(adapter.read_text(encoding="utf-8")) or {}
        wl = data.get("wordlist")
        if not wl:
            continue
        p = WORDLISTS / f"{wl}.txt"
        assert p.exists(), f"{adapter.name} points to missing {wl}.txt"


def test_paths_lists_start_with_slash():
    for name in ADAPTER_WORDLISTS:
        if not name.startswith("paths_"):
            continue
        for line in _lines(name):
            assert line.startswith("/"), f"{name}: {line}"


def test_weak_password_list_is_curated_not_huge():
    lines = _lines("weak_passwords_top100")
    assert len(lines) <= 120, "weak password list should be curated"
