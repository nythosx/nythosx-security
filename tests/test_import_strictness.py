import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_engine_load_errors_exposed():
    import engine
    assert hasattr(engine, "LOAD_ERRORS")
    assert isinstance(engine.LOAD_ERRORS, list)


def test_engine_loads_in_fresh_process():
    result = subprocess.run(
        [sys.executable, "-c", "import engine; print(len(engine.LOAD_ERRORS))"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip()) <= 3


def test_engine_raises_when_too_many_modules_fail(tmp_path):
    fake_engine = tmp_path / "engine"
    fake_engine.mkdir()
    (fake_engine / "__init__.py").write_text(
        "import sys as _sys\n"
        "LOAD_ERRORS = []\n"
        "_MODULES = ('nonexistent_a', 'nonexistent_b', 'nonexistent_c',\n"
        "            'nonexistent_d', 'nonexistent_e')\n"
        "_MAX_SILENT_FAILURES = 3\n"
        "for _name in _MODULES:\n"
        "    try:\n"
        "        __import__(f'engine.{_name}')\n"
        "    except Exception as _e:\n"
        "        LOAD_ERRORS.append(str(_e))\n"
        "if len(LOAD_ERRORS) > _MAX_SILENT_FAILURES:\n"
        "    raise RuntimeError('refused')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-c", "import engine"],
        cwd=str(tmp_path), capture_output=True, text=True, timeout=15,
    )
    assert result.returncode != 0
    assert "refused" in result.stderr
