import importlib
import pkgutil
from pathlib import Path

_tools = []


def discover():
    global _tools
    _tools = []
    pkg = Path(__file__).parent
    for info in pkgutil.iter_modules([str(pkg)]):
        if info.name.startswith("_") or info.name == "registry":
            continue
        mod = importlib.import_module(f"sec_checker_tools.{info.name}")
        for attr in dir(mod):
            if attr.startswith("tool_"):
                _tools.append(getattr(mod, attr))
    return _tools


def all_tools():
    if not _tools:
        discover()
    return list(_tools)


def find(name):
    for t in all_tools():
        if t.__name__ == name or getattr(t, "_tool_name", None) == name:
            return t
    return None
