"""Shared tool-schema helpers for MCP.

Kept in a leaf module with no mcp import so it can be unit-tested without
requiring the mcp package or an MCP server runtime.
"""


def _type_name(typ):
    if typ is int:
        return "integer"
    if typ is float:
        return "number"
    if typ is bool:
        return "boolean"
    return "string"


def schema_for(tool_fn):
    schema = getattr(tool_fn, "_tool_schema", None) or {}
    props = {}
    required = []
    for name, spec in schema.items():
        if isinstance(spec, tuple) and len(spec) == 2:
            typ, optional = spec
        else:
            typ, optional = spec, False
        props[name] = {"type": _type_name(typ)}
        if not optional:
            required.append(name)
    return {"type": "object", "properties": props, "required": required}


__all__ = ["schema_for"]
