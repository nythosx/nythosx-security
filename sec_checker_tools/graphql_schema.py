from claude_agent_sdk import tool

from engine import graphql_schema
from engine.config import load_engine
from engine.roe_guard import ROEGuard


@tool(
    "graphql_schema_walk",
    "Reconstruct a GraphQL schema when introspection is disabled by "
    "iteratively sending unknown-field queries and following the "
    "'Did you mean X?' suggestion hints the server returns. Returns the "
    "list of accepted root fields.",
    {"endpoint": str, "max_fields": int},
)
async def tool_graphql_schema(args):
    try:
        guard = ROEGuard(engine_cfg=load_engine())
        r = graphql_schema.scan(
            args["endpoint"],
            max_fields=int(args.get("max_fields") or 40),
            roe_guard=guard)
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"graphql_schema error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
