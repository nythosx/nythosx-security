from claude_agent_sdk import tool

from engine import cloud_storage


@tool(
    "cloud_storage_enum",
    "Enumerate cloud storage buckets derived from a domain. Generates ~25 "
    "candidate names (base, base-backup, base-prod, base-dev, base-assets, "
    "etc.) and probes S3, GCS, and Azure. Classifies each as public "
    "(listable), private, or available (registerable).",
    {"domain": str},
)
async def tool_cloud_storage(args):
    try:
        r = cloud_storage.scan(args["domain"])
    except Exception as e:
        return {"content": [{"type": "text",
                             "text": f"cloud_storage error: {type(e).__name__}: {e}"}],
                "isError": True}
    return {"content": [{"type": "text",
                         "text": f"{r['verdict']}: {r.reason}"}],
            "structuredContent": r.to_dict()}
