"""Full desync exploitation (Tier-3 §1).

  tunnel       -- request tunneling via the confirmed desync primitive
  queue_poison -- self-only response-queue poisoning proof

Both rely on the `desync_surface` fact produced by
engine.parserdiff.boundary_diff, and both are bounded so no third party is
ever affected:

  tunnel       -- max 10 smuggled requests per finding, each carrying a
                  unique marker path under our own control; abort on any
                  500-series cascade
  queue_poison -- max 3 rounds, self-consumed within a single connection,
                  never allowed to serve another user

Client-side desync (browser-based proof) is deferred: it needs a Playwright
browser fixture that is its own phase.
"""
from . import tunnel
from . import queue_poison

__all__ = ["tunnel", "queue_poison"]
