"""Parser differential exploitation (Tier-2 §1).

The backbone: a finding exists wherever two parsers disagree on the same
bytes. Three submodules:

  boundary_diff    -- frontend (nginx/CDN/LB) vs backend consensus
  bodyparser_diff  -- 8 serializations of the same semantic payload
  charset_diff     -- encoding & Unicode normalization variants

Each module returns a dict in the chain-tool contract:
    {"verdict", "reason", "evidence", "desync_surface" | "divergence"}

`desync_surface` is the fact consumed by Tier-2 Phase 2 (desync exploitation
tunnel) to use confirmed splits instead of blind CL.TE probing.
"""
from . import boundary_diff
from . import bodyparser_diff
from . import charset_diff

__all__ = ["boundary_diff", "bodyparser_diff", "charset_diff"]
