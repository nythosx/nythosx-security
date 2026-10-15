"""Phase 7 Part A — Deep Injection Surface.

Extends injection coverage beyond single-param reflection:

  structural  — JSON/XML tree mutations (dup keys, type juggling, deep
                nesting, prototype pollution) classified by parser behaviour.
  parserdiff  — re-send accepted payloads with mismatched Content-Type to
                find WAF/parser bypasses.
  graphqlx    — introspection, alias batching, field-suggestion mining,
                mutation discovery on read-only endpoints.
  headersurf  — replay endpoints with mutated routing/trust headers.

Every request routes through engine.http (scope gate + rate limiter). No
DoS / resource-exhaustion patterns: mutations exist to classify parser
behaviour, bounded by hard caps.
"""
from . import structural, parserdiff, graphqlx, headersurf

__all__ = ["structural", "parserdiff", "graphqlx", "headersurf"]
