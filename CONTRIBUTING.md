# Contributing

## Setup
## Before opening a PR

- `ruff check .`
- `pytest tests/ -q`

## Safety invariants (do not break)

- The ROE guard is fail-closed. If scope is unconfigured or empty, refuse.
- Raw `httpx` usage outside the shared HTTP client is discouraged.
- Destructive capabilities must be `default_on=False` and gated behind an
  explicit opt-in.
- Nothing leaves the process without going through `engine/redact.py`.
