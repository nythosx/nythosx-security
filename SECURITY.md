# Security Policy

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer
directly. Do not file a public issue for anything that could be exploited.

## Scope

This tool performs **active security testing**. It is designed to be run only
against targets you own or have **written authorization** to test. The
`roe.yaml` scope file is fail-closed by design: if a host is not listed,
no request is sent.

## Local-only data

The following files and directories contain live credentials, session tokens,
or evidence and are **never** safe to commit, upload, or share:

- `configs/credentials.yaml`
- `configs/targets.yaml`
- `configs/roe.yaml`
- `configs/sessions/`
- `evidence/`
- `findings/`
- `reports/`

These are listed in `.gitignore` and in the pre-commit hook. If you
accidentally commit any of them, rotate every credential they contained
immediately.

## Redaction

All evidence written to disk and all data returned from the web UI and MCP
server passes through `engine/redact.py` first. See that module for the
token patterns and header blocklist.
