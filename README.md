# Titanium Repo Operator

Titanium Repo Operator is an async-first MCP server that provides atomic, auditable repo operations for autonomous coding agents. Tested, CI-enforced, reproducible run.

## Quickstart
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
make test
make run
```

## Expected output
```text
EVAL RESULTS
smoke: pass (12.34ms)
tool_contract: pass (20.11ms)
atomic_write: pass (3.42ms)
checks_passed: 3/3
safe_commands: 5
```

## Evaluation
Run the evaluation suite:
```bash
make eval
```

| Metric | Command | Expected |
| --- | --- | --- |
| Eval pass rate | `make eval` | 3/3 (100%) |
| SAFE_COMMANDS count | `make eval` | 5 |

## Evidence of correctness
`make eval` includes lightweight checks for tool contract compliance and atomic writes.

| Check | Signal | Example result |
| --- | --- | --- |
| Tool contract compliance | All expected tools registered; schemas generated | pass, <25ms |
| Forbidden path rejection | `validate_path("../forbidden")` raises | pass, <5ms |
| Atomic write guarantees | content matches latest, no temp files | pass, <5ms |

## Quick start (dev)
1. Install `uv` (PEP-723 runner) if you want the single-file dev experience.
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Run the server locally (it will create a cached venv from the `# /// script` header in `server.py`):
```bash
uv run server.py
```

3. To register with Claude Code (dev local stdio):
```bash
claude mcp add titanium -- uv run --with fastmcp --with gitpython /path/to/server.py
```

## Production notes
- Use the included `Dockerfile` to build a container image.
- Run containers with network disabled by default and mount workspace under `/workspace`.
- Integrate secrets with Vault / Cloud KMS; do not bake tokens into images.

## Files
- `server.py` — main FastMCP server and CLI entrypoint
- `mcp_tools.py` — MCP `@mcp.tool()` wrappers exposing safe tool contract
- `worktree.py` — worktree lifecycle and patch application helpers
- `audit.py` — audit logging and signing
- `utils.py` — shared utilities (validate_path, run_shell_cmd, atomic write)
- `Dockerfile` — production container
- `k8s/deployment.yaml` — example k8s deployment manifest
- `.github/workflows/ci.yaml` — CI workflow
- `build-and-push.sh` — Docker build script for CI
- `SECURITY.md` — security hardening guidance and checklist
- `Makefile` — `make run`, `make test`, `make eval`
- `evals/smoke_eval.py` — smoke checks for repo structure and SAFE_COMMANDS
- `evals/tool_contract_eval.py` — tool registry and schema compliance checks
- `evals/atomic_write_eval.py` — atomic write invariants check
- `evals/run_eval.py` — combined evaluation runner
