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

## Quickstart (local)
Recommended (uv):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
make run
```

Editable install (pip):
```bash
pip install -e .
titanium-mcp
```

## Quickstart (docker)
```bash
docker compose up --build
```

## Verification (60-second proof)
```bash
make test
make eval
```
CI enforces lint, type checks, unit tests, and coverage (minimum 65%).

## Evaluation
Run the evaluation suite:
```bash
make eval
```

### Expected output
```text
EVAL RESULTS
smoke: pass (12.34ms)
tool_contract: pass (20.11ms)
atomic_write: pass (3.42ms)
checks_passed: 3/3
safe_commands: 5
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

## Production notes
- Use the included `Dockerfile` to build a container image.
- Run containers with network disabled by default and mount workspace under `/workspace`.
- Integrate secrets with Vault / Cloud KMS; do not bake tokens into images.

## Files
- `titanium_repo_operator/` — package with server, tools, policy, and utilities
- `server.py` — compatibility shim for `uv run server.py`
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
