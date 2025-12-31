# Titanium Repo Operator

## "Titanium" MCP server"

### "An async-first, atomic, auditable, worktree-oriented MCP server for autonomous coding agents."


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
