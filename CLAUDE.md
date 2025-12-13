# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Titanium Repo Operator is an async-first, atomic, auditable, worktree-oriented MCP server for autonomous coding agents. It provides safe repository operations through ephemeral worktrees, patch-based changes with verification, and comprehensive audit logging.

## Architecture

### Core Components

**server.py** - FastMCP server entrypoint
- Registers all MCP tools via `mcp_tools.register_tools()`
- Handles graceful shutdown with signal handling (SIGINT, SIGTERM)
- Uses uvloop for performance optimization where available
- Creates `worktrees/` and `audits/` directories on startup

**mcp_tools.py** - MCP tool definitions
- Exposes safe tool contract for repository operations
- All tools are async and registered via `@mcp.tool()` decorator
- Uses atomic operations and path validation for safety
- Integrates with audit logging for all critical operations

**worktree.py** - Worktree lifecycle management
- Creates ephemeral git worktrees with unique IDs (`wt-{uuid}`)
- Applies patches safely with verification before committing
- Runs automated checks (pytest) in isolated worktrees
- Cleanup removes worktree references and files

**audit.py** - Audit logging with HMAC signing
- All critical operations logged to `audits/audits.jsonl`
- Each entry includes timestamp, event type, metadata, and HMAC signature
- HMAC key from `TITANIUM_AUDIT_KEY` environment variable (default: dev-key-change-me)
- Provides tamper detection for compliance/forensics

**utils.py** - Security and safety utilities
- `validate_path()` enforces path traversal protection (must be under ROOT)
- `atomic_write()` uses temp files + fsync for durability
- `run_shell_cmd()` with timeout protection (default 30s)
- `truncate_output()` prevents excessive response sizes (16KB limit)

**config.py** - Centralized configuration
- Single source of truth for all environment-based settings
- Paths: `REPO_ROOT`, `WORKTREES_DIR`, `AUDITS_DIR`
- Policy constraints: `MAX_LOC_PER_PATCH`, `MAX_FILES_PER_PATCH`, `MAX_ITERATIONS`
- Feature flags: `REQUIRE_APPROVAL_FOR_PUSH`, `DEV_MODE`
- Signing: `SIGNING_METHOD`, `SIGNING_KEY`, `SSH_ALLOWED_SIGNERS`

**policy.py** - OPA/Cedar-style policy engine
- Enforces agent constraints before operations execute
- Evaluates patches: LOC limits, file counts, prohibited paths, secrets detection
- Evaluates pushes: protected branch restrictions, approval requirements
- Evaluates commands: allowlist enforcement, dangerous command blocking
- Returns `PolicyResult` with decision (ALLOW/DENY/REQUIRE_APPROVAL) and violations

**approval.py** - Human approval middleware
- Async approval workflow with configurable timeout (default 5 minutes)
- Persistent approval state in `audits/pending_approvals.json`
- States: PENDING → APPROVED/REJECTED/EXPIRED
- Integrates with policy engine for REQUIRE_APPROVAL decisions
- Supports review comments and audit trail

**signing.py** - Commit signing support
- Multiple signing methods: `gpg`, `ssh`, `sigstore` (gitsign)
- Configures git signing settings per repository
- `sign_commit()` creates signed commits
- `verify_commit()` validates commit signatures
- Environment variables: `TITANIUM_SIGNING_METHOD`, `TITANIUM_SIGNING_KEY`

### Security Model

All file operations undergo path validation to prevent directory traversal attacks. The system enforces repository root boundaries and raises `SecurityError` for violations. Audit logs are HMAC-signed for tamper detection. Production deployments should:
- Use dedicated service accounts with minimal Git permissions
- Run containers with network disabled and restricted capabilities
- Store audit logs in tamper-evident storage (S3 with immutability)
- Rotate HMAC keys regularly via secrets manager (Vault, Cloud KMS)

## Common Development Commands

### Running the Server

**Development (local stdio)**:
```bash
uv run server.py
```

**Register with Claude Code**:
```bash
claude mcp add titanium -- uv run --with fastmcp --with gitpython /path/to/server.py
```

### Dependency Management

**Generate lock file** (after adding deps to pyproject.toml):
```bash
uv lock
```

**Install all dependencies** (dev):
```bash
uv sync --all-extras --dev
```

**Install production only**:
```bash
uv sync --frozen --no-dev
```

### Testing and Quality

**Run all tests**:
```bash
uv run pytest -q
```

**Run unit tests only**:
```bash
uv run pytest -q tests/unit
```

**Lint and format**:
```bash
uv run ruff check .
uv run ruff format --check .
```

**Type check**:
```bash
uv run mypy .
```

**Security scan**:
```bash
uv run bandit -c bandit.yaml -r .
```

**Available check types** (via `run_check` tool):
- `test_unit` - Unit tests only
- `test_all` - Full test suite
- `lint` - Ruff linting
- `format_check` - Ruff format verification
- `typecheck` - MyPy type checking

### Build and Deploy

**Build Docker image**:
```bash
docker build -t titanium-agent:local .
```

**Run with docker-compose** (production):
```bash
docker-compose up titanium
```

**Run with docker-compose** (dev mode):
```bash
docker-compose --profile dev up titanium-dev
```

**Manual container run** (hardened):
```bash
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  -v ./workspace:/workspace:rw --tmpfs /tmp titanium-agent:local
```

## Tool Workflow Patterns

### Safe Code Changes Pattern

1. **Create worktree**: `spawn_worktree_tool(base_branch="main")` → Returns path
2. **Apply changes**: `apply_patch_tool(worktree_path, patch_text, run_checks=True)`
   - Validates patch with `git apply --check`
   - Applies patch and auto-commits
   - Runs pytest if `run_checks=True`
   - Returns `{ok: bool, diff_hash: str, commit: str, tests: str}`
3. **Review results**: Check `tests` output for failures
4. **Create PR**: `create_pr(title, branch_name, base_branch="main", push=False)`
5. **Cleanup**: `cleanup_worktree_tool(worktree_path)` - Always cleanup, even on failure

### Code Search Pattern

**Symbol search** (Python only):
```python
symbol_definition(symbol_name="MyClass", path=".")
```
Uses AST parsing to find class/function definitions across `.py` files.

**Text search** (requires ripgrep):
```python
search_code(query="TODO", case_sensitive=False)
```
Returns line numbers with 1-line context.

### Git Operations

**Check status before changes**:
```python
git_status_check()  # Returns branch + porcelain status
```

**Stage and commit** (auto-stages modified files):
```python
git_commit(message="feat: add new feature")
git_commit(message="feat: signed commit", sign=True)  # With signature
```

**Review staged changes**:
```python
git_diff_staged()
```

**Push with policy enforcement**:
```python
git_push()  # Current branch
git_push(branch="feature/new", force=False)  # Specific branch
# Protected branches (main, master, prod) require approval
```

### Policy-Enforced Operations

All mutation operations pass through the policy engine before execution:

1. **Patch application**: Checks LOC limits (500), file counts (20), prohibited paths
2. **File writes**: Validates against secrets patterns and protected files
3. **Push operations**: Enforces protected branch rules, requires approval
4. **Commands**: Validates against allowlist, blocks dangerous operations

**Policy violations return structured errors**:
```python
{
    "ok": False,
    "reason": "policy_violation",
    "violations": ["Patch exceeds 500 LOC limit (got 750)"]
}
```

### Approval Workflow

High-risk operations require human approval when policy dictates:

**List pending approvals**:
```python
list_pending_approvals()  # Returns JSON array
```

**Approve a request**:
```python
approve_request(request_id="apr-abc123", reviewer="admin", comment="LGTM")
```

**Reject a request**:
```python
reject_request(request_id="apr-abc123", reviewer="admin", comment="Too risky")
```

Approvals timeout after 5 minutes by default. Expired requests must be resubmitted.

## Important Constraints

### Security Boundaries
- **Path validation**: All file paths must resolve within repository root
- **Output truncation**: Command outputs limited to 16KB to prevent memory issues
- **Timeout protection**: Shell commands timeout after 30s (configurable)
- **Worktree isolation**: Changes always happen in ephemeral worktrees, never main working tree
- **Check commands**: Only predefined safe commands allowed via `run_check` (see SAFE_COMMANDS dict)

### Policy Limits (configurable via environment)
- **Max LOC per patch**: 500 lines (TITANIUM_MAX_LOC)
- **Max files per patch**: 20 files (TITANIUM_MAX_FILES)
- **Max iterations per task**: 10 iterations (TITANIUM_MAX_ITERATIONS)
- **Protected branches**: main, master, production, prod - require approval for push
- **Prohibited paths**: `.git/`, `.env`, `**/secrets/**`, `**/*credential*`

### Approval Requirements
- Push to protected branches
- Force push operations
- Patches affecting security-sensitive files
- Operations exceeding policy soft limits

## Environment Variables

All configuration is centralized in `config.py` and loaded from environment:

| Variable | Default | Description |
|----------|---------|-------------|
| `REPO_ROOT` | `cwd` | Repository root path (in container: `/workspace`) |
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) |
| `TITANIUM_AUDIT_KEY` | `dev-key-change-me` | HMAC key for audit log signing |
| `TITANIUM_MAX_LOC` | `500` | Maximum lines of code per patch |
| `TITANIUM_MAX_FILES` | `20` | Maximum files per patch |
| `TITANIUM_MAX_ITERATIONS` | `10` | Maximum iterations per task |
| `TITANIUM_REQUIRE_APPROVAL` | `true` | Require approval for protected branch push |
| `TITANIUM_SHELL_TIMEOUT` | `30` | Shell command timeout in seconds |
| `TITANIUM_OUTPUT_LIMIT` | `16000` | Output truncation limit in characters |
| `TITANIUM_SIGNING_METHOD` | `none` | Commit signing method (none, gpg, ssh, sigstore) |
| `TITANIUM_SIGNING_KEY` | - | GPG key ID or path to SSH private key |
| `TITANIUM_SSH_ALLOWED_SIGNERS` | - | SSH allowed signers file for verification |
| `TITANIUM_DEV_MODE` | `false` | Enable dev mode (auto-approves, relaxed security) |

See `.env.example` for a complete template.

## Production Considerations

See SECURITY.md for comprehensive hardening guidance. Key points:
- Never store secrets in repository or Docker images
- Use Vault/Cloud KMS for secret injection at runtime
- Run containers as non-root user (titanium) with minimal capabilities
- Enable network restrictions and use egress allowlists
- Configure human approval gates for high-risk operations
- Maintain audit log backups and configure alerting for anomalies
- Set resource quotas (CPU/memory) and iteration budgets

### Commit Signing

For production environments, enable commit signing to verify agent-authored commits:

**GPG signing**:
```bash
TITANIUM_SIGNING_METHOD=gpg
TITANIUM_SIGNING_KEY=<gpg-key-id>
```

**SSH signing**:
```bash
TITANIUM_SIGNING_METHOD=ssh
TITANIUM_SIGNING_KEY=~/.ssh/id_ed25519
TITANIUM_SSH_ALLOWED_SIGNERS=~/.ssh/allowed_signers
```

**Sigstore/Gitsign** (keyless, OIDC-based):
```bash
TITANIUM_SIGNING_METHOD=sigstore
# Requires gitsign installed and OIDC provider configured
```
