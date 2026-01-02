# Repository Guidelines

## Project Structure & Module Organization
- `titanium_repo_operator/` contains the core server, tools, policy, and utilities.
- `server.py` is a compatibility shim for running with `uv run server.py`.
- `tests/unit/` and `tests/integration/` hold pytest suites; `tests/` also provides shared fixtures.
- `evals/` contains lightweight eval runners (smoke, tool contract, atomic write checks).
- Deployment assets live at `Dockerfile`, `docker-compose.yml`, and `k8s-deployment.yaml`.

## Build, Test, and Development Commands
- `make run` — run the MCP server locally via `uv`.
- `make test` — run pytest with coverage and async support (fails below 65%).
- `make eval` — run the evaluation suite in `evals/`.
- Optional: `pip install -e .` then `titanium-mcp` for an editable install.
- Optional: `docker compose up --build` for a containerized run.

## Coding Style & Naming Conventions
- Python 3.12 codebase; default indentation is 4 spaces.
- Linting/formatting: `ruff` with a 100-character line length (see `pyproject.toml`).
- Type checking: `mypy` is configured for strict mode; keep annotations complete.
- Security checks: `bandit` is configured with repo-specific skips.
- Naming: modules and functions use `snake_case`, classes use `CapWords`, tests follow `test_*.py`.

## Testing Guidelines
- Frameworks: `pytest`, `pytest-asyncio`, `pytest-cov`.
- Naming conventions: test files `test_*.py`, test functions `test_*`.
- Coverage: `make test` enforces a minimum 65% overall coverage.
- Organize new tests under `tests/unit/` or `tests/integration/` depending on scope.

## Commit & Pull Request Guidelines
- Commit messages are short, imperative summaries (e.g., “Handle apply/commit failures”).
- Keep changes focused; avoid mixing refactors with behavior changes.
- PRs should include: a clear description, linked issues (if any), and test results (e.g., `make test`).
- Add screenshots only if you change user-facing outputs or logs.

## Security & Configuration Tips
- Runtime configuration is centralized in `titanium_repo_operator/config.py`.
- Key env vars include `REPO_ROOT`, `TITANIUM_AUDIT_KEY`, and `TITANIUM_*` limits.
- Do not commit secrets; use `.env.example` as the pattern for local setup.
