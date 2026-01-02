"""Minimal evaluation checks for Titanium Repo Operator."""

from __future__ import annotations

from pathlib import Path
import sys

from config import REPO_ROOT
from mcp_tools import SAFE_COMMANDS

EXPECTED_SAFE_COMMANDS = {
    "test_unit",
    "test_all",
    "lint",
    "format_check",
    "typecheck",
}


def run_check() -> tuple[bool, dict[str, str]]:
    checks = {
        "repo_root_exists": Path(REPO_ROOT).is_dir(),
        "docker_compose_exists": (Path(REPO_ROOT) / "docker-compose.yml").is_file(),
        "safe_commands_present": EXPECTED_SAFE_COMMANDS.issubset(SAFE_COMMANDS),
    }

    passed = sum(1 for ok in checks.values() if ok)
    total = len(checks)

    details = {name: "pass" if ok else "fail" for name, ok in checks.items()}
    details["checks_passed"] = f"{passed}/{total}"
    details["safe_commands"] = str(len(SAFE_COMMANDS))

    return passed == total, details


if __name__ == "__main__":
    ok, details = run_check()
    print("EVAL RESULTS")
    for name, status in details.items():
        print(f"{name}: {status}")
    sys.exit(0 if ok else 1)
