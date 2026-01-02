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


def main() -> int:
    checks = {
        "repo_root_exists": Path(REPO_ROOT).is_dir(),
        "docker_compose_exists": (Path(REPO_ROOT) / "docker-compose.yml").is_file(),
        "safe_commands_present": EXPECTED_SAFE_COMMANDS == SAFE_COMMANDS,
    }

    passed = sum(1 for ok in checks.values() if ok)
    total = len(checks)

    print("EVAL RESULTS")
    for name, ok in checks.items():
        status = "pass" if ok else "fail"
        print(f"{name}: {status}")
    print(f"checks_passed: {passed}/{total}")
    print(f"safe_commands: {len(SAFE_COMMANDS)}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
