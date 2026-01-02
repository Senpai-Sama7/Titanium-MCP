"""Evaluation checks for tool contract compliance."""

from __future__ import annotations

import asyncio

from titanium_repo_operator.server import mcp
from titanium_repo_operator.utils import SecurityError, validate_path

EXPECTED_TOOLS = {
    "read_file",
    "write_file",
    "list_files",
    "git_status_check",
    "git_commit",
    "search_code",
    "spawn_worktree_tool",
    "apply_patch_tool",
    "health",
}


async def _fetch_tools() -> dict[str, object]:
    tools = await mcp.get_tools()
    return tools


def run_check() -> tuple[bool, dict[str, str]]:
    details: dict[str, str] = {}
    tools = asyncio.run(_fetch_tools())

    expected_tools_present = EXPECTED_TOOLS.issubset(tools.keys())

    details["tool_count"] = str(len(tools))
    details["expected_tools"] = str(len(EXPECTED_TOOLS))
    details["expected_tools_present"] = "pass" if expected_tools_present else "fail"

    schema_ok = True
    for name, tool in tools.items():
        try:
            schema = tool.model_json_schema()
            schema_ok = schema_ok and isinstance(schema, dict) and schema.get("title") is not None
        except Exception:
            schema_ok = False
            details["schema_error"] = f"schema_failed:{name}"
            break
    details["schema_validation"] = "pass" if schema_ok else "fail"

    forbidden_ok = False
    try:
        validate_path("../forbidden")
    except SecurityError:
        forbidden_ok = True
    details["forbidden_path_rejected"] = "pass" if forbidden_ok else "fail"

    passed = (
        len(tools) >= len(EXPECTED_TOOLS)
        and expected_tools_present
        and schema_ok
        and forbidden_ok
    )

    return passed, details


if __name__ == "__main__":
    ok, details = run_check()
    print("EVAL RESULTS")
    for name, status in details.items():
        print(f"{name}: {status}")
    raise SystemExit(0 if ok else 1)
