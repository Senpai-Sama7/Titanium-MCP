"""Unit tests for mcp tools."""

import importlib
import os
import sys
from pathlib import Path

import asyncio
import pytest
from fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _setup_mcp(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> FastMCP:
    monkeypatch.setenv("REPO_ROOT", str(temp_dir))
    monkeypatch.chdir(temp_dir)

    import titanium_repo_operator.config as config
    importlib.reload(config)
    import titanium_repo_operator.utils as utils
    importlib.reload(utils)
    import titanium_repo_operator.mcp_tools as mcp_tools
    importlib.reload(mcp_tools)

    mcp = FastMCP("test")
    mcp_tools.register_tools(mcp)
    return mcp


def test_list_files_non_recursive_ignores_max_depth(
    temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_file = temp_dir / "root.txt"
    root_file.write_text("root")
    nested_dir = temp_dir / "subdir"
    nested_dir.mkdir()
    nested_file = nested_dir / "nested.txt"
    nested_file.write_text("nested")

    mcp = _setup_mcp(temp_dir, monkeypatch)
    tool = asyncio.run(mcp.get_tool("list_files"))

    result = asyncio.run(tool.fn(path=".", recursive=False, max_depth=0))
    lines = result.splitlines()

    assert "root.txt" in lines
    assert os.path.join("subdir", "nested.txt") not in lines


def test_list_files_recursive_respects_max_depth(
    temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root_file = temp_dir / "root.txt"
    root_file.write_text("root")
    nested_dir = temp_dir / "subdir"
    nested_dir.mkdir()
    nested_file = nested_dir / "nested.txt"
    nested_file.write_text("nested")

    mcp = _setup_mcp(temp_dir, monkeypatch)
    tool = asyncio.run(mcp.get_tool("list_files"))

    result = asyncio.run(tool.fn(path=".", recursive=True, max_depth=0))
    lines = result.splitlines()

    assert "root.txt" in lines
    assert os.path.join("subdir", "nested.txt") not in lines

    result = asyncio.run(tool.fn(path=".", recursive=True, max_depth=1))
    lines = result.splitlines()

    assert os.path.join("subdir", "nested.txt") in lines
