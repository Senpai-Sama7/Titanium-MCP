"""Integration tests for worktree operations."""

import asyncio
from pathlib import Path

import pytest

from titanium_repo_operator import audit, worktree

@pytest.mark.asyncio
class TestWorktreeLifecycle:
    """Integration tests for worktree lifecycle."""

    async def test_spawn_worktree(self, temp_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test spawning a worktree."""
        monkeypatch.chdir(temp_repo)

        # Patch the module-level variables
        monkeypatch.setattr(worktree, "REPO_ROOT", temp_repo)
        monkeypatch.setattr(worktree, "WORKTREES_DIR", temp_repo / "worktrees")
        (temp_repo / "worktrees").mkdir(exist_ok=True)

        from titanium_repo_operator.worktree import spawn_worktree

        wt_path = await spawn_worktree("HEAD")

        assert Path(wt_path).exists()
        assert "wt-" in wt_path

    async def test_cleanup_worktree(self, temp_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test cleaning up a worktree."""
        monkeypatch.chdir(temp_repo)

        monkeypatch.setattr(worktree, "REPO_ROOT", temp_repo)
        monkeypatch.setattr(worktree, "WORKTREES_DIR", temp_repo / "worktrees")
        (temp_repo / "worktrees").mkdir(exist_ok=True)

        from titanium_repo_operator.worktree import cleanup_worktree, spawn_worktree

        wt_path = await spawn_worktree("HEAD")
        assert Path(wt_path).exists()

        await cleanup_worktree(wt_path)
        assert not Path(wt_path).exists()

    async def test_cleanup_nonexistent_worktree(
        self, temp_repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that cleaning up nonexistent worktree doesn't error."""
        monkeypatch.chdir(temp_repo)

        monkeypatch.setattr(worktree, "REPO_ROOT", temp_repo)

        from titanium_repo_operator.worktree import cleanup_worktree

        # Should not raise
        await cleanup_worktree("/nonexistent/path")


@pytest.mark.asyncio
class TestPatchApplication:
    """Integration tests for patch application."""

    async def test_apply_valid_patch(
        self, temp_repo: Path, sample_patch: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test applying a valid patch."""
        monkeypatch.chdir(temp_repo)

        monkeypatch.setattr(worktree, "REPO_ROOT", temp_repo)
        monkeypatch.setattr(worktree, "WORKTREES_DIR", temp_repo / "worktrees")
        monkeypatch.setattr(audit, "AUDITS_DIR", temp_repo / "audits")
        (temp_repo / "worktrees").mkdir(exist_ok=True)
        (temp_repo / "audits").mkdir(exist_ok=True)

        from titanium_repo_operator.worktree import apply_patch_and_verify, cleanup_worktree, spawn_worktree

        wt_path = await spawn_worktree("HEAD")

        result = await apply_patch_and_verify(wt_path, sample_patch, run_checks=False)

        assert result["ok"] is True
        assert result["diff_hash"] is not None
        assert len(result["diff_hash"]) == 64  # SHA256 hex

        # Cleanup
        await cleanup_worktree(wt_path)

    async def test_apply_invalid_patch(
        self, temp_repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test applying an invalid patch."""
        monkeypatch.chdir(temp_repo)

        monkeypatch.setattr(worktree, "REPO_ROOT", temp_repo)
        monkeypatch.setattr(worktree, "WORKTREES_DIR", temp_repo / "worktrees")
        (temp_repo / "worktrees").mkdir(exist_ok=True)

        from titanium_repo_operator.worktree import apply_patch_and_verify, cleanup_worktree, spawn_worktree

        wt_path = await spawn_worktree("HEAD")

        invalid_patch = "this is not a valid patch"
        result = await apply_patch_and_verify(wt_path, invalid_patch, run_checks=False)

        assert result["ok"] is False

        # Cleanup
        await cleanup_worktree(wt_path)

    async def test_apply_patch_to_missing_worktree(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test applying patch to nonexistent worktree."""
        from titanium_repo_operator.worktree import apply_patch_and_verify

        result = await apply_patch_and_verify("/nonexistent", "patch", run_checks=False)

        assert result["ok"] is False
        assert result["reason"] == "worktree_missing"
