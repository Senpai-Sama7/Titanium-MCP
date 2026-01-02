"""Worktree management: create ephemeral worktrees, apply patches safely, run checks."""

import hashlib
import shutil
import uuid
from pathlib import Path

from .audit import log_audit
from .config import REPO_ROOT, WORKTREES_DIR
from .utils import run_shell_cmd


async def spawn_worktree(base_branch: str = "HEAD") -> str:
    """Create a new ephemeral git worktree.

    Args:
        base_branch: The branch or commit to base the worktree on

    Returns:
        Path to the created worktree

    Raises:
        RuntimeError: If worktree creation fails
    """
    worktree_id = f"wt-{uuid.uuid4().hex[:8]}"
    wt_path = WORKTREES_DIR / worktree_id
    wt_path.mkdir(parents=True, exist_ok=True)

    out = await run_shell_cmd(["git", "worktree", "add", str(wt_path), base_branch])

    if "fatal" in out.lower() or "error" in out.lower():
        # Clean up failed worktree
        if wt_path.exists():
            shutil.rmtree(wt_path, ignore_errors=True)
        raise RuntimeError(f"Failed to spawn worktree: {out}")

    log_audit("worktree_spawned", {"worktree_id": worktree_id, "base": base_branch})
    return str(wt_path)


async def cleanup_worktree(worktree_path: str) -> None:
    """Clean up a worktree and its git references.

    Args:
        worktree_path: Path to the worktree to remove
    """
    wt = Path(worktree_path)
    if not wt.exists():
        return

    # Remove worktree reference first
    try:
        await run_shell_cmd(["git", "worktree", "remove", "-f", str(wt)])
    except Exception:
        pass

    # Ensure files are removed
    if wt.exists():
        shutil.rmtree(wt, ignore_errors=True)

    log_audit("worktree_cleaned", {"path": worktree_path})


async def apply_patch_and_verify(
    worktree_path: str,
    patch_text: str,
    run_checks: bool = True
) -> dict:
    """Apply a patch to a worktree and optionally run verification checks.

    Args:
        worktree_path: Path to the target worktree
        patch_text: The patch content to apply
        run_checks: Whether to run tests after applying

    Returns:
        Dict with status, diff_hash, commit info, and test results
    """
    wt = Path(worktree_path)
    if not wt.exists():
        return {"ok": False, "reason": "worktree_missing"}

    # Write patch to temp file
    patch_file = wt / f"patch-{uuid.uuid4().hex[:8]}.diff"
    patch_file.write_text(patch_text, encoding="utf-8")

    try:
        # Verify patch can be applied
        check = await run_shell_cmd(["git", "apply", "--check", str(patch_file)], cwd=wt)
        if check and ("error" in check.lower() or "fatal" in check.lower()):
            return {"ok": False, "reason": "patch_check_failed", "output": check}

        # Apply patch
        apply_out = await run_shell_cmd(["git", "apply", str(patch_file)], cwd=wt)
        if apply_out and ("error" in apply_out.lower() or "fatal" in apply_out.lower()):
            return {"ok": False, "reason": "apply_failed", "output": apply_out}

        # Stage and commit changes
        await run_shell_cmd(["git", "add", "-A"], cwd=wt)
        staged_changes = await run_shell_cmd(
            ["git", "diff", "--cached", "--name-only"],
            cwd=wt
        )
        if not staged_changes.strip():
            return {"ok": False, "reason": "empty_commit", "output": staged_changes}

        commit_out = await run_shell_cmd(
            ["git", "commit", "-m", "Agent patch (staging)"],
            cwd=wt
        )
        if commit_out and (
            "error" in commit_out.lower()
            or "fatal" in commit_out.lower()
            or "nothing to commit" in commit_out.lower()
        ):
            return {"ok": False, "reason": "commit_failed", "output": commit_out}

        # Run verification checks if requested
        tests = None
        if run_checks:
            tests = await run_shell_cmd(["pytest", "-q"], cwd=wt, timeout=60)

        # Calculate patch hash for audit trail
        diff_hash = hashlib.sha256(patch_text.encode()).hexdigest()

        # Log the patch application
        audit_entry = {
            "worktree": str(wt.relative_to(REPO_ROOT)) if str(wt).startswith(str(REPO_ROOT)) else str(wt),
            "diff_hash": diff_hash,
            "commit": commit_out.strip() if commit_out else "",
            "tests_passed": tests is None or "failed" not in tests.lower() if tests else None,
        }
        log_audit("patch_applied", audit_entry)

        return {
            "ok": True,
            "diff_hash": diff_hash,
            "commit": commit_out,
            "tests": tests
        }

    finally:
        # Clean up patch file
        if patch_file.exists():
            patch_file.unlink()
