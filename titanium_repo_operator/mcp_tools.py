"""Tool definitions exposed via FastMCP decorators.

This module exposes a carefully curated tool contract for repo operations,
with integrated policy enforcement and approval workflows.
"""

import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .approval import get_approval_manager, require_approval
from .audit import log_audit
from .config import REPO_ROOT
from .config import APPROVAL_TOKEN
from .policy import PolicyDecision, evaluate_command, evaluate_patch, evaluate_push
from .signing import get_commit_signer
from .utils import atomic_write, run_shell_cmd, truncate_output, validate_path
from .worktree import apply_patch_and_verify, cleanup_worktree, spawn_worktree

# Allowed safe commands used by run_check
SAFE_COMMANDS = {
    "test_unit": ["pytest", "-q", "tests/unit"],
    "test_all": ["pytest", "-q"],
    "lint": ["ruff", "check", "."],
    "format_check": ["ruff", "format", "--check", "."],
    "typecheck": ["mypy", "."],
}


def _extract_affected_files(patch_text: str) -> list[str]:
    """Extract list of affected files from a patch."""
    files = []
    for line in patch_text.split("\n"):
        if line.startswith("diff --git"):
            # Extract b/path from "diff --git a/path b/path"
            match = re.search(r"b/(.+)$", line)
            if match:
                files.append(match.group(1))
        elif line.startswith("+++") and not line.startswith("+++ /dev/null"):
            # Fallback: extract from +++ b/path
            match = re.search(r"\+\+\+ b/(.+)$", line)
            if match:
                files.append(match.group(1))
    return list(set(files))


def register_tools(mcp: FastMCP) -> None:
    """Register all MCP tools with the server."""

    def _validate_approval_token(token: str | None) -> str | None:
        if APPROVAL_TOKEN is None:
            return None
        if token != APPROVAL_TOKEN:
            return "Error: approval token required or invalid."
        return None

    # =========================================================================
    # File Operations
    # =========================================================================

    @mcp.tool()
    async def read_file(
        path: str,
        line_start: int = 1,
        line_end: int | None = None
    ) -> str:
        """Read a file's contents, optionally with line range.

        Args:
            path: Path to file (relative to repo root)
            line_start: Starting line number (1-indexed)
            line_end: Ending line number (inclusive, optional)

        Returns:
            File contents or error message
        """
        validated_path = validate_path(path)
        if not validated_path.exists():
            return "Error: File not found."

        text = validated_path.read_text(encoding="utf-8")

        if line_start == 1 and line_end is None:
            return text

        lines = text.splitlines()
        end_idx = line_end if line_end else len(lines)
        return "\n".join(lines[line_start - 1:end_idx])

    @mcp.tool()
    async def write_file(path: str, content: str) -> str:
        """Write content to a file atomically.

        Prefer apply_patch for tracked changes. This tool bypasses
        patch-based workflow but still enforces path validation.

        Args:
            path: Path to file (relative to repo root)
            content: Content to write

        Returns:
            Success message or error
        """
        validated_path = validate_path(path)

        # Check policy for file write
        policy_result = evaluate_patch(
            f"+++ {path}\n" + content,
            [path],
        )

        if policy_result.decision == PolicyDecision.DENY:
            violations = "; ".join(v.reason for v in policy_result.violations)
            return f"Policy violation: {violations}"

        if policy_result.requires_approval:
            approved = await require_approval(
                "write_file",
                policy_result.approval_reason or "File write requires approval",
                {"path": path},
            )
            if not approved:
                return "Operation cancelled: approval denied or timed out"

        try:
            atomic_write(validated_path, content)
            log_audit("write_file", {"path": str(validated_path)})
            return f"Successfully wrote {validated_path}"
        except Exception as e:
            return f"Write failed: {e}"

    @mcp.tool()
    async def list_files(
        path: str = ".",
        recursive: bool = True,
        max_depth: int = 2
    ) -> str:
        """List files in a directory.

        Args:
            path: Directory path (relative to repo root)
            recursive: Whether to recurse into subdirectories
            max_depth: Maximum recursion depth

        Returns:
            Newline-separated list of file paths
        """
        p = validate_path(path)
        results = []
        max_results = 1000
        if not recursive:
            for entry in os.scandir(p):
                if not entry.is_file():
                    continue
                if entry.name.endswith('.pyc'):
                    continue
                rel = os.path.relpath(p, str(REPO_ROOT))
                if rel == ".":
                    rel = ""
                results.append(os.path.join(rel, entry.name))
                if len(results) >= max_results:
                    break
        else:
            base_depth = len(str(p).split(os.sep))
            reached_max = False

            for root, dirs, files in os.walk(p):
                depth = len(root.split(os.sep)) - base_depth

                if depth > max_depth:
                    del dirs[:]
                    continue

                rel = os.path.relpath(root, str(REPO_ROOT))
                if rel == ".":
                    rel = ""

                for f in files:
                    if f.endswith('.pyc'):
                        continue
                    results.append(os.path.join(rel, f))
                    if len(results) >= max_results:
                        reached_max = True
                        break
                if reached_max:
                    break

        return "\n".join(results) or "No files found."

    # =========================================================================
    # Git Operations
    # =========================================================================

    @mcp.tool()
    async def git_status_check() -> str:
        """Get current git status and branch.

        Returns:
            Branch name and list of changes
        """
        status = await run_shell_cmd(["git", "status", "--porcelain"])
        branch = await run_shell_cmd(["git", "branch", "--show-current"])
        if not status.ok or not branch.ok:
            return f"Error: {status.output or branch.output}"
        out = f"Branch: {branch.output.strip()}\nChanges:\n{status.output}"
        log_audit("git_status_check", {})
        return out

    @mcp.tool()
    async def git_commit(message: str, sign: bool = False) -> str:
        """Stage modified files and commit.

        Args:
            message: Commit message
            sign: Whether to sign the commit (if signing is configured)

        Returns:
            Commit result or error
        """
        add_result = await run_shell_cmd(["git", "add", "-u"])
        if not add_result.ok:
            return f"Error: {add_result.output}"

        if sign:
            signer = get_commit_signer()
            success, result = await signer.sign_commit(message, REPO_ROOT)
            if not success:
                return f"Signed commit failed: {result}"
            log_audit("git_commit", {"message": message, "signed": True})
            return result
        else:
            res = await run_shell_cmd(["git", "commit", "-m", message])
            if not res.ok:
                return f"Error: {res.output}"
            log_audit("git_commit", {"message": message, "signed": False})
            return res.output

    @mcp.tool()
    async def git_diff_staged() -> str:
        """Get the diff of staged changes.

        Returns:
            Staged diff output
        """
        diff = await run_shell_cmd(["git", "diff", "--staged"])
        if not diff.ok:
            return f"Error: {diff.output}"
        return diff.output

    @mcp.tool()
    async def git_push(
        branch: str | None = None,
        force: bool = False
    ) -> str:
        """Push commits to remote.

        Args:
            branch: Branch to push (current if None)
            force: Force push (requires approval)

        Returns:
            Push result or error
        """
        # Determine target branch
        if branch is None:
            branch_result = await run_shell_cmd(["git", "branch", "--show-current"])
            if not branch_result.ok:
                return f"Error: {branch_result.output}"
            branch = branch_result.output.strip()

        # Check policy
        is_protected = branch in ("main", "master", "production", "prod")
        policy_result = evaluate_push(branch, is_protected)

        if policy_result.decision == PolicyDecision.DENY:
            violations = "; ".join(v.reason for v in policy_result.violations)
            return f"Policy violation: {violations}"

        if policy_result.requires_approval or force:
            reason = policy_result.approval_reason or "Push requires approval"
            if force:
                reason = f"Force push to {branch} requires approval"

            approved = await require_approval(
                "git_push",
                reason,
                {"branch": branch, "force": force},
            )
            if not approved:
                return "Push cancelled: approval denied or timed out"

        cmd = ["git", "push"]
        if force:
            cmd.append("--force-with-lease")
        if branch:
            cmd.extend(["-u", "origin", branch])

        result = await run_shell_cmd(cmd)
        if not result.ok:
            return f"Error: {result.output}"
        log_audit("git_push", {"branch": branch, "force": force})
        return result.output

    # =========================================================================
    # Code Search
    # =========================================================================

    @mcp.tool()
    async def search_code(query: str, case_sensitive: bool = False) -> str:
        """Search code using ripgrep.

        Args:
            query: Search pattern (regex supported)
            case_sensitive: Whether to match case

        Returns:
            Search results with context
        """
        args = ["rg", "--line-number", "--context", "1"]
        if not case_sensitive:
            args.append("--ignore-case")
        args.extend(["--", query])

        # Check policy for command
        policy_result = evaluate_command(args)
        if policy_result.decision == PolicyDecision.DENY:
            return f"Policy violation: {policy_result.violations[0].reason}"

        if policy_result.requires_approval:
            approved = await require_approval(
                "search_code",
                policy_result.approval_reason or "Search requires approval",
                {"query": query},
            )
            if not approved:
                return "Operation cancelled: approval denied or timed out"

        res = await run_shell_cmd(args)
        if res.returncode == 127:
            return "Error: 'rg' not available; install ripgrep for best results."
        if not res.ok:
            return f"Error: {res.output}"
        return res.output

    @mcp.tool()
    async def symbol_definition(symbol_name: str, path: str = ".") -> str:
        """Find symbol definitions in Python code.

        Args:
            symbol_name: Name of class or function to find
            path: Directory to search

        Returns:
            Locations of symbol definitions
        """
        root = validate_path(path)
        results = []

        for r, _, files in os.walk(root):
            for f in files:
                if not f.endswith('.py'):
                    continue
                p = Path(r) / f
                try:
                    tree = ast.parse(p.read_text(encoding='utf-8'))
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            if node.name == symbol_name:
                                rel_path = os.path.relpath(p, REPO_ROOT)
                                results.append(f"Found in {rel_path}:{node.lineno}")
                except Exception:
                    continue

        return "\n".join(results) or f"Symbol '{symbol_name}' not found."

    # =========================================================================
    # Quality Checks
    # =========================================================================

    @mcp.tool()
    async def run_check(check_type: str) -> str:
        """Run a predefined quality check.

        Available checks: test_unit, test_all, lint, format_check, typecheck

        Args:
            check_type: Type of check to run

        Returns:
            Check output
        """
        if check_type not in SAFE_COMMANDS:
            return f"Error: Invalid check. Allowed: {', '.join(SAFE_COMMANDS.keys())}"

        cmd = SAFE_COMMANDS[check_type]

        # Check policy
        policy_result = evaluate_command(cmd)
        if policy_result.decision == PolicyDecision.DENY:
            return f"Policy violation: {policy_result.violations[0].reason}"

        if policy_result.requires_approval:
            approved = await require_approval(
                "run_check",
                policy_result.approval_reason or "Check requires approval",
                {"check": check_type},
            )
            if not approved:
                return "Operation cancelled: approval denied or timed out"

        out = await run_shell_cmd(cmd)
        log_audit(
            "run_check",
            {
                "check": check_type,
                "returncode": out.returncode,
                "duration_ms": f"{out.duration_ms:.2f}",
            },
        )
        if not out.ok:
            return f"Error: {out.output}"
        return out.output

    # =========================================================================
    # Worktree Operations
    # =========================================================================

    @mcp.tool()
    async def spawn_worktree_tool(base_branch: str = "HEAD") -> str:
        """Create an ephemeral git worktree for safe changes.

        Args:
            base_branch: Branch or commit to base the worktree on

        Returns:
            Path to the created worktree
        """
        wt = await spawn_worktree(base_branch)
        return wt

    @mcp.tool()
    async def apply_patch_tool(
        worktree_path: str,
        patch_text: str,
        run_checks: bool = True,
        task_id: str | None = None
    ) -> dict[str, Any]:
        """Apply a patch to a worktree with policy enforcement.

        Args:
            worktree_path: Path to target worktree
            patch_text: The patch to apply
            run_checks: Whether to run tests after applying
            task_id: Optional task ID for iteration tracking

        Returns:
            Result dict with status, hash, and test results
        """
        # Extract affected files for policy check
        affected_files = _extract_affected_files(patch_text)
        if not affected_files:
            return {
                "ok": False,
                "reason": "invalid_patch",
                "violations": ["No affected files found in patch headers"],
            }

        # Check policy
        policy_result = evaluate_patch(patch_text, affected_files, task_id)

        if policy_result.decision == PolicyDecision.DENY:
            return {
                "ok": False,
                "reason": "policy_violation",
                "violations": [v.reason for v in policy_result.violations],
            }

        if policy_result.requires_approval:
            approved = await require_approval(
                "apply_patch",
                policy_result.approval_reason or "Patch requires approval",
                {"affected_files": affected_files},
            )
            if not approved:
                return {
                    "ok": False,
                    "reason": "approval_denied",
                }

        result = await apply_patch_and_verify(worktree_path, patch_text, run_checks)
        return result

    @mcp.tool()
    async def cleanup_worktree_tool(worktree_path: str) -> str:
        """Clean up an ephemeral worktree.

        Args:
            worktree_path: Path to worktree to remove

        Returns:
            Success confirmation
        """
        await cleanup_worktree(worktree_path)
        return "ok"

    # =========================================================================
    # PR Operations
    # =========================================================================

    @mcp.tool()
    async def create_pr(
        title: str,
        branch_name: str,
        base_branch: str = "main",
        push: bool = False
    ) -> str:
        """Create a branch with changes (optionally push).

        Args:
            title: PR/commit title
            branch_name: Name for the new branch
            base_branch: Branch to base off of
            push: Whether to push to remote

        Returns:
            Result message
        """
        checkout = await run_shell_cmd(["git", "checkout", "-b", branch_name, base_branch])
        if not checkout.ok:
            return f"Error: {checkout.output}"
        add_result = await run_shell_cmd(["git", "add", "-A"])
        if not add_result.ok:
            return f"Error: {add_result.output}"
        commit_result = await run_shell_cmd(["git", "commit", "-m", title])
        if not commit_result.ok:
            return f"Error: {commit_result.output}"

        out = "Created branch and committed locally"

        if push:
            # Check policy for push
            policy_result = evaluate_push(branch_name)

            if policy_result.requires_approval:
                approved = await require_approval(
                    "create_pr_push",
                    policy_result.approval_reason or "Push requires approval",
                    {"branch": branch_name},
                )
                if not approved:
                    return out + " (push cancelled: approval denied)"

            push_result = await run_shell_cmd(["git", "push", "-u", "origin", branch_name])
            if not push_result.ok:
                return f"Error: {push_result.output}"
            out = push_result.output

        log_audit("create_pr", {"branch": branch_name, "title": title, "pushed": push})
        return out

    # =========================================================================
    # Summary & Diagnostics
    # =========================================================================

    @mcp.tool()
    async def summarize_changes() -> str:
        """Get a summary of recent changes.

        Returns:
            Diff of last commit
        """
        diff = await run_shell_cmd(["git", "--no-pager", "diff", "HEAD~1..HEAD"])
        if not diff.output:
            return "No recent changes detected."
        return truncate_output(diff.output)

    @mcp.tool()
    async def health() -> str:
        """Health check endpoint.

        Returns:
            'ok' if healthy
        """
        return "ok"

    @mcp.tool()
    async def list_tools() -> str:
        """List available tools.

        Returns:
            JSON array of tool names
        """
        tools = [t.__name__ for t in mcp._tools] if hasattr(mcp, "_tools") else []
        return json.dumps(tools)

    # =========================================================================
    # Approval Management
    # =========================================================================

    @mcp.tool()
    async def list_pending_approvals(token: str | None = None) -> str:
        """List pending approval requests.

        Args:
            token: Optional approval token if configured

        Returns:
            JSON array of pending approvals
        """
        error = _validate_approval_token(token)
        if error:
            return error
        manager = get_approval_manager()
        pending = manager.list_pending()
        return json.dumps([req.to_dict() for req in pending], indent=2)

    @mcp.tool()
    async def approve_request(
        request_id: str,
        reviewer: str = "cli_user",
        comment: str | None = None,
        token: str | None = None,
    ) -> str:
        """Approve a pending request.

        Args:
            request_id: ID of the request to approve
            reviewer: Name of the approver
            comment: Optional comment
            token: Optional approval token if configured

        Returns:
            Confirmation message
        """
        error = _validate_approval_token(token)
        if error:
            return error
        manager = get_approval_manager()
        try:
            request = manager.approve(request_id, reviewer, comment)
            return f"Approved: {request_id}"
        except (KeyError, ValueError) as e:
            return f"Error: {e}"

    @mcp.tool()
    async def reject_request(
        request_id: str,
        reviewer: str = "cli_user",
        comment: str | None = None,
        token: str | None = None,
    ) -> str:
        """Reject a pending request.

        Args:
            request_id: ID of the request to reject
            reviewer: Name of the rejector
            comment: Optional rejection reason
            token: Optional approval token if configured

        Returns:
            Confirmation message
        """
        error = _validate_approval_token(token)
        if error:
            return error
        manager = get_approval_manager()
        try:
            request = manager.reject(request_id, reviewer, comment)
            return f"Rejected: {request_id}"
        except (KeyError, ValueError) as e:
            return f"Error: {e}"
