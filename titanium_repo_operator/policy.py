"""Policy engine for enforcing agent constraints.

Provides Cedar/OPA-style policy evaluation for autonomous agent operations.
Policies can restrict:
- Maximum lines of code per patch
- Maximum files modified per operation
- Prohibited file paths and patterns
- Required approval for specific operations
- Rate limiting per operation type
"""

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .config import (
    MAX_FILES_PER_PATCH,
    MAX_ITERATIONS_PER_TASK,
    MAX_LOC_PER_PATCH,
    REPO_ROOT,
    REQUIRE_APPROVAL_FOR_PUSH,
)


class PolicyDecision(Enum):
    """Result of a policy evaluation."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class PolicyViolation:
    """Details of a policy violation."""
    policy_name: str
    reason: str
    details: dict = field(default_factory=dict)


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    decision: PolicyDecision
    violations: list[PolicyViolation] = field(default_factory=list)
    requires_approval: bool = False
    approval_reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecision.ALLOW

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "violations": [
                {"policy": v.policy_name, "reason": v.reason, "details": v.details}
                for v in self.violations
            ],
            "requires_approval": self.requires_approval,
            "approval_reason": self.approval_reason,
        }


# Prohibited path patterns (production safety)
PROHIBITED_PATTERNS = [
    "*.env",
    "*.env.*",
    ".env*",
    "**/secrets/**",
    "**/credentials/**",
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/id_rsa*",
    "**/*.pem",
    "**/*.key",
    "**/config/production*",
    "**/prod/**",
    "Dockerfile",  # Require approval for container changes
    "docker-compose*.yml",
    ".github/workflows/*",  # Require approval for CI changes
    "pyproject.toml",  # Require approval for dependency changes
    "requirements*.txt",
]

# Patterns requiring human approval
APPROVAL_REQUIRED_PATTERNS = [
    "Dockerfile",
    "docker-compose*.yml",
    ".github/workflows/*",
    "**/migrations/**",
    "pyproject.toml",
    "package.json",
    "**/security/**",
]


class PolicyEngine:
    """Evaluates operations against defined policies."""

    def __init__(
        self,
        max_loc: int = MAX_LOC_PER_PATCH,
        max_files: int = MAX_FILES_PER_PATCH,
        max_iterations: int = MAX_ITERATIONS_PER_TASK,
        require_approval_for_push: bool = REQUIRE_APPROVAL_FOR_PUSH,
        prohibited_patterns: list[str] | None = None,
        approval_patterns: list[str] | None = None,
    ):
        self.max_loc = max_loc
        self.max_files = max_files
        self.max_iterations = max_iterations
        self.require_approval_for_push = require_approval_for_push
        self.prohibited_patterns = prohibited_patterns or PROHIBITED_PATTERNS
        self.approval_patterns = approval_patterns or APPROVAL_REQUIRED_PATTERNS
        self._iteration_count: dict[str, int] = {}

    def evaluate_patch(
        self,
        patch_text: str,
        affected_files: list[str],
        task_id: str | None = None,
    ) -> PolicyResult:
        """Evaluate a patch against all policies.

        Args:
            patch_text: The patch content
            affected_files: List of files modified by the patch
            task_id: Optional task identifier for iteration tracking

        Returns:
            PolicyResult with decision and any violations
        """
        violations: list[PolicyViolation] = []
        requires_approval = False
        approval_reasons: list[str] = []

        # Check LOC limit
        loc_count = self._count_loc(patch_text)
        if loc_count > self.max_loc:
            violations.append(PolicyViolation(
                policy_name="max_loc",
                reason=f"Patch exceeds maximum LOC ({loc_count} > {self.max_loc})",
                details={"loc_count": loc_count, "max_loc": self.max_loc}
            ))

        # Check file count limit
        if len(affected_files) > self.max_files:
            violations.append(PolicyViolation(
                policy_name="max_files",
                reason=f"Patch affects too many files ({len(affected_files)} > {self.max_files})",
                details={"file_count": len(affected_files), "max_files": self.max_files}
            ))

        # Check for prohibited paths
        for file_path in affected_files:
            if self._matches_patterns(file_path, self.prohibited_patterns):
                violations.append(PolicyViolation(
                    policy_name="prohibited_path",
                    reason=f"File '{file_path}' matches prohibited pattern",
                    details={"file": file_path}
                ))

            # Check for approval-required paths
            if self._matches_patterns(file_path, self.approval_patterns):
                requires_approval = True
                approval_reasons.append(f"Modifying sensitive file: {file_path}")

        # Check iteration limit
        if task_id:
            self._iteration_count[task_id] = self._iteration_count.get(task_id, 0) + 1
            if self._iteration_count[task_id] > self.max_iterations:
                violations.append(PolicyViolation(
                    policy_name="max_iterations",
                    reason=f"Task exceeded maximum iterations ({self._iteration_count[task_id]} > {self.max_iterations})",
                    details={"iterations": self._iteration_count[task_id], "max": self.max_iterations}
                ))

        # Determine final decision
        if violations:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                violations=violations,
            )
        elif requires_approval:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                requires_approval=True,
                approval_reason="; ".join(approval_reasons),
            )
        else:
            return PolicyResult(decision=PolicyDecision.ALLOW)

    def evaluate_push(self, branch: str, is_protected: bool = False) -> PolicyResult:
        """Evaluate a push operation.

        Args:
            branch: Target branch name
            is_protected: Whether the branch is protected

        Returns:
            PolicyResult with decision
        """
        if is_protected or branch in ("main", "master", "production", "prod"):
            if self.require_approval_for_push:
                return PolicyResult(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    requires_approval=True,
                    approval_reason=f"Push to protected branch '{branch}' requires approval",
                )

        return PolicyResult(decision=PolicyDecision.ALLOW)

    def evaluate_command(self, command: list[str]) -> PolicyResult:
        """Evaluate a shell command.

        Args:
            command: Command and arguments

        Returns:
            PolicyResult with decision
        """
        # Block dangerous commands
        dangerous_commands = {
            "rm": ["-rf /", "-rf /*", "-rf ~"],
            "chmod": ["777"],
            "curl": ["|", "| sh", "| bash"],
            "wget": ["|", "| sh", "| bash"],
        }

        cmd_name = command[0] if command else ""
        cmd_args = " ".join(command[1:]) if len(command) > 1 else ""

        if cmd_name in dangerous_commands:
            for pattern in dangerous_commands[cmd_name]:
                if pattern in cmd_args:
                    return PolicyResult(
                        decision=PolicyDecision.DENY,
                        violations=[PolicyViolation(
                            policy_name="dangerous_command",
                            reason=f"Command '{cmd_name}' with dangerous pattern '{pattern}'",
                            details={"command": command}
                        )]
                    )

        return PolicyResult(decision=PolicyDecision.ALLOW)

    def reset_iterations(self, task_id: str) -> None:
        """Reset iteration counter for a task."""
        if task_id in self._iteration_count:
            del self._iteration_count[task_id]

    def _count_loc(self, patch_text: str) -> int:
        """Count lines of code added/modified in a patch."""
        loc = 0
        for line in patch_text.split("\n"):
            # Count added lines (excluding patch headers)
            if line.startswith("+") and not line.startswith("+++"):
                loc += 1
            # Count removed lines
            if line.startswith("-") and not line.startswith("---"):
                loc += 1
        return loc

    def _matches_patterns(self, path: str, patterns: list[str]) -> bool:
        """Check if a path matches any of the given patterns."""
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
            # Also check against basename
            if fnmatch.fnmatch(Path(path).name, pattern):
                return True
        return False


# Global policy engine instance
_policy_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """Get or create the global policy engine."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine


def evaluate_patch(
    patch_text: str,
    affected_files: list[str],
    task_id: str | None = None
) -> PolicyResult:
    """Convenience function to evaluate a patch."""
    return get_policy_engine().evaluate_patch(patch_text, affected_files, task_id)


def evaluate_push(branch: str, is_protected: bool = False) -> PolicyResult:
    """Convenience function to evaluate a push."""
    return get_policy_engine().evaluate_push(branch, is_protected)


def evaluate_command(command: list[str]) -> PolicyResult:
    """Convenience function to evaluate a command."""
    return get_policy_engine().evaluate_command(command)
