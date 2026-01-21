"""Commit signing support for provenance verification.

Provides mechanisms to sign commits for provenance tracking:
- GPG signing (traditional)
- SSH signing (modern, simpler key management)
- Sigstore/Gitsign (keyless, OIDC-based)

This module handles the configuration and execution of signed commits
to ensure cryptographic proof of agent-generated changes.
"""

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .utils import run_shell_cmd


class SigningMethod(Enum):
    """Available signing methods."""
    NONE = "none"
    GPG = "gpg"
    SSH = "ssh"
    SIGSTORE = "sigstore"


@dataclass
class SigningConfig:
    """Configuration for commit signing."""
    method: SigningMethod = SigningMethod.NONE
    key_id: str | None = None  # GPG key ID or SSH key path
    ssh_allowed_signers: Path | None = None  # For SSH verification


class CommitSigner:
    """Handles commit signing operations."""

    def __init__(self, config: SigningConfig | None = None):
        self.config = config or self._load_config_from_env()

    def _load_config_from_env(self) -> SigningConfig:
        """Load signing configuration from environment variables."""
        method_str = os.environ.get("TITANIUM_SIGNING_METHOD", "none").lower()

        try:
            method = SigningMethod(method_str)
        except ValueError:
            method = SigningMethod.NONE

        key_id = os.environ.get("TITANIUM_SIGNING_KEY")

        ssh_signers_path = os.environ.get("TITANIUM_SSH_ALLOWED_SIGNERS")
        ssh_allowed_signers = Path(ssh_signers_path) if ssh_signers_path else None

        return SigningConfig(
            method=method,
            key_id=key_id,
            ssh_allowed_signers=ssh_allowed_signers,
        )

    async def configure_git_signing(self, repo_path: Path | None = None) -> bool:
        """Configure git for signing commits.

        Args:
            repo_path: Repository path (uses global config if None)

        Returns:
            True if configuration succeeded
        """
        if self.config.method == SigningMethod.NONE:
            return True

        cwd = repo_path

        if self.config.method == SigningMethod.GPG:
            return await self._configure_gpg(cwd)
        elif self.config.method == SigningMethod.SSH:
            return await self._configure_ssh(cwd)
        elif self.config.method == SigningMethod.SIGSTORE:
            return await self._configure_sigstore(cwd)

        return False

    async def _configure_gpg(self, cwd: Path | None) -> bool:
        """Configure GPG signing."""
        if not self.config.key_id:
            return False

        commands = [
            ["git", "config", "commit.gpgsign", "true"],
            ["git", "config", "user.signingkey", self.config.key_id],
            ["git", "config", "gpg.program", "gpg"],
        ]

        for cmd in commands:
            result = await run_shell_cmd(cmd, cwd=cwd)
            if not result.ok:
                return False

        return True

    async def _configure_ssh(self, cwd: Path | None) -> bool:
        """Configure SSH signing."""
        if not self.config.key_id:
            return False

        key_path = Path(self.config.key_id).expanduser()
        if not key_path.exists():
            return False

        commands = [
            ["git", "config", "commit.gpgsign", "true"],
            ["git", "config", "gpg.format", "ssh"],
            ["git", "config", "user.signingkey", str(key_path)],
        ]

        if self.config.ssh_allowed_signers:
            commands.append([
                "git", "config", "gpg.ssh.allowedSignersFile",
                str(self.config.ssh_allowed_signers)
            ])

        for cmd in commands:
            result = await run_shell_cmd(cmd, cwd=cwd)
            if not result.ok:
                return False

        return True

    async def _configure_sigstore(self, cwd: Path | None) -> bool:
        """Configure Sigstore/Gitsign signing.

        Requires gitsign to be installed: https://github.com/sigstore/gitsign
        """
        # Check if gitsign is available
        check = await run_shell_cmd(["which", "gitsign"])
        if not check.ok or not check.output.strip():
            return False

        commands = [
            ["git", "config", "commit.gpgsign", "true"],
            ["git", "config", "gpg.format", "x509"],
            ["git", "config", "gpg.x509.program", "gitsign"],
        ]

        for cmd in commands:
            result = await run_shell_cmd(cmd, cwd=cwd)
            if not result.ok:
                return False

        return True

    async def sign_commit(
        self,
        message: str,
        repo_path: Path,
        amend: bool = False,
    ) -> tuple[bool, str]:
        """Create a signed commit.

        Args:
            message: Commit message
            repo_path: Path to the repository
            amend: Whether to amend the last commit

        Returns:
            Tuple of (success, output/error)
        """
        # Ensure signing is configured
        if self.config.method != SigningMethod.NONE:
            configured = await self.configure_git_signing(repo_path)
            if not configured:
                return False, f"Failed to configure {self.config.method.value} signing"

        # Build commit command
        cmd = ["git", "commit"]

        if self.config.method != SigningMethod.NONE:
            cmd.append("-S")  # Sign the commit

        if amend:
            cmd.append("--amend")

        cmd.extend(["-m", message])

        result = await run_shell_cmd(cmd, cwd=repo_path)

        if not result.ok:
            return False, result.output

        return True, result.output

    async def verify_commit(
        self,
        commit_ref: str,
        repo_path: Path,
    ) -> tuple[bool, str]:
        """Verify a commit signature.

        Args:
            commit_ref: Commit reference (SHA, branch, etc.)
            repo_path: Path to the repository

        Returns:
            Tuple of (valid, output/error)
        """
        result = await run_shell_cmd(
            ["git", "verify-commit", commit_ref],
            cwd=repo_path
        )

        # Git returns error code for invalid signatures
        is_valid = "good signature" in result.output.lower() or "valid signature" in result.output.lower()

        return is_valid, result.output

    async def get_commit_signature_info(
        self,
        commit_ref: str,
        repo_path: Path,
    ) -> dict[str, Any]:
        """Get signature information for a commit.

        Args:
            commit_ref: Commit reference
            repo_path: Path to the repository

        Returns:
            Dict with signature information
        """
        # Get signature status
        result = await run_shell_cmd(
            ["git", "log", "-1", "--format=%G?|%GK|%GS|%GP", commit_ref],
            cwd=repo_path
        )

        parts = result.output.strip().split("|")

        status_map = {
            "G": "good",
            "B": "bad",
            "U": "unknown_validity",
            "X": "expired",
            "Y": "expired_key",
            "R": "revoked",
            "E": "cannot_check",
            "N": "no_signature",
        }

        status_code = parts[0] if parts else "N"

        return {
            "status": status_map.get(status_code, "unknown"),
            "status_code": status_code,
            "key_id": parts[1] if len(parts) > 1 else None,
            "signer": parts[2] if len(parts) > 2 else None,
            "primary_key": parts[3] if len(parts) > 3 else None,
            "is_signed": status_code != "N",
            "is_valid": status_code == "G",
        }


# Global signer instance
_commit_signer: CommitSigner | None = None


def get_commit_signer() -> CommitSigner:
    """Get or create the global commit signer."""
    global _commit_signer
    if _commit_signer is None:
        _commit_signer = CommitSigner()
    return _commit_signer


async def sign_commit(
    message: str,
    repo_path: Path,
    amend: bool = False,
) -> tuple[bool, str]:
    """Convenience function to create a signed commit."""
    return await get_commit_signer().sign_commit(message, repo_path, amend)


async def verify_commit(commit_ref: str, repo_path: Path) -> tuple[bool, str]:
    """Convenience function to verify a commit signature."""
    return await get_commit_signer().verify_commit(commit_ref, repo_path)
