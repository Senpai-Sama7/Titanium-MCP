"""Centralized configuration for Titanium Repo Operator.

All path and environment configuration should be imported from this module
to ensure consistency across the codebase.
"""

import os
from pathlib import Path

# Repository root - configurable via environment for container deployments
REPO_ROOT = Path(os.environ.get("REPO_ROOT", os.getcwd())).resolve()

# Standard directories
WORKTREES_DIR = REPO_ROOT / "worktrees"
AUDITS_DIR = REPO_ROOT / "audits"

# Ensure directories exist
WORKTREES_DIR.mkdir(exist_ok=True)
AUDITS_DIR.mkdir(exist_ok=True)

# Logging configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Audit configuration
AUDIT_HMAC_KEY = os.environ.get("TITANIUM_AUDIT_KEY", "dev-key-change-me")

# Agent constraints (policy defaults)
MAX_LOC_PER_PATCH = int(os.environ.get("TITANIUM_MAX_LOC", "500"))
MAX_FILES_PER_PATCH = int(os.environ.get("TITANIUM_MAX_FILES", "20"))
MAX_ITERATIONS_PER_TASK = int(os.environ.get("TITANIUM_MAX_ITERATIONS", "10"))
REQUIRE_APPROVAL_FOR_PUSH = os.environ.get("TITANIUM_REQUIRE_APPROVAL", "true").lower() == "true"

# Command execution
SHELL_TIMEOUT = int(os.environ.get("TITANIUM_SHELL_TIMEOUT", "30"))
OUTPUT_TRUNCATE_LIMIT = int(os.environ.get("TITANIUM_OUTPUT_LIMIT", "16000"))
