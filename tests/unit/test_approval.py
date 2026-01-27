"""Tests for approval request behavior."""

import importlib
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from titanium_repo_operator.approval import ApprovalManager


@pytest.mark.asyncio
async def test_request_approval_timeout_uses_timedelta(temp_dir) -> None:
    approval_file = temp_dir / "approvals.json"
    manager = ApprovalManager(approval_timeout_seconds=3600, approval_file=approval_file)

    request = await manager.request_approval(
        operation="test-operation",
        reason="Test timeout window",
    )

    assert request.expires_at is not None
    assert request.expires_at - request.created_at == timedelta(seconds=3600)


@pytest.mark.asyncio
async def test_auto_approve_in_dev_mode(
    temp_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REPO_ROOT", str(temp_dir))
    monkeypatch.setenv("TITANIUM_DEV_MODE", "true")
    monkeypatch.setenv("TITANIUM_AUTO_APPROVE_IN_DEV", "true")
    monkeypatch.chdir(temp_dir)

    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    import titanium_repo_operator.config as config
    importlib.reload(config)
    import titanium_repo_operator.approval as approval
    importlib.reload(approval)

    result = await approval.require_approval(
        operation="test-operation",
        reason="Dev auto approve",
    )

    assert result is True
