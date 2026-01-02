"""Tests for approval request behavior."""

from datetime import timedelta

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
