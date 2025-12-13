"""Human approval middleware for high-risk operations.

Provides a mechanism for pausing agent operations and requesting
human approval before proceeding with sensitive actions.
"""

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Awaitable

from audit import log_audit
from config import AUDITS_DIR


class ApprovalStatus(Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class ApprovalRequest:
    """A request for human approval."""
    id: str
    operation: str
    reason: str
    context: dict
    created_at: datetime
    expires_at: datetime | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_comment: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "operation": self.operation,
            "reason": self.reason,
            "context": self.context,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_comment": self.review_comment,
        }

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


class ApprovalManager:
    """Manages approval requests and their lifecycle."""

    def __init__(
        self,
        approval_timeout_seconds: int = 3600,  # 1 hour default
        approval_file: Path | None = None,
    ):
        self.timeout_seconds = approval_timeout_seconds
        self.approval_file = approval_file or (AUDITS_DIR / "pending_approvals.json")
        self._pending: dict[str, ApprovalRequest] = {}
        self._callbacks: dict[str, asyncio.Event] = {}
        self._load_pending()

    def _load_pending(self) -> None:
        """Load pending approvals from disk."""
        if self.approval_file.exists():
            try:
                data = json.loads(self.approval_file.read_text())
                for item in data:
                    req = ApprovalRequest(
                        id=item["id"],
                        operation=item["operation"],
                        reason=item["reason"],
                        context=item["context"],
                        created_at=datetime.fromisoformat(item["created_at"]),
                        expires_at=datetime.fromisoformat(item["expires_at"]) if item.get("expires_at") else None,
                        status=ApprovalStatus(item["status"]),
                    )
                    if req.status == ApprovalStatus.PENDING and not req.is_expired():
                        self._pending[req.id] = req
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_pending(self) -> None:
        """Persist pending approvals to disk."""
        data = [req.to_dict() for req in self._pending.values()]
        self.approval_file.write_text(json.dumps(data, indent=2))

    async def request_approval(
        self,
        operation: str,
        reason: str,
        context: dict | None = None,
        timeout_seconds: int | None = None,
    ) -> ApprovalRequest:
        """Create a new approval request.

        Args:
            operation: Type of operation requiring approval
            reason: Human-readable explanation of why approval is needed
            context: Additional context about the operation
            timeout_seconds: Override default timeout

        Returns:
            The created ApprovalRequest
        """
        timeout = timeout_seconds or self.timeout_seconds
        now = datetime.now(timezone.utc)

        request = ApprovalRequest(
            id=f"apr-{uuid.uuid4().hex[:12]}",
            operation=operation,
            reason=reason,
            context=context or {},
            created_at=now,
            expires_at=now.replace(second=now.second + timeout) if timeout > 0 else None,
        )

        self._pending[request.id] = request
        self._callbacks[request.id] = asyncio.Event()
        self._save_pending()

        log_audit("approval_requested", {
            "request_id": request.id,
            "operation": operation,
            "reason": reason,
        })

        return request

    async def wait_for_approval(
        self,
        request_id: str,
        timeout: float | None = None,
    ) -> ApprovalRequest:
        """Wait for an approval decision.

        Args:
            request_id: ID of the approval request
            timeout: Maximum time to wait (uses request's expiry if None)

        Returns:
            Updated ApprovalRequest with decision

        Raises:
            TimeoutError: If approval times out
            KeyError: If request not found
        """
        if request_id not in self._pending:
            raise KeyError(f"Approval request {request_id} not found")

        request = self._pending[request_id]
        event = self._callbacks.get(request_id)

        if event is None:
            event = asyncio.Event()
            self._callbacks[request_id] = event

        # Calculate timeout
        if timeout is None and request.expires_at:
            remaining = (request.expires_at - datetime.now(timezone.utc)).total_seconds()
            timeout = max(0, remaining)

        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            request.status = ApprovalStatus.EXPIRED
            self._save_pending()
            log_audit("approval_expired", {"request_id": request_id})
            raise TimeoutError(f"Approval request {request_id} expired")

        return self._pending.get(request_id, request)

    def approve(
        self,
        request_id: str,
        reviewer: str = "unknown",
        comment: str | None = None,
    ) -> ApprovalRequest:
        """Approve a pending request.

        Args:
            request_id: ID of the request to approve
            reviewer: Identifier of the approving user
            comment: Optional review comment

        Returns:
            Updated ApprovalRequest

        Raises:
            KeyError: If request not found
            ValueError: If request is not pending
        """
        if request_id not in self._pending:
            raise KeyError(f"Approval request {request_id} not found")

        request = self._pending[request_id]

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request {request_id} is not pending (status: {request.status})")

        if request.is_expired():
            request.status = ApprovalStatus.EXPIRED
            self._save_pending()
            raise ValueError(f"Request {request_id} has expired")

        request.status = ApprovalStatus.APPROVED
        request.reviewed_by = reviewer
        request.reviewed_at = datetime.now(timezone.utc)
        request.review_comment = comment

        self._save_pending()

        # Signal waiting coroutines
        if request_id in self._callbacks:
            self._callbacks[request_id].set()

        log_audit("approval_granted", {
            "request_id": request_id,
            "reviewer": reviewer,
            "comment": comment,
        })

        return request

    def reject(
        self,
        request_id: str,
        reviewer: str = "unknown",
        comment: str | None = None,
    ) -> ApprovalRequest:
        """Reject a pending request.

        Args:
            request_id: ID of the request to reject
            reviewer: Identifier of the rejecting user
            comment: Optional rejection reason

        Returns:
            Updated ApprovalRequest

        Raises:
            KeyError: If request not found
            ValueError: If request is not pending
        """
        if request_id not in self._pending:
            raise KeyError(f"Approval request {request_id} not found")

        request = self._pending[request_id]

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request {request_id} is not pending (status: {request.status})")

        request.status = ApprovalStatus.REJECTED
        request.reviewed_by = reviewer
        request.reviewed_at = datetime.now(timezone.utc)
        request.review_comment = comment

        self._save_pending()

        # Signal waiting coroutines
        if request_id in self._callbacks:
            self._callbacks[request_id].set()

        log_audit("approval_rejected", {
            "request_id": request_id,
            "reviewer": reviewer,
            "comment": comment,
        })

        return request

    def cancel(self, request_id: str) -> ApprovalRequest:
        """Cancel a pending request.

        Args:
            request_id: ID of the request to cancel

        Returns:
            Updated ApprovalRequest
        """
        if request_id not in self._pending:
            raise KeyError(f"Approval request {request_id} not found")

        request = self._pending[request_id]
        request.status = ApprovalStatus.CANCELLED

        self._save_pending()

        if request_id in self._callbacks:
            self._callbacks[request_id].set()

        log_audit("approval_cancelled", {"request_id": request_id})

        return request

    def list_pending(self) -> list[ApprovalRequest]:
        """List all pending approval requests."""
        # Clean up expired requests
        now = datetime.now(timezone.utc)
        expired = [
            req_id for req_id, req in self._pending.items()
            if req.is_expired() and req.status == ApprovalStatus.PENDING
        ]
        for req_id in expired:
            self._pending[req_id].status = ApprovalStatus.EXPIRED

        if expired:
            self._save_pending()

        return [
            req for req in self._pending.values()
            if req.status == ApprovalStatus.PENDING
        ]

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        """Get a specific approval request."""
        return self._pending.get(request_id)


# Global approval manager instance
_approval_manager: ApprovalManager | None = None


def get_approval_manager() -> ApprovalManager:
    """Get or create the global approval manager."""
    global _approval_manager
    if _approval_manager is None:
        _approval_manager = ApprovalManager()
    return _approval_manager


async def require_approval(
    operation: str,
    reason: str,
    context: dict | None = None,
    auto_approve_in_dev: bool = True,
) -> bool:
    """Request and wait for human approval.

    Convenience function that creates a request and waits for decision.

    Args:
        operation: Type of operation
        reason: Why approval is needed
        context: Additional context
        auto_approve_in_dev: Auto-approve in development mode

    Returns:
        True if approved, False if rejected or expired
    """
    import os

    # Auto-approve in development mode if enabled
    if auto_approve_in_dev and os.environ.get("TITANIUM_DEV_MODE", "").lower() == "true":
        log_audit("approval_auto_approved", {
            "operation": operation,
            "reason": "Development mode auto-approval",
        })
        return True

    manager = get_approval_manager()
    request = await manager.request_approval(operation, reason, context)

    try:
        result = await manager.wait_for_approval(request.id)
        return result.status == ApprovalStatus.APPROVED
    except TimeoutError:
        return False
