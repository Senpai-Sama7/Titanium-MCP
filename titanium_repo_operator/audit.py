"""Audit logging with HMAC signing for tamper detection."""

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

from .config import AUDITS_DIR, AUDIT_HMAC_KEY


def sign_payload(payload: bytes) -> str:
    """Generate HMAC-SHA256 signature for a payload.

    Args:
        payload: The bytes to sign

    Returns:
        Hex-encoded HMAC signature
    """
    return hmac.new(
        AUDIT_HMAC_KEY.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()


def _write_jsonl(filename: Path, obj: dict) -> None:
    """Append a JSON object to a JSONL file.

    Args:
        filename: Path to the JSONL file
        obj: Dictionary to write as JSON
    """
    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def log_audit(event: str, meta: dict) -> dict:
    """Log an audit event with HMAC signature.

    Creates a tamper-evident audit log entry with:
    - ISO timestamp with UTC timezone
    - Event type
    - Arbitrary metadata
    - HMAC signature over the payload

    Args:
        event: The event type (e.g., "patch_applied", "worktree_spawned")
        meta: Additional metadata for the event

    Returns:
        The complete audit entry including HMAC
    """
    obj = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": event,
        "meta": meta,
    }

    # Sign the payload before adding HMAC
    payload = json.dumps(obj, sort_keys=True).encode("utf-8")
    obj["hmac"] = sign_payload(payload)

    # Write to audit log
    _write_jsonl(AUDITS_DIR / "audits.jsonl", obj)

    return obj


def verify_audit_entry(entry: dict) -> bool:
    """Verify the HMAC signature of an audit entry.

    Args:
        entry: The audit entry to verify

    Returns:
        True if signature is valid, False otherwise
    """
    entry_copy = dict(entry)
    stored_hmac = entry_copy.pop("hmac", None)
    if not stored_hmac:
        return False

    payload = json.dumps(entry_copy, sort_keys=True).encode("utf-8")
    expected_hmac = sign_payload(payload)

    return hmac.compare_digest(stored_hmac, expected_hmac)
