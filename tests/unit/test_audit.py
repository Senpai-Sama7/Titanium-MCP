"""Unit tests for audit module."""

import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from titanium_repo_operator.audit import log_audit, sign_payload


class TestSignPayload:
    """Tests for HMAC signing."""

    def test_sign_payload_deterministic(self) -> None:
        """Test that signing is deterministic."""
        payload = b'{"event": "test"}'
        sig1 = sign_payload(payload)
        sig2 = sign_payload(payload)
        assert sig1 == sig2

    def test_sign_payload_different_for_different_input(self) -> None:
        """Test that different payloads produce different signatures."""
        sig1 = sign_payload(b'{"event": "test1"}')
        sig2 = sign_payload(b'{"event": "test2"}')
        assert sig1 != sig2

    def test_sign_payload_returns_hex(self) -> None:
        """Test that signature is hex-encoded."""
        sig = sign_payload(b"test")
        assert all(c in "0123456789abcdef" for c in sig)
        assert len(sig) == 64  # SHA256 hex = 64 chars


class TestLogAudit:
    """Tests for audit logging."""

    def test_log_audit_structure(self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that audit logs have correct structure."""
        # Patch AUDITS_DIR
        import audit
        monkeypatch.setattr(audit, "AUDITS_DIR", temp_dir)

        result = log_audit("test_event", {"key": "value"})

        assert "ts" in result
        assert "event" in result
        assert "meta" in result
        assert "hmac" in result
        assert result["event"] == "test_event"
        assert result["meta"] == {"key": "value"}

    def test_log_audit_writes_to_file(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that audit logs are written to file."""
        import audit
        monkeypatch.setattr(audit, "AUDITS_DIR", temp_dir)

        log_audit("test_event", {"test": True})

        audit_file = temp_dir / "audits.jsonl"
        assert audit_file.exists()

        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) >= 1

        entry = json.loads(lines[-1])
        assert entry["event"] == "test_event"

    def test_log_audit_timestamp_format(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that timestamp is ISO format with Z suffix."""
        import audit
        monkeypatch.setattr(audit, "AUDITS_DIR", temp_dir)

        result = log_audit("test", {})

        assert result["ts"].endswith("Z")
        assert "T" in result["ts"]

    def test_log_audit_hmac_verifiable(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that HMAC can be verified."""
        import audit
        monkeypatch.setattr(audit, "AUDITS_DIR", temp_dir)

        result = log_audit("test", {"data": "value"})

        # Reconstruct what was signed
        obj = {
            "ts": result["ts"],
            "event": result["event"],
            "meta": result["meta"],
        }
        payload = json.dumps(obj, sort_keys=True).encode("utf-8")
        expected_hmac = sign_payload(payload)

        assert result["hmac"] == expected_hmac
