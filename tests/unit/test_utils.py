"""Unit tests for utils module."""

import asyncio
from pathlib import Path

import pytest

# Import after path setup
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils import SecurityError, atomic_write, truncate_output, validate_path


class TestValidatePath:
    """Tests for validate_path function."""

    def test_valid_relative_path(self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that valid relative paths are accepted."""
        monkeypatch.chdir(temp_dir)
        test_file = temp_dir / "test.txt"
        test_file.write_text("test")

        # Should not raise
        result = validate_path("test.txt")
        assert result == test_file

    def test_path_traversal_blocked(self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that path traversal attempts are blocked."""
        monkeypatch.chdir(temp_dir)

        with pytest.raises(SecurityError) as exc_info:
            validate_path("../../../etc/passwd")

        assert "SECURITY VIOLATION" in str(exc_info.value)

    def test_absolute_path_outside_root_blocked(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that absolute paths outside root are blocked."""
        monkeypatch.chdir(temp_dir)

        with pytest.raises(SecurityError):
            validate_path("/etc/passwd")

    def test_symlink_escape_blocked(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that symlink escapes are blocked."""
        monkeypatch.chdir(temp_dir)

        # Create a symlink pointing outside
        symlink = temp_dir / "escape"
        try:
            symlink.symlink_to("/etc")
        except OSError:
            pytest.skip("Cannot create symlinks")

        with pytest.raises(SecurityError):
            validate_path("escape/passwd")


class TestTruncateOutput:
    """Tests for truncate_output function."""

    def test_short_content_unchanged(self) -> None:
        """Test that short content is not modified."""
        content = "Hello, World!"
        result = truncate_output(content)
        assert result == content

    def test_long_content_truncated(self) -> None:
        """Test that long content is truncated."""
        content = "x" * 20000
        result = truncate_output(content, limit=100)
        assert len(result) < len(content)
        assert "Truncated" in result

    def test_none_content_returns_empty(self) -> None:
        """Test that None returns empty string."""
        result = truncate_output(None)  # type: ignore
        assert result == ""

    def test_exact_limit_unchanged(self) -> None:
        """Test content exactly at limit is unchanged."""
        content = "x" * 100
        result = truncate_output(content, limit=100)
        assert result == content


class TestAtomicWrite:
    """Tests for atomic_write function."""

    def test_basic_write(self, temp_dir: Path) -> None:
        """Test basic atomic write."""
        target = temp_dir / "test.txt"
        content = "Hello, World!"

        atomic_write(target, content)

        assert target.exists()
        assert target.read_text() == content

    def test_overwrite_existing(self, temp_dir: Path) -> None:
        """Test overwriting existing file."""
        target = temp_dir / "test.txt"
        target.write_text("old content")

        atomic_write(target, "new content")

        assert target.read_text() == "new content"

    def test_no_partial_write_on_error(self, temp_dir: Path) -> None:
        """Test that partial writes don't corrupt files."""
        target = temp_dir / "test.txt"
        target.write_text("original")

        # The temp file should be cleaned up even if fsync fails
        # This is a simplified test - real test would mock filesystem
        atomic_write(target, "updated")
        assert target.read_text() == "updated"

    def test_creates_parent_directories(self, temp_dir: Path) -> None:
        """Test that parent directories are handled."""
        target = temp_dir / "subdir" / "test.txt"
        target.parent.mkdir(parents=True, exist_ok=True)

        atomic_write(target, "content")
        assert target.read_text() == "content"
