"""Pytest configuration and shared fixtures."""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Generator

import pytest


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_repo(temp_dir: Path) -> Generator[Path, None, None]:
    """Create a temporary git repository for tests."""
    import subprocess

    repo_dir = temp_dir / "test_repo"
    repo_dir.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )

    # Create initial commit
    readme = repo_dir / "README.md"
    readme.write_text("# Test Repository\n")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )

    yield repo_dir


@pytest.fixture
def mock_env(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up mock environment variables for tests."""
    monkeypatch.setenv("REPO_ROOT", str(temp_dir))
    monkeypatch.setenv("TITANIUM_AUDIT_KEY", "test-key-for-testing")


@pytest.fixture
def sample_patch() -> str:
    """Sample git patch for testing."""
    return """diff --git a/test.py b/test.py
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/test.py
@@ -0,0 +1,3 @@
+def hello():
+    return "Hello, World!"
+
"""
