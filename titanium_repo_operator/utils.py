"""Utility helpers: path validation, safe shell execution, atomic write, truncation."""

import asyncio
import os
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from .config import OUTPUT_TRUNCATE_LIMIT, REPO_ROOT, SHELL_TIMEOUT


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass


@dataclass
class CommandResult:
    """Result of a shell command execution."""

    stdout: str
    stderr: str
    returncode: int
    duration_ms: float

    @property
    def output(self) -> str:
        return f"{self.stdout}{self.stderr}"

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def validate_path(p: str) -> Path:
    """Validate that a path is within the repository root.

    Args:
        p: The path to validate (relative or absolute)

    Returns:
        The resolved absolute path

    Raises:
        SecurityError: If the path escapes the repository root
    """
    repo_root = REPO_ROOT.resolve()
    candidate = Path(p)
    if not candidate.is_absolute():
        candidate = (repo_root / candidate).resolve()
    else:
        candidate = candidate.resolve()

    try:
        candidate.relative_to(repo_root)
    except ValueError:
        raise SecurityError(f"SECURITY VIOLATION: Path '{p}' escapes repository root")

    return candidate


def truncate_output(content: str | None, limit: int = OUTPUT_TRUNCATE_LIMIT) -> str:
    """Truncate output to prevent excessive memory usage.

    Args:
        content: The content to truncate
        limit: Maximum number of characters

    Returns:
        The truncated content with indicator if truncated
    """
    if content is None:
        return ""
    if len(content) <= limit:
        return content
    return content[:limit] + f"\n... [Truncated {len(content) - limit} chars]"


async def run_shell_cmd(
    args: list[str] | str,
    cwd: Path | None = None,
    timeout: int = SHELL_TIMEOUT
) -> CommandResult:
    """Execute a shell command safely with timeout.

    Uses create_subprocess_exec which does NOT invoke a shell,
    preventing shell injection attacks. Arguments are passed
    directly to the process.

    Args:
        args: Command and arguments (list or string)
        cwd: Working directory for the command
        timeout: Maximum execution time in seconds

    Returns:
        Combined stdout and stderr, truncated if necessary
    """
    if isinstance(args, str):
        args = shlex.split(args)

    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )

        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        duration_ms = (time.perf_counter() - start) * 1000
        stdout_text = stdout.decode() if stdout else ""
        stderr_text = stderr.decode() if stderr else ""
        return CommandResult(
            stdout=truncate_output(stdout_text),
            stderr=truncate_output(stderr_text),
            returncode=proc.returncode or 0,
            duration_ms=duration_ms,
        )

    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        duration_ms = (time.perf_counter() - start) * 1000
        return CommandResult(
            stdout="",
            stderr=f"Error: Command timed out after {timeout}s",
            returncode=124,
            duration_ms=duration_ms,
        )
    except FileNotFoundError:
        duration_ms = (time.perf_counter() - start) * 1000
        return CommandResult(
            stdout="",
            stderr=f"Error: Command not found: {args[0]}",
            returncode=127,
            duration_ms=duration_ms,
        )
    except Exception as e:
        duration_ms = (time.perf_counter() - start) * 1000
        return CommandResult(
            stdout="",
            stderr=f"Error executing command: {e}",
            returncode=1,
            duration_ms=duration_ms,
        )


def atomic_write(path: Path, content: str) -> None:
    """Write content to a file atomically.

    Uses a temporary file and rename to ensure the write is atomic.
    This prevents partial writes from corrupting files.

    Args:
        path: Target file path
        content: Content to write
    """
    tmp = path.with_suffix(path.suffix + ".tmp")

    try:
        tmp.write_text(content, encoding="utf-8")

        # Flush to disk
        try:
            with open(tmp, 'rb') as f:
                os.fsync(f.fileno())
        except OSError:
            pass

        # Atomic rename
        tmp.replace(path)

        # Sync parent directory
        try:
            parent_fd = os.open(str(path.parent), os.O_RDONLY)
            os.fsync(parent_fd)
            os.close(parent_fd)
        except OSError:
            pass

    except Exception:
        # Clean up temp file on error
        if tmp.exists():
            tmp.unlink()
        raise
