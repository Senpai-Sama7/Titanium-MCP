# /// script
# dependencies = [
#   "fastmcp>=2.0.0",
#   "gitpython>=3.1",
#   "pydantic>=2.0",
#   "prometheus-client>=0.16",
#   "uvloop; platform_system != 'Windows'",
# ]
# ///

"""Titanium Repo Operator - main server

Run with: uv run server.py

This file wires together mcp_tools (exposed tools), audits, and a small HTTP health/metrics endpoint.
"""

import asyncio
import logging
import signal
import sys

# prefer uvloop when available for speed
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

from fastmcp import FastMCP

# Import centralized configuration
from .config import (
    AUDIT_HMAC_KEY,
    AUDITS_DIR,
    DEFAULT_AUDIT_HMAC_KEY,
    DEV_MODE,
    LOG_LEVEL,
    REPO_ROOT,
    WORKTREES_DIR,
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
log = logging.getLogger("titanium")

# Log startup configuration
log.info("Titanium Repo Operator starting...")
log.info("REPO_ROOT: %s", REPO_ROOT)
log.info("WORKTREES_DIR: %s", WORKTREES_DIR)
log.info("AUDITS_DIR: %s", AUDITS_DIR)
if not DEV_MODE and AUDIT_HMAC_KEY == DEFAULT_AUDIT_HMAC_KEY:
    log.error("TITANIUM_AUDIT_KEY must be set in non-dev environments.")
    raise SystemExit(1)

# Instantiate FastMCP
mcp = FastMCP("TitaniumOperator")

# Import and register tools
from .mcp_tools import register_tools
register_tools(mcp)


def _setup_signals(loop: asyncio.AbstractEventLoop) -> None:
    """Set up signal handlers for graceful shutdown."""
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(_shutdown(loop, s)))


async def _shutdown(loop: asyncio.AbstractEventLoop, sig: signal.Signals) -> None:
    """Handle graceful shutdown."""
    log.info("Received signal %s, initiating graceful shutdown...", sig.name)

    # Attempt to shutdown MCP gracefully
    try:
        if hasattr(mcp, 'shutdown'):
            await mcp.shutdown()
    except Exception as e:
        log.warning("Error during MCP shutdown: %s", e)

    # Cancel all pending tasks
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if tasks:
        log.info("Cancelling %d pending tasks...", len(tasks))
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    loop.stop()
    log.info("Shutdown complete")


def main() -> None:
    """Run the MCP server on stdio."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    _setup_signals(loop)
    log.info("Starting Titanium MCP server on stdio...")

    # Run MCP (blocking call)
    mcp.run()


if __name__ == "__main__":
    main()
