"""Compatibility shim for running the server from repo root."""

from titanium_repo_operator.server import main, mcp

if __name__ == "__main__":
    main()
