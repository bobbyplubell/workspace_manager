"""Command-line entry points for wm_server."""

from __future__ import annotations

import sys


def main() -> None:
    """Delegate to uvicorn's CLI entry point.

    Using an explicit shim avoids depending on uvicorn's private
    ``__main__`` module structure, which changed between versions.
    """

    try:
        from uvicorn.main import main as uvicorn_main
    except Exception as exc:  # pragma: no cover - import-time failure
        raise SystemExit(f"uvicorn is required to run wm_server CLI: {exc}")

    sys.exit(uvicorn_main())
