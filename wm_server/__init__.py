"""
wm_server package

This package contains the WorkspaceManager server implementation (FastAPI service)
and related server-side modules. It is intentionally lightweight at import time
and avoids importing the FastAPI app by default to prevent side effects during
module discovery or tooling (e.g., linting, type-checking).

Public surface:
- __version__: string version of the server package

To run the service with uvicorn (example):
    uvicorn wm_server.app.main:app --host 127.0.0.1 --port 8081 --reload
"""

# Keep version definition synchronized with wm_server.app
try:
    from .app import __version__ as _app_version  # noqa: F401
except Exception:
    # Fallback static version if the submodule is unavailable
    _app_version = "0.1.0"

__version__ = _app_version

__all__ = ["__version__"]