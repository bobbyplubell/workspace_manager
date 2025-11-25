"""
Test session bootstrap for workspace_manager

Ensures that the in-repo wm_server and wm_client packages are importable
without requiring editable installs. This mirrors what monorepo roots
often do, but scoped to the workspace_manager test package.

- Adds wm_server/src to sys.path so `import wm_server` works.
- Adds the wm_client/src directory to sys.path so `import wm_client` works.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path


def _add_sys_path(p: Path) -> None:
    """
    Prepend a filesystem path to sys.path if it's not already present.
    """
    try:
        rp = str(p.resolve())
    except Exception:
        rp = str(p)
    if rp not in sys.path:
        sys.path.insert(0, rp)


# Compute important paths relative to this file
_THIS_FILE = Path(__file__).resolve()
_TESTS_DIR = _THIS_FILE.parent                  # .../workspace_manager/tests
_PROJECT_DIR = _TESTS_DIR.parent                # .../workspace_manager
_REPO_ROOT = _PROJECT_DIR.parent                # .../splunky (monorepo root)

# Make wm_server importable (src layout lives under wm_server/src)
_WM_SERVER_SRC = _PROJECT_DIR / "wm_server" / "src"
if _WM_SERVER_SRC.exists():
    _add_sys_path(_WM_SERVER_SRC)
# Also add the project dir itself for backwards-compatibility helpers
_add_sys_path(_PROJECT_DIR)

# Make wm_client importable (client is laid out with a 'src' root)
_WM_CLIENT_SRC = _PROJECT_DIR / "wm_client" / "src"
if _WM_CLIENT_SRC.exists():
    _add_sys_path(_WM_CLIENT_SRC)

# Optionally add repo root in case tests reach across packages (harmless if unused)
_add_sys_path(_REPO_ROOT)


def _ensure_env(var: str, factory) -> str:
    existing = os.environ.get(var)
    if existing:
        return existing
    value = factory()
    os.environ[var] = value
    return value


_ensure_env("SPLUNK_PASSWORD", lambda: secrets.token_urlsafe(24))
os.environ.setdefault("SPLUNK_USERNAME", "admin")
os.environ.setdefault("WM_ALLOW_INSECURE_HTTP", "true")
