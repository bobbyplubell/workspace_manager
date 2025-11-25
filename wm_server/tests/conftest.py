# Pytest configuration for WorkspaceManager tests.
# - Registers a "docker" marker for tests that require a running Docker daemon.
# - Automatically skips tests marked with @pytest.mark.docker when Docker is unavailable.

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path
from typing import Tuple

import pytest


def _add_sys_path(p: Path) -> None:
    """
    Prepend a filesystem path to sys.path if it's not already present.
    Ensures in-repo packages are importable without editable installs.
    """
    try:
        rp = str(p.resolve())
    except Exception:
        rp = str(p)
    if rp not in sys.path:
        sys.path.insert(0, rp)


# Make the workspace_manager project root importable so `import wm_server` works
_THIS_FILE = Path(__file__).resolve()
_TESTS_DIR = _THIS_FILE.parent                  # .../workspace_manager/wm_server/tests
_PROJECT_DIR = _TESTS_DIR.parent.parent         # .../workspace_manager
_REPO_ROOT = _PROJECT_DIR.parent                # repo root

_WM_SERVER_SRC = _PROJECT_DIR / "wm_server" / "src"
if _WM_SERVER_SRC.exists():
    _add_sys_path(_WM_SERVER_SRC)

_add_sys_path(_PROJECT_DIR)
_add_sys_path(_REPO_ROOT)

_TEST_PLUGIN_SPEC = "workspace_manager.tests.plugins.generic_http:TestHTTPPlugin"
_modules = os.environ.get("WM_PLUGINS_MODULES", "")
if _TEST_PLUGIN_SPEC not in [m.strip() for m in _modules.split(",") if m.strip()]:
    merged = [m.strip() for m in _modules.split(",") if m.strip()]
    merged.append(_TEST_PLUGIN_SPEC)
    os.environ["WM_PLUGINS_MODULES"] = ",".join(merged)
os.environ.setdefault("WM_PLUGINS_ENABLED", "true")


def _docker_available() -> Tuple[bool, str]:
    """
    Check if Docker daemon is reachable.
    Returns (available, reason_if_unavailable).
    """
    try:
        import docker  # type: ignore
    except Exception as e:
        # Be explicit about how to fix import-time failures so CI/devers know the requirement.
        return False, f"Docker SDK not importable: {e} (install the 'docker' Python package, e.g. `pip install docker`)"

    try:
        with contextlib.closing(docker.from_env()) as client:  # type: ignore
            client.ping()
        return True, ""
    except Exception as e:
        # Provide actionable guidance: the daemon may be down or inaccessible (remote host, permissions).
        return False, f"Docker daemon not reachable: {e} (ensure the Docker daemon is running and reachable; if using a remote Docker endpoint set DOCKER_HOST and confirm credentials/permissions)"


def pytest_configure(config: pytest.Config) -> None:
    # Register marker to avoid 'PytestUnknownMarkWarning'
    config.addinivalue_line(
        "markers",
        "docker: mark test as requiring Docker (skipped if Docker is unavailable)",
    )

    available, reason = _docker_available()
    # Stash for collection phase
    setattr(config, "_wm_docker_available", available)
    setattr(config, "_wm_docker_unavailable_reason", reason)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    available: bool = getattr(config, "_wm_docker_available", False)
    reason: str = getattr(
        config,
        "_wm_docker_unavailable_reason",
        "Docker daemon not reachable (ensure Docker is running and reachable; set DOCKER_HOST if using remote Docker)",
    )
    if available:
        return

    skip_marker = pytest.mark.skip(
        reason=reason
        or "Docker daemon not reachable (ensure Docker is running and reachable; set DOCKER_HOST if using remote Docker)"
    )
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip_marker)
