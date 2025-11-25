from __future__ import annotations

"""
Lifecycle helpers for WorkspaceManager.

This module extracts non-route logic related to:
- Container/application readiness polling
- Background janitor loop for idle workspace cleanup

Defaults and notes:
- Default container workspace directory is "/tmp/workspace" unless overridden via CONTAINER_WORKSPACE_DIR.
- All imports are eager; no lazy imports or guarded imports.
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException

from docker import DockerClient
from docker.models.containers import Container

from wm_server.app.deps import get_settings, ServiceConfig
from wm_server.app.workspaces.core import (
    LABEL_MANAGED,
    LABEL_CREATED_AT,
    LABEL_WORKSPACE_ID,
    epoch_now,
    get_last_used,
    clear_last_used,
)

__all__ = [
    "wait_for_app_ready",
    "janitor_loop",
]


async def wait_for_app_ready(
    c: Container,
    app: Any,
    timeout_s: int = 240,
    logger: Optional[logging.Logger] = None,
) -> None:
    settings = get_settings()
    try:
        await app.wait_for_ready(c, settings, timeout_s, logger)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


async def janitor_loop(settings: ServiceConfig, client: DockerClient) -> None:
    """
    Background janitor loop for idle workspace cleanup.

    - Iterates over managed containers (labeled).
    - Determines idle time using in-memory last-used index with fallback to creation time.
    - Stops and removes containers idle beyond the configured TTL.
    - Also cleans up non-running managed containers older than TTL.

    Respects WORKSPACE_JANITOR_INTERVAL_SECONDS with a minimum interval of 10 seconds.
    """
    interval_s = int(os.getenv("WORKSPACE_JANITOR_INTERVAL_SECONDS", "3600"))
    if interval_s < 10:
        interval_s = 10

    ttl = settings.workspace_idle_ttl_seconds
    label_filter = {LABEL_MANAGED: "true"}

    while True:
        try:
            containers = client.containers.list(
                all=True,
                filters={"label": [f"{k}={v}" for k, v in label_filter.items()]},
            )
            now = epoch_now()
            for c in containers:
                try:
                    labels = c.labels or {}
                    wsid = labels.get(LABEL_WORKSPACE_ID)
                    created_at_iso = labels.get(LABEL_CREATED_AT)

                    created_epoch = now
                    if created_at_iso:
                        try:
                            created_epoch = datetime.fromisoformat(created_at_iso).timestamp()
                        except Exception:
                            created_epoch = now

                    last_used = get_last_used(wsid, fallback=created_epoch) if wsid else created_epoch
                    idle = now - last_used

                    c.reload()
                    if c.status == "running":
                        if ttl > 0 and idle > ttl:
                            # Stop and remove idle container
                            try:
                                c.stop(timeout=20)
                            except Exception as e:
                                # Stopping a container in janitor should be observable; log at error level.
                                logging.getLogger("workspace_manager").error(
                                    "Janitor: failed to stop container ws=%s: %s", wsid or getattr(c, "name", "<unknown>"), e
                                )
                            # Gather attached named volumes before removal
                            mounts = (getattr(c, "attrs", {}) or {}).get("Mounts") or []
                            _attached_vols = []
                            try:
                                for _m in mounts:
                                    if isinstance(_m, dict) and _m.get("Type") == "volume":
                                        _n = _m.get("Name")
                                        if isinstance(_n, str) and _n:
                                            _attached_vols.append(_n)
                            except Exception as e:
                                logging.getLogger("workspace_manager").error(f"Janitor: failed to parse mounts for ws={wsid or c.name}: {e}")
                            try:
                                c.remove(force=True, v=True)
                            except Exception as e:
                                logging.getLogger("workspace_manager").error(f"Janitor: failed to remove container ws={wsid or c.name}: {e}")
                            # Attempt explicit removal of attached named volumes (exclude shared tools volume)
                            _tools_vol = settings.tools_volume_name
                            for _vn in _attached_vols:
                                if _vn == _tools_vol:
                                    continue
                                try:
                                    _vol = client.volumes.get(_vn)
                                    _vol.remove(force=True)
                                except Exception as e:
                                    logging.getLogger("workspace_manager").error(f"Janitor: failed to remove volume '{_vn}' ws={wsid or c.name}: {e}")
                            if wsid:
                                clear_last_used(wsid)
                    elif c.status in ("exited", "created", "dead"):
                        if ttl > 0 and idle > ttl:
                            # Gather attached named volumes before removal
                            mounts = (getattr(c, "attrs", {}) or {}).get("Mounts") or []
                            _attached_vols = []
                            try:
                                for _m in mounts:
                                    if isinstance(_m, dict) and _m.get("Type") == "volume":
                                        _n = _m.get("Name")
                                        if isinstance(_n, str) and _n:
                                            _attached_vols.append(_n)
                            except Exception as e:
                                logging.getLogger("workspace_manager").error(f"Janitor: failed to parse mounts for ws={wsid or c.name}: {e}")
                            try:
                                c.remove(force=True, v=True)
                            except Exception as e:
                                logging.getLogger("workspace_manager").error(f"Janitor: failed to remove container ws={wsid or c.name}: {e}")
                            # Attempt explicit removal of attached named volumes (exclude shared tools volume)
                            _tools_vol = settings.tools_volume_name
                            for _vn in _attached_vols:
                                if _vn == _tools_vol:
                                    continue
                                try:
                                    _vol = client.volumes.get(_vn)
                                    _vol.remove(force=True)
                                except Exception as e:
                                    logging.getLogger("workspace_manager").error(f"Janitor: failed to remove volume '{_vn}' ws={wsid or c.name}: {e}")
                except Exception:
                    # best-effort; continue with next container
                    continue
        except Exception:
            # swallow errors; next tick will retry
            pass

        await asyncio.sleep(interval_s)
