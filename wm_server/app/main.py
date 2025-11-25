from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Awaitable, Callable, List, Optional
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import docker
from dotenv import load_dotenv

# Routers (make sure these modules exist; no lazy imports as per project policy)
# The `workspaces` router should implement the WorkspaceManager API surface.

# Load environment from optional .env file before instantiating settings
_SERVER_ENV_FILE = os.getenv("WM_SERVER_ENV_FILE", ".env.server")
if _SERVER_ENV_FILE and Path(_SERVER_ENV_FILE).is_file():
    load_dotenv(_SERVER_ENV_FILE)

from wm_server.app.config import get_settings

settings = get_settings()
from wm_server.app.logging_setup import initialize_from_env
from wm_server.app.routers import plugins, workspaces
from wm_server.app.workspaces.lifecycle import wait_for_app_ready, janitor_loop

logger = logging.getLogger("workspace_manager")
_LOG_PATH = initialize_from_env(service_name="workspace_manager")
logger.info(f"WorkspaceManager logging to file: {_LOG_PATH}")

app = FastAPI(
    title="WorkspaceManager",
    version=settings.service_version,
    description="Multi-tenant, stateless manager for containerized Splunk workspaces.",
)

# CORS: permissive by default; lock down in deployment via env vars if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# App state used by background maintenance loop
app.state.janitor_task = None
app.state.janitor_callbacks = []

def ensure_docker_available_on_startup() -> None:
    """
    Verify Docker Engine is reachable before the API starts serving requests.
    This service depends on Docker; we intentionally fail fast if it's unavailable.
    Exits the process with a non-zero status if Docker is unavailable.
    """
    timeout_s = settings.docker_client_timeout
    try:
        client = docker.from_env(timeout=timeout_s)
        # Ensure the daemon/socket is reachable
        client.ping()
        client.close()
    except Exception as e:
        logger.critical(
            "Docker is not available. WorkspaceManager cannot start without Docker. "
            "Ensure Docker Engine is running and accessible (for example Docker Desktop or dockerd). "
            f"Details: {e}"
        )
        raise SystemExit(1)


async def _janitor_loop() -> None:
    """
    Background maintenance loop.

    Executes registered janitor callbacks on a configurable interval.
    Intended for:
      - Auto-cleanup of idle workspaces
      - Pruning zombie containers/volumes
      - Metrics/health reconciliation

    Other modules can register callbacks by appending async callables to:
      app.state.janitor_callbacks
    """
    interval_s = settings.janitor_interval_seconds
    if interval_s < 10:
        interval_s = 10

    logger.info(f"Janitor loop started (interval={interval_s}s)")
    try:
        while True:
            started_at = datetime.now(timezone.utc).isoformat()
            try:
                if not hasattr(app.state, "janitor_callbacks") or not app.state.janitor_callbacks:
                    logger.debug("Janitor tick: no callbacks registered")
                else:
                    for cb in list(app.state.janitor_callbacks):
                        try:
                            await cb()
                        except Exception as cb_err:
                            logger.warning(f"Janitor callback error: {cb_err}")
                logger.debug(f"Janitor tick completed at {started_at}")
            except Exception as e:
                logger.warning(f"Janitor loop iteration error: {e}")
            await asyncio.sleep(interval_s)
    except asyncio.CancelledError:
        logger.info("Janitor loop cancelled; shutting down.")
        raise


from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast if Docker is unavailable
    ensure_docker_available_on_startup()

    # Register routers
    app.include_router(workspaces.router, prefix="/workspaces", tags=["workspaces"])
    app.include_router(plugins.router)

    # Start background janitor
    if getattr(app.state, "janitor_task", None) is None:
        app.state.janitor_task = asyncio.create_task(_janitor_loop())
        logger.info("WorkspaceManager startup complete.")

    try:
        yield
    finally:
        # Stop background janitor
        task: Optional[asyncio.Task] = getattr(app.state, "janitor_task", None)
        if task is not None:
            try:
                # Cancel without awaiting to avoid cross-event-loop issues under TestClient teardown
                task.cancel()
                # If the task already finished on this loop, drain exception to silence warnings
                if task.done():
                    _ = task.exception() if not task.cancelled() else None
            except Exception:
                # Best-effort: ignore cancellation/cleanup errors
                pass
            finally:
                app.state.janitor_task = None
        logger.info("WorkspaceManager shutdown complete.")

# Register lifespan handler for FastAPI to remove deprecated on_event usage
app.router.lifespan_context = lifespan


@app.get("/health")
async def health() -> dict:
    """
    Basic health probe; intentionally unauthenticated.
    """
    return {
        "status": "ok",
        "service": "WorkspaceManager",
        "version": app.version,
    }
