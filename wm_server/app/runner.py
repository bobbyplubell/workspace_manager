from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Tuple

import uvicorn

logger = logging.getLogger(__name__)


def start_uvicorn_in_thread(
    app,
    *,
    host: str,
    port: int,
    log_level: str = "info",
    startup_timeout: float = 15.0,
    thread_factory: Callable[..., threading.Thread] | None = None,
) -> Tuple[uvicorn.Server, threading.Thread]:
    """
    Start a uvicorn.Server for the given FastAPI app inside a background thread.

    The function blocks until the server reports that it has started or until
    the startup timeout elapses. If the server thread exits before startup
    completes (for example, due to a bind/permission error) a RuntimeError is
    raised so callers can fail fast instead of waiting for downstream health
    probes to time out.
    """

    config = uvicorn.Config(app, host=host, port=port, log_level=log_level)
    server = uvicorn.Server(config)

    factory = thread_factory or (lambda **kwargs: threading.Thread(**kwargs))
    thread = factory(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + max(0.5, float(startup_timeout))
    poll_interval = 0.05

    while time.time() < deadline:
        if getattr(server, "started", False) and thread.is_alive():
            logger.info("uvicorn server started on %s:%s", host, port)
            return server, thread
        if not thread.is_alive():
            break
        time.sleep(poll_interval)

    if getattr(server, "started", False) and thread.is_alive():
        logger.info("uvicorn server started on %s:%s", host, port)
        return server, thread

    raise RuntimeError(
        f"uvicorn server failed to start on {host}:{port} within {startup_timeout} seconds. "
        "Check logs for bind/permission issues."
    )
