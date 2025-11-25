import os
import socket
import threading
import time
from typing import Dict

import docker
import pytest
import requests
import uvicorn

from wm_client import WorkspaceManagerClient  # type: ignore


def _ensure_test_http_plugin() -> None:
    modules = os.environ.get("WM_PLUGINS_MODULES", "")
    spec = "workspace_manager.tests.plugins.generic_http:TestHTTPPlugin"
    parts = [m.strip() for m in modules.split(",") if m.strip()]
    if spec not in parts:
        parts.append(spec)
        os.environ["WM_PLUGINS_MODULES"] = ",".join(parts)
    os.environ.setdefault("WM_PLUGINS_ENABLED", "true")


def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _addr, port = s.getsockname()
    s.close()
    return port


def _start_workspace_service() -> tuple[str, WorkspaceManagerClient, object, threading.Thread]:
    os.environ.setdefault("CONTAINER_WORKSPACE_DIR", "/tmp/workspace")
    os.environ.setdefault("WORKSPACE_JANITOR_INTERVAL_SECONDS", "999999")
    os.environ.setdefault("WORKSPACE_DEFAULT_CPU", "1")
    os.environ.setdefault("WORKSPACE_DEFAULT_MEM", "2g")
    os.environ.setdefault("WORKSPACE_DEFAULT_IMAGE", os.getenv("TEST_HTTP_IMAGE", "python:3.11-alpine"))
    os.environ.setdefault("WORKSPACE_APPLICATION_KIND", "test-http")
    os.environ.setdefault("WORKSPACE_NETWORK_MODE", "bridge")
    _ensure_test_http_plugin()
    os.environ.setdefault("DOCKER_CLIENT_TIMEOUT", "600")
    os.environ.setdefault("WORKSPACE_API_KEY_HEADER", "X-API-Key")
    os.environ.setdefault("WORKSPACE_API_KEY", "http-tests-key")
    os.environ.setdefault("WM_ALLOW_INSECURE_HTTP", "true")

    from wm_server.app.config import get_settings  # type: ignore

    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    from wm_server.app.main import app as server_app  # type: ignore

    host = "127.0.0.1"
    port = _find_free_port()
    base_url = f"http://{host}:{port}"
    os.environ["WORKSPACE_API_URL"] = base_url

    config = uvicorn.Config(server_app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 90
    healthy = False
    while time.time() < deadline:
        try:
            resp = requests.get(f"{base_url}/health", timeout=2.0)
            if resp.status_code == 200 and (resp.json() or {}).get("status") == "ok":
                healthy = True
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not healthy:
        raise RuntimeError("WorkspaceManager did not become healthy in time")

    client = WorkspaceManagerClient(
        base_url=base_url,
        api_key=os.environ.get("WORKSPACE_API_KEY"),
        api_key_header_name=os.environ.get("WORKSPACE_API_KEY_HEADER", "X-API-Key"),
        allow_insecure_http=True,
    )
    return base_url, client, server, thread


def _stop_server(server: object, th: threading.Thread) -> None:
    try:
        server.should_exit = True  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        th.join(timeout=15)
    except Exception:
        pass


def _resolve_http_host_port(workspace_id: str) -> int:
    dc = docker.from_env()
    containers = dc.containers.list(all=True, filters={"label": f"splk.ws.id={workspace_id}"})
    if not containers:
        raise RuntimeError(f"Container for workspace {workspace_id} not found")
    c = containers[0]
    c.reload()
    ports = (c.attrs.get("NetworkSettings", {}) or {}).get("Ports", {}) or {}
    binding = ports.get("8080/tcp")
    if not binding:
        raise RuntimeError("No HTTP port binding found")
    host_port = binding[0].get("HostPort")
    return int(host_port)


@pytest.mark.integration
@pytest.mark.docker
def test_http_web_access():
    base_url, client, server, thread = _start_workspace_service()
    workspace_id = None
    try:
        resp = client.create_workspace(
            application_kind="test-http",
            env_vars={},
            wait_ready=True,
            require_application_params=False,
        )
        workspace_id = resp.get("workspace_id")
        assert workspace_id, "create_workspace did not return workspace_id"

        host_port = _resolve_http_host_port(workspace_id)
        r = requests.get(f"http://127.0.0.1:{host_port}/index.html", timeout=15)
        assert r.status_code == 200
        assert "workspace-manager" in r.text
    finally:
        if workspace_id:
            try:
                client.delete_workspace(workspace_id)
            except Exception:
                pass
        _stop_server(server, thread)
