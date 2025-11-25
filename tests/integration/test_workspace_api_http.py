import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import docker
import pytest
import requests
import uvicorn


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


def _start_service() -> tuple[str, Dict[str, str], object, threading.Thread]:
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
    os.environ.setdefault("WORKSPACE_API_KEY", "workspace-api-tests")
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

    headers = {os.environ.get("WORKSPACE_API_KEY_HEADER", "X-API-Key"): os.environ.get("WORKSPACE_API_KEY", "")}
    return base_url, headers, server, thread


def _stop_service(server: object, thread: threading.Thread) -> None:
    try:
        server.should_exit = True  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        thread.join(timeout=15)
    except Exception:
        pass


def _create_workspace(base_url: str, headers: Dict[str, str], wait_ready: bool = True) -> str:
    payload = {
        "application_kind": "test-http",
        "env_vars": {},
        "ports": {},
        "labels": {"suite": "workspace-api"},
    }
    params = {"wait_ready": "true" if wait_ready else "false"}
    resp = requests.post(f"{base_url}/workspaces", json=payload, params=params, headers=headers, timeout=180)
    resp.raise_for_status()
    data = resp.json() or {}
    wsid = data.get("workspace_id")
    if not wsid:
        raise AssertionError(f"create_workspace missing workspace_id: {data}")
    return wsid


def _delete_workspace(base_url: str, headers: Dict[str, str], workspace_id: str) -> None:
    resp = requests.delete(f"{base_url}/workspaces/{workspace_id}", headers=headers, timeout=60)
    resp.raise_for_status()


def _exec_command(base_url: str, headers: Dict[str, str], workspace_id: str, command: str) -> Dict[str, str]:
    payload = {"command": command, "user": "root", "timeout": 90}
    resp = requests.post(f"{base_url}/workspaces/{workspace_id}/exec", json=payload, headers=headers, timeout=180)
    resp.raise_for_status()
    return resp.json() or {}


def _write_file(base_url: str, headers: Dict[str, str], workspace_id: str, path: str, content: str) -> None:
    payload = {"path": path, "content": content}
    resp = requests.post(f"{base_url}/workspaces/{workspace_id}/files/write", json=payload, headers=headers, timeout=60)
    resp.raise_for_status()


def _read_file(base_url: str, headers: Dict[str, str], workspace_id: str, path: str) -> str:
    resp = requests.get(f"{base_url}/workspaces/{workspace_id}/files/read", params={"path": path}, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json() or {}
    return data.get("content", "")


def _resolve_http_port(workspace_id: str) -> int:
    client = docker.from_env()
    containers = client.containers.list(all=True, filters={"label": f"splk.ws.id={workspace_id}"})
    if not containers:
        raise RuntimeError(f"container not found for {workspace_id}")
    container = containers[0]
    container.reload()
    ports = (container.attrs.get("NetworkSettings", {}) or {}).get("Ports", {}) or {}
    binding = ports.get("8080/tcp")
    if not binding:
        raise RuntimeError("HTTP port binding missing")
    return int(binding[0].get("HostPort"))


@pytest.mark.integration
@pytest.mark.docker
def test_workspace_api_exec_and_files():
    base_url, headers, server, thread = _start_service()
    workspace_id = None
    try:
        workspace_id = _create_workspace(base_url, headers, wait_ready=True)

        result = _exec_command(base_url, headers, workspace_id, "/bin/sh -c 'echo $((2 + 3))'")
        assert int(result.get("exit_code", 1)) == 0
        assert "5" in result.get("stdout", "")

        test_file = "/tmp/workspace/test_api_http.txt"
        payload = "integration-ok"
        _write_file(base_url, headers, workspace_id, test_file, payload)
        content = _read_file(base_url, headers, workspace_id, test_file)
        assert payload in content

        host_port = _resolve_http_port(workspace_id)
        resp = requests.get(f"http://127.0.0.1:{host_port}/index.html", timeout=15)
        assert resp.status_code == 200
        assert "workspace-manager" in resp.text

        logs = requests.get(f"{base_url}/workspaces/{workspace_id}/logs", headers=headers, timeout=60)
        logs.raise_for_status()
        assert logs.json().get("logs") is not None
    finally:
        if workspace_id:
            try:
                _delete_workspace(base_url, headers, workspace_id)
            except Exception:
                pass
        _stop_service(server, thread)


@pytest.mark.integration
@pytest.mark.docker
def test_workspace_api_concurrent_creation():
    base_url, headers, server, thread = _start_service()
    created: List[str] = []
    try:
        def _create_and_destroy(idx: int) -> bool:
            wsid = _create_workspace(base_url, headers, wait_ready=False)
            created.append(wsid)
            _delete_workspace(base_url, headers, wsid)
            return True

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_create_and_destroy, i) for i in range(6)]
            for fut in as_completed(futures):
                assert fut.result()

            # Ensure all workspaces created in this test are gone
            deadline = time.time() + 60
            remaining: List[str] = []
            while time.time() < deadline:
                resp = requests.get(f"{base_url}/workspaces", headers=headers, timeout=60)
                resp.raise_for_status()
                items = (resp.json() or {}).get("workspaces") or []
                ids = [item.get("workspace_id") for item in items if item.get("workspace_id")]
                remaining = [ws for ws in ids if ws in created]
                if not remaining:
                    break
                time.sleep(1)
            assert not remaining, f"workspaces still present: {remaining}"
    finally:
        for wsid in created:
            try:
                _delete_workspace(base_url, headers, wsid)
            except Exception:
                pass
        _stop_service(server, thread)
