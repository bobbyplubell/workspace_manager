import os
import io
import time
import uuid
import socket
import threading
import hashlib
import tempfile
import sys
from typing import Dict, Tuple

import requests
import pytest

import uvicorn
import docker

# Ensure token secrets present before importing server app/settings
os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_SECRET", "test-upload-secret")
os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_HEADER", "Authorization")
os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM", "token")

# Ensure wm_client is importable by adding wm_client/src to sys.path
_here = os.path.abspath(os.path.dirname(__file__))
_repo_root = os.path.abspath(os.path.join(_here, "..", ".."))
_client_src = os.path.join(_repo_root, "wm_client", "src")
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
if _client_src not in sys.path:
    sys.path.insert(0, _client_src)

from wm_client import WorkspaceManagerClient  # type: ignore


def _add_repo_to_syspath() -> None:
    """
    Ensure the repository root is importable during test runs (no cross-project coupling).
    """
    here = os.path.abspath(os.path.dirname(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


def _docker_available_and_prepull() -> Tuple[bool, str]:
    """
    Best-effort check for Docker availability and pre-pull of the default image.
    Returns (available, image_name).
    """
    image_name = os.environ.get("WORKSPACE_DEFAULT_IMAGE") or os.environ.get("TEST_HTTP_IMAGE") or "python:3.11-alpine"
    try:
        dc = docker.from_env()
        dc.ping()
        # Pre-pull to avoid long delays during workspace creation
        try:
            dc.images.pull(image_name)
        except Exception:
            # Allow runtime to pull if needed
            pass
        return True, image_name
    except Exception:
        return False, image_name


def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _addr, port = s.getsockname()
    s.close()
    return port


@pytest.fixture(scope="module")
def workspace_service_env():
    """
    Module-scoped fixture to configure environment for the WorkspaceManager service.
    Restores env after tests.
    """
    _old_env: Dict[str, str | None] = {
        "WORKSPACE_API_KEY": os.environ.get("WORKSPACE_API_KEY"),
        "WORKSPACE_API_KEY_HEADER": os.environ.get("WORKSPACE_API_KEY_HEADER"),
        "WORKSPACE_API_URL": os.environ.get("WORKSPACE_API_URL"),
        "CONTAINER_WORKSPACE_DIR": os.environ.get("CONTAINER_WORKSPACE_DIR"),
        "WORKSPACE_JANITOR_INTERVAL_SECONDS": os.environ.get("WORKSPACE_JANITOR_INTERVAL_SECONDS"),
        "WORKSPACE_DEFAULT_CPU": os.environ.get("WORKSPACE_DEFAULT_CPU"),
        "WORKSPACE_DEFAULT_MEM": os.environ.get("WORKSPACE_DEFAULT_MEM"),
        "DOCKER_CLIENT_TIMEOUT": os.environ.get("DOCKER_CLIENT_TIMEOUT"),
        "WORKSPACE_UPLOAD_TOKEN_SECRET": os.environ.get("WORKSPACE_UPLOAD_TOKEN_SECRET"),
        "WORKSPACE_UPLOAD_TOKEN_HEADER": os.environ.get("WORKSPACE_UPLOAD_TOKEN_HEADER"),
        "WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM": os.environ.get("WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM"),
    }

    os.environ.setdefault("CONTAINER_WORKSPACE_DIR", "/tmp/workspace")
    os.environ.setdefault("WORKSPACE_JANITOR_INTERVAL_SECONDS", "999999")
    os.environ.setdefault("WORKSPACE_DEFAULT_CPU", "1")
    os.environ.setdefault("WORKSPACE_DEFAULT_MEM", "2g")
    os.environ.setdefault("WORKSPACE_DEFAULT_IMAGE", os.getenv("TEST_HTTP_IMAGE", "python:3.11-alpine"))
    os.environ.setdefault("WORKSPACE_APPLICATION_KIND", "test-http")
    modules = os.environ.get("WM_PLUGINS_MODULES", "")
    spec = "workspace_manager.tests.plugins.generic_http:TestHTTPPlugin"
    parts = [m.strip() for m in modules.split(",") if m.strip()]
    if spec not in parts:
        parts.append(spec)
        os.environ["WM_PLUGINS_MODULES"] = ",".join(parts)
    os.environ.setdefault("WM_PLUGINS_ENABLED", "true")
    # Give Docker ample time for large transfers
    os.environ.setdefault("DOCKER_CLIENT_TIMEOUT", "600")
    # Direct upload token settings for tests
    os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_SECRET", "test-upload-secret")
    os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_HEADER", "Authorization")
    os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM", "token")

    try:
        yield
    finally:
        for k, v in _old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture(scope="module")
def workspace_service(workspace_service_env):
    """
    Start the WorkspaceManager FastAPI service (uvicorn) on a free local port.
    Yields WorkspaceManagerClient for making API calls, and ensures shutdown at teardown.
    """
    available, _image = _docker_available_and_prepull()
    if not available:
        pytest.fail("Docker is not available or not reachable for WorkspaceManager integration tests")

    _add_repo_to_syspath()

    try:
        from wm_server.app.config import get_settings as config_get_settings  # type: ignore
        if hasattr(config_get_settings, "cache_clear"):
            config_get_settings.cache_clear()
        from wm_server.app.main import app as server_app  # type: ignore
    except Exception as e:
        pytest.fail(f"Workspace service app not importable: {e}")

    host = "127.0.0.1"
    port = _find_free_port()
    base_url = f"http://{host}:{port}"
    api_key = "api-key-for-tests"
    os.environ["WORKSPACE_API_KEY"] = api_key
    os.environ["WORKSPACE_API_KEY_HEADER"] = "X-API-Key"
    os.environ["WORKSPACE_API_URL"] = base_url

    config = uvicorn.Config(server_app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()

    # Wait for /health
    deadline = time.time() + 45
    healthy = False
    while time.time() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=2.0)
            if r.status_code == 200 and (r.json() or {}).get("status") == "ok":
                healthy = True
                break
        except Exception:
            pass
        time.sleep(0.5)

    assert healthy, "WorkspaceManager did not become healthy in time"

    try:
        client = WorkspaceManagerClient(
            base_url=base_url,
            api_key=api_key,
            api_key_header_name="X-API-Key",
            allow_insecure_http=True,
        )
        yield client
    finally:
        try:
            server.should_exit = True
        except Exception:
            pass
        try:
            th.join(timeout=15)
        except Exception:
            pass


def _create_workspace(client: WorkspaceManagerClient) -> str:
    resp = client.create_workspace(
        application_kind="test-http",
        env_vars={},
        ports={},
        labels={"splk.ws.owner": "ws_copy_streaming_tests"},
        wait_ready=True,
        timeout=600,
        require_application_params=False,
    )
    wsid = (resp or {}).get("workspace_id")
    assert isinstance(wsid, str) and wsid, f"Invalid workspace_id from service: {resp}"
    return wsid


def _delete_workspace(client: WorkspaceManagerClient, wsid: str) -> None:
    try:
        client.delete_workspace(wsid, timeout=30)
    except Exception:
        pass


def _api_headers(client: WorkspaceManagerClient) -> Dict[str, str]:
    h: Dict[str, str] = {}
    if getattr(client, "api_key", None):
        h[getattr(client, "api_key_header_name", "X-API-Key")] = client.api_key  # type: ignore
    return h


@pytest.mark.integration
@pytest.mark.docker
def test_copy_to_and_copy_from_large_file_streaming(workspace_service):
    """
    Ensure copy-to uploads a large file without server-side buffering issues and copy-from
    streams the file back efficiently. Validate integrity via SHA-256 digest.
    """
    client = workspace_service
    wsid = _create_workspace(client)
    try:
        base_url = client.base_url
        headers = _api_headers(client)

        cws = os.environ.get("CONTAINER_WORKSPACE_DIR", "/tmp/workspace").rstrip("/")
        dest_path = f"{cws}/large_stream_{uuid.uuid4().hex}.bin"
        filename = os.path.basename(dest_path)

        # Create a temporary file (~4 MiB) on disk and compute its sha256
        total_size = 4 * 1024 * 1024  # 4 MiB
        block = b"0123456789abcdef" * 2048  # 32 KiB
        sha_send = hashlib.sha256()

        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            temp_path = tf.name
            remaining = total_size
            while remaining > 0:
                chunk = block if remaining >= len(block) else block[:remaining]
                tf.write(chunk)
                sha_send.update(chunk)
                remaining -= len(chunk)

        # Obtain a short-lived upload token for secure direct upload
        cred_resp = requests.post(
            f"{base_url}/workspaces/{wsid}/generate-upload-token",
            params={"destination_path": dest_path},
            headers=headers,
            timeout=30,
        )
        assert cred_resp.status_code == 200, f"generate-upload-token failed: {cred_resp.status_code} {cred_resp.text}"
        creds = cred_resp.json() or {}
        header_name = creds.get("header", "Authorization")
        token_value = creds.get("token")
        assert token_value, f"Token not provided in credentials: {creds}"
        upload_headers = dict(headers)
        upload_headers[header_name] = token_value

        # Upload via copy-to (multipart/form-data) using a file object for streaming
        with open(temp_path, "rb") as f:
            files = {"file": (filename, f, "application/octet-stream")}
            r = requests.post(
                f"{base_url}/workspaces/{wsid}/files/copy-to",
                params={"destination_path": dest_path},
                headers=upload_headers,
                files=files,
                timeout=600,
            )
        os.unlink(temp_path)  # remove local temp file
        assert r.status_code == 200, f"copy-to failed: {r.status_code} {r.text}"

        # Download via copy-from with streaming and compute sha256 on the fly
        # Obtain a short-lived download token for secure direct download
        cred_dl = requests.post(
            f"{base_url}/workspaces/{wsid}/generate-download-token",
            params={"source_path": dest_path},
            headers=headers,
            timeout=30,
        )
        assert cred_dl.status_code == 200, f"generate-download-token failed: {cred_dl.status_code} {cred_dl.text}"
        creds_dl = cred_dl.json() or {}
        dl_headers = dict(headers)
        dl_headers[creds_dl.get("header", "Authorization")] = creds_dl.get("token")

        r = requests.get(
            f"{base_url}/workspaces/{wsid}/files/copy-from",
            params={"source_path": dest_path},
            headers=dl_headers,
            stream=True,
            timeout=600,
        )
        assert r.status_code == 200, f"copy-from failed: {r.status_code} {r.text}"
        cd = r.headers.get("Content-Disposition", "")
        assert filename in cd, f"Expected filename in Content-Disposition, got: {cd}"

        sha_recv = hashlib.sha256()
        recv_bytes = 0
        for chunk in r.iter_content(chunk_size=128 * 1024):
            if not chunk:
                continue
            sha_recv.update(chunk)
            recv_bytes += len(chunk)

        assert recv_bytes == total_size, f"Received size mismatch: {recv_bytes} != {total_size}"
        assert sha_recv.hexdigest() == sha_send.hexdigest(), "SHA-256 mismatch for streamed large file"

    finally:
        _delete_workspace(client, wsid)


@pytest.mark.integration
@pytest.mark.docker
def test_copy_from_single_file_not_found(workspace_service):
    """
    Ensure copy-from returns 404 with a clean error when the file does not exist.
    """
    client = workspace_service
    wsid = _create_workspace(client)
    try:
        base_url = client.base_url
        headers = _api_headers(client)
        missing_path = f"/tmp/workspace/this_file_should_not_exist_{uuid.uuid4().hex}.bin"

        # Obtain a short-lived download token for the missing path
        cred_dl = requests.post(
            f"{base_url}/workspaces/{wsid}/generate-download-token",
            params={"source_path": missing_path},
            headers=headers,
            timeout=30,
        )
        assert cred_dl.status_code == 200, f"generate-download-token failed: {cred_dl.status_code} {cred_dl.text}"
        creds_dl = cred_dl.json() or {}
        dl_headers = dict(headers)
        dl_headers[creds_dl.get("header", "Authorization")] = creds_dl.get("token")

        r = requests.get(
            f"{base_url}/workspaces/{wsid}/files/copy-from",
            params={"source_path": missing_path},
            headers=dl_headers,
            timeout=60,
        )
        assert r.status_code == 404, f"Expected 404 for missing file, got {r.status_code} with body: {r.text}"
        # Optional: ensure error detail is present
        assert r.text, "Expected error body for missing file"

    finally:
        _delete_workspace(client, wsid)
