import io
import os
import time
import hashlib
from typing import Dict, Tuple

import pytest
import requests
import uvicorn
import socket
import threading


def _base_url() -> str:
    return os.getenv("WM_BASE_URL", "http://127.0.0.1:8081")


def _api_headers() -> Dict[str, str]:
    key_header = os.getenv("WORKSPACE_API_KEY_HEADER", "X-API-Key")
    key_value = os.getenv("WORKSPACE_API_KEY")
    return {key_header: key_value} if key_value else {}


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _stream_sha256(resp: requests.Response) -> Tuple[int, str]:
    h = hashlib.sha256()
    total = 0
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        h.update(chunk)
        total += len(chunk)
    return total, h.hexdigest()


# Local server bootstrap for tests to avoid skips
def _find_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _addr, port = s.getsockname()
    s.close()
    return port

def _start_local_server() -> tuple[str, Dict[str, str], object, object]:
    # Ensure required env defaults
    os.environ.setdefault("CONTAINER_WORKSPACE_DIR", "/tmp/workspace")
    os.environ.setdefault("WORKSPACE_JANITOR_INTERVAL_SECONDS", "999999")
    os.environ.setdefault("WORKSPACE_DEFAULT_CPU", "1")
    os.environ.setdefault("WORKSPACE_DEFAULT_MEM", "2g")
    os.environ.setdefault("WORKSPACE_DEFAULT_IMAGE", os.getenv("TEST_HTTP_IMAGE", "python:3.11-alpine"))
    os.environ.setdefault("WORKSPACE_APPLICATION_KIND", "test-http")
    os.environ.setdefault("DOCKER_CLIENT_TIMEOUT", "1200")
    modules = os.environ.get("WM_PLUGINS_MODULES", "")
    spec = "workspace_manager.tests.plugins.generic_http:TestHTTPPlugin"
    parts = [m.strip() for m in modules.split(",") if m.strip()]
    if spec not in parts:
        parts.append(spec)
        os.environ["WM_PLUGINS_MODULES"] = ",".join(parts)
    os.environ.setdefault("WM_PLUGINS_ENABLED", "true")
    # Direct upload/download token settings for tests
    os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_SECRET", "test-upload-secret")
    os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_HEADER", "Authorization")
    os.environ.setdefault("WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM", "token")

    # Local API key for the spawned server
    os.environ.setdefault("WORKSPACE_API_KEY", "api-key-for-tests")
    os.environ.setdefault("WORKSPACE_API_KEY_HEADER", "X-API-Key")

    from wm_server.app.config import get_settings as config_get_settings  # type: ignore
    if hasattr(config_get_settings, "cache_clear"):
        config_get_settings.cache_clear()
    from wm_server.app.main import app as server_app  # import within tests

    host = "127.0.0.1"
    port = _find_free_port()
    base_url = f"http://{host}:{port}"

    config = uvicorn.Config(server_app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()

    # Wait for /health
    deadline = time.time() + 90
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
    if not healthy:
        raise RuntimeError("WorkspaceManager did not become healthy in time")

    headers = {os.environ.get("WORKSPACE_API_KEY_HEADER", "X-API-Key"): os.environ.get("WORKSPACE_API_KEY", "")}
    return base_url, headers, server, th

def _stop_server(server: object, th: object) -> None:
    try:
        server.should_exit = True  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        th.join(timeout=15)
    except Exception:
        pass


@pytest.mark.integration
@pytest.mark.docker
def test_secure_upload_handoff_flow():
    """
    Integration test for secure, direct upload handoff flow:
    1) Create a workspace (API-key auth).
    2) Request short-lived upload token and URL for a destination path.
    3) Upload a file directly using the returned token in the configured header.
    4) Verify upload success and integrity by downloading the file via copy-from.
    5) Cleanup the workspace.
    """
    base_url = _base_url().rstrip("/")
    headers = _api_headers()

    # Ensure server is available; if not, start a local one
    server = None
    th = None
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        r.raise_for_status()
    except Exception:
        base_url, headers, server, th = _start_local_server()

    # Create a new workspace (no need to wait for app readiness for file operations)
    wsid = None
    try:
        payload = {
            "application_kind": "test-http",
            "env_vars": {},
            "ports": {},
            "labels": {"owner": "tests"},
        }
        r = requests.post(
            f"{base_url}/workspaces",
            params={"wait_ready": "true"},
            json=payload,
            headers=headers,
            timeout=600,
        )
        # If a 401 occurs here against a local server, it's a test failure; external servers are not used.
        r.raise_for_status()
        data = r.json() or {}
        wsid = data.get("workspace_id")
        assert wsid, f"create_workspace did not return a workspace_id: {data}"

        # Request a short-lived upload token for the destination path
        destination_path = f"/tmp/workspace/uploads/handoff_test_{int(time.time())}.txt"
        r = requests.post(
            f"{base_url}/workspaces/{wsid}/generate-upload-token",
            params={"destination_path": destination_path},
            headers=headers,
            timeout=30,
        )
        # Endpoint must be implemented; a 404 here indicates a server misconfiguration.
        r.raise_for_status()
        creds = r.json() or {}

        upload_url = creds.get("upload_url")
        header_name = creds.get("header", "Authorization")
        query_param = creds.get("query_param", "token")
        token_value = creds.get("token")
        assert upload_url and token_value, f"Invalid credentials response: {creds}"

        # Prepare content to upload
        content = b"Hello secure handoff!\n" + os.urandom(32 * 1024)
        digest_expected = _sha256_bytes(content)

        # Perform the direct upload using the provided token header
        files = {"file": ("handoff.txt", io.BytesIO(content), "application/octet-stream")}
        up_headers = dict(headers)
        up_headers[header_name] = token_value

        r = requests.post(
            upload_url,
            params={"destination_path": destination_path},
            headers=up_headers,
            files=files,
            timeout=1200,
        )
        r.raise_for_status()

        # Verify existence via /files/exists
        r = requests.get(
            f"{base_url}/workspaces/{wsid}/files/exists",
            params={"path": destination_path},
            headers=headers,
            timeout=30,
        )
        r.raise_for_status()
        exists = (r.json() or {}).get("exists")
        assert exists is True, f"Uploaded file not found at {destination_path}"

        # Download the file via copy-from using a short-lived download token and validate integrity
        r = requests.post(
            f"{base_url}/workspaces/{wsid}/generate-download-token",
            params={"source_path": destination_path},
            headers=headers,
            timeout=30,
        )
        r.raise_for_status()
        dl_creds = r.json() or {}
        download_url = dl_creds.get("download_url")
        header_name = dl_creds.get("header", "Authorization")
        token_value = dl_creds.get("token")
        assert download_url and token_value, f"Invalid download credentials: {dl_creds}"
        dl_headers = dict(headers)
        dl_headers[header_name] = token_value

        r = requests.get(
            download_url,
            params={"source_path": destination_path},
            headers=dl_headers,
            stream=True,
            timeout=120,
        )
        r.raise_for_status()
        size, digest_actual = _stream_sha256(r)
        assert size == len(content), f"Size mismatch: expected={len(content)} actual={size}"
        assert digest_actual == digest_expected, f"SHA-256 mismatch: expected={digest_expected} actual={digest_actual}"

    finally:
        # Cleanup the workspace
        if wsid:
            try:
                _ = requests.delete(f"{base_url}/workspaces/{wsid}", headers=headers, timeout=30)
            except Exception:
                # best-effort cleanup
                pass
        # Stop local server if we started one
        if 'server' in locals() and server is not None:
            _stop_server(server, th)

@pytest.mark.integration
@pytest.mark.docker
def test_secure_download_handoff_flow():
    """
    Integration test for secure, direct download handoff flow:
    1) Create a workspace (API-key auth).
    2) Create a file inside the workspace via files/write.
    3) Request short-lived download token and URL for the source path.
    4) Download the file directly using the returned token in the configured header.
    5) Verify download integrity.
    6) Cleanup the workspace.
    """
    base_url = _base_url().rstrip("/")
    headers = _api_headers()

    # Ensure server is available; if not, start a local one
    server = None
    th = None
    try:
        r = requests.get(f"{base_url}/health", timeout=5)
        r.raise_for_status()
    except Exception:
        base_url, headers, server, th = _start_local_server()

    wsid = None
    try:
        # Create a new workspace (wait for readiness to avoid container startup races)
        payload = {
            "application_kind": "test-http",
            "env_vars": {},
            "ports": {},
            "labels": {"owner": "tests"},
        }
        r = requests.post(
            f"{base_url}/workspaces",
            params={"wait_ready": "true"},
            json=payload,
            headers=headers,
            timeout=600,
        )
        # If a 401 occurs here against a local server, it's a test failure; external servers are not used.
        r.raise_for_status()
        data = r.json() or {}
        wsid = data.get("workspace_id")
        assert wsid, f"create_workspace did not return a workspace_id: {data}"

        # Create content and write it to a file inside the workspace
        cws = os.environ.get("CONTAINER_WORKSPACE_DIR", "/tmp/workspace").rstrip("/")
        source_path = f"{cws}/downloads/handoff_download_{int(time.time())}.txt"
        content_str = ("Hello secure download handoff!\n" * 2048)  # ~50KB ASCII content
        digest_expected = hashlib.sha256(content_str.encode("utf-8")).hexdigest()

        r = requests.post(
            f"{base_url}/workspaces/{wsid}/files/write",
            json={"path": source_path, "content": content_str},
            headers=headers,
            timeout=60,
        )
        r.raise_for_status()

        # Obtain a short-lived download token
        r = requests.post(
            f"{base_url}/workspaces/{wsid}/generate-download-token",
            params={"source_path": source_path},
            headers=headers,
            timeout=30,
        )
        # Endpoint must be implemented; a 404 here indicates a server misconfiguration.
        r.raise_for_status()
        creds = r.json() or {}
        download_url = creds.get("download_url")
        header_name = creds.get("header", "Authorization")
        query_param = creds.get("query_param", "token")
        token_value = creds.get("token")
        assert download_url and token_value, f"Invalid credentials response: {creds}"

        # Perform the direct download using the provided token header
        dl_headers = dict(headers)
        dl_headers[header_name] = token_value

        r = requests.get(
            download_url,
            params={"source_path": source_path},
            headers=dl_headers,
            stream=True,
            timeout=120,
        )
        # If a 401 occurs here against a local server, it's a test failure; external servers are not used.
        r.raise_for_status()
        size, digest_actual = _stream_sha256(r)

        assert size == len(content_str.encode("utf-8")), f"Size mismatch: expected={len(content_str.encode('utf-8'))} actual={size}"
        assert digest_actual == digest_expected, f"SHA-256 mismatch: expected={digest_expected} actual={digest_actual}"

    finally:
        # Cleanup the workspace
        if wsid:
            try:
                _ = requests.delete(f"{base_url}/workspaces/{wsid}", headers=headers, timeout=30)
            except Exception:
                # best-effort cleanup
                pass
