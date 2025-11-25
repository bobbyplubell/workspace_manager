import os
import time
import socket
import threading
from typing import Dict, List, Tuple

import pytest
import requests
import docker
import uvicorn

# Ensure wm_client is importable by adding wm_client/src to sys.path
import sys
_here = os.path.abspath(os.path.dirname(__file__))
_repo_root = os.path.abspath(os.path.join(_here, "..", ".."))
_client_src = os.path.join(_repo_root, "wm_client", "src")
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
if _client_src not in sys.path:
    sys.path.insert(0, _client_src)

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


def _docker_available_and_prepull() -> Tuple[bool, str]:
    """
    Best-effort check for Docker availability and pre-pull of the default image.
    Returns (available, image_name).
    """
    image_name = os.environ.get("WORKSPACE_DEFAULT_IMAGE") or os.environ.get("TEST_HTTP_IMAGE") or "python:3.11-alpine"
    try:
        dc = docker.from_env()
        dc.ping()
        try:
            dc.images.pull(image_name)
        except Exception:
            pass
        return True, image_name
    except Exception:
        return False, image_name


@pytest.fixture(scope="module")
def multi_user_env():
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
    }

    os.environ.setdefault("CONTAINER_WORKSPACE_DIR", "/tmp/workspace")
    os.environ.setdefault("WORKSPACE_JANITOR_INTERVAL_SECONDS", "999999")
    os.environ.setdefault("WORKSPACE_DEFAULT_CPU", "1")
    os.environ.setdefault("WORKSPACE_DEFAULT_MEM", "2g")
    os.environ.setdefault("WORKSPACE_DEFAULT_IMAGE", os.getenv("TEST_HTTP_IMAGE", "python:3.11-alpine"))
    os.environ.setdefault("WORKSPACE_APPLICATION_KIND", "test-http")
    os.environ.setdefault("DOCKER_CLIENT_TIMEOUT", "1200")
    os.environ.setdefault("WORKSPACE_NETWORK_MODE", "bridge")
    _ensure_test_http_plugin()

    try:
        yield
    finally:
        for k, v in _old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture(scope="module")
def workspace_service(multi_user_env):
    """
    Start the WorkspaceManager FastAPI service (uvicorn) on a free local port.
    Yields base_url for making API calls, and ensures shutdown at teardown.
    """
    available, _image = _docker_available_and_prepull()
    assert available, "Docker is not available or not reachable for WorkspaceManager integration tests"

    try:
        from wm_server.app.config import get_settings  # type: ignore
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()
        from wm_server.app.main import app as server_app  # type: ignore
    except Exception as e:
        pytest.fail(f"Workspace service app not importable: {e}")

    host = "127.0.0.1"
    port = _find_free_port()
    base_url = f"http://{host}:{port}"

    # Single API key for this server instance (scoping by API key suffix cannot be tested until server accepts multiple keys)
    api_key_a = "api-key-for-tests"
    api_key_b = "api-key-for-tests-2"
    api_header = "X-API-Key"
    os.environ["WORKSPACE_API_KEY"] = api_key_a
    os.environ["WORKSPACE_API_KEYS"] = f"{api_key_a},{api_key_b}"
    os.environ["WORKSPACE_API_KEY_HEADER"] = api_header
    os.environ["WORKSPACE_API_URL"] = base_url

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

    assert healthy, "WorkspaceManager did not become healthy in time"

    try:
        yield base_url
    finally:
        try:
            server.should_exit = True
        except Exception:
            pass
        try:
            th.join(timeout=15)
        except Exception:
            pass


def _new_client(base_url: str, api_key: str, api_key_header_name: str = "X-API-Key") -> WorkspaceManagerClient:
    return WorkspaceManagerClient(
        base_url=base_url,
        api_key=api_key,
        api_key_header_name=api_key_header_name,
        allow_insecure_http=True,
    )


def _create_workspace_for_owner(client: WorkspaceManagerClient, owner: str, wait_ready: bool = False) -> str:
    resp = client.create_workspace(
        application_kind="test-http",
        env_vars={},
        ports={},
        labels={"splk.ws.owner": owner},
        wait_ready=wait_ready,
        timeout=180,
        require_application_params=False,
    )
    wsid = (resp or {}).get("workspace_id")
    assert isinstance(wsid, str) and wsid, f"Invalid workspace_id from service: {resp}"
    return wsid


def _list_ids(resp_json: Dict) -> List[str]:
    items = (resp_json or {}).get("workspaces") or []
    ids: List[str] = []
    for w in items:
        wsid = (w or {}).get("workspace_id")
        if isinstance(wsid, str):
            ids.append(wsid)
    return ids


@pytest.mark.integration
@pytest.mark.docker
def test_multi_user_list_and_cleanup_by_label(workspace_service):
    """
    Verify:
    - Multiple workspaces created for different owners
    - Listing with owner filter returns only corresponding workspaces
    - Cleanup by label (owner) deletes only targeted workspaces
    """
    base_url = workspace_service

    # Use the same server API key (server currently accepts a single key)
    api_key = "api-key-for-tests"
    client = _new_client(base_url, api_key)

    # Create workspaces for two "users" (owner labels)
    owners = ("alice", "bob")

    ws_alice: List[str] = []
    ws_bob: List[str] = []
    try:
        # Create two per owner
        for _ in range(2):
            ws_alice.append(_create_workspace_for_owner(client, "alice", wait_ready=False))
            ws_bob.append(_create_workspace_for_owner(client, "bob", wait_ready=False))

        # List all workspaces
        all_resp = client.list_workspaces(owner=None, timeout=60)
        all_ids = _list_ids(all_resp)
        # Should include all we created
        for wsid in ws_alice + ws_bob:
            assert wsid in all_ids, f"Workspace {wsid} missing from overall list"

        # List filtered by owner label
        alice_resp = client.list_workspaces(owner="alice", timeout=60)
        alice_ids = set(_list_ids(alice_resp))
        bob_resp = client.list_workspaces(owner="bob", timeout=60)
        bob_ids = set(_list_ids(bob_resp))

        assert alice_ids.issuperset(ws_alice) and len(alice_ids) >= len(ws_alice), "Owner=alice list should contain only Alice workspaces"
        assert bob_ids.issuperset(ws_bob) and len(bob_ids) >= len(ws_bob), "Owner=bob list should contain only Bob workspaces"
        assert alice_ids.isdisjoint(bob_ids), "Owner label filter should segregate results"

        # Cleanup by label: delete all of Alice's workspaces
        for wsid in list(alice_ids):
            client.delete_workspace(wsid, timeout=30)

        # Verify Alice gone, Bob remains
        all_after_alice = set(_list_ids(client.list_workspaces(owner=None, timeout=60)))
        assert all(wsid not in all_after_alice for wsid in ws_alice), "Alice workspaces should be deleted"
        assert all(wsid in all_after_alice for wsid in ws_bob), "Bob workspaces should remain"

        # Verify get_workspace for a deleted id returns 404
        if ws_alice:
            deleted_id = ws_alice[0]
            r = requests.get(f"{base_url}/workspaces/{deleted_id}", headers={client.api_key_header_name: client.api_key}, timeout=15)
            assert r.status_code == 404, f"Expected 404 for deleted workspace {deleted_id}, got {r.status_code}: {r.text}"

        # Cleanup by label: delete all of Bob's workspaces
        for wsid in list(bob_ids):
            client.delete_workspace(wsid, timeout=30)

        # Ensure no managed workspaces left for both labels
        assert _list_ids(client.list_workspaces(owner="alice", timeout=60)) == []
        assert _list_ids(client.list_workspaces(owner="bob", timeout=60)) == []

    finally:
        # Best-effort cleanup in case of failures above
        for wsid in ws_alice + ws_bob:
            try:
                client.delete_workspace(wsid, timeout=15)
            except Exception:
                pass


@pytest.mark.integration
@pytest.mark.docker
def test_multi_api_key_isolation(workspace_service):
    """
    Verify per-API-key isolation:
    - Two different API keys can each create workspaces
    - Listing is scoped to caller's API key (doesn't reveal others)
    - Access with wrong API key returns 404
    - Deleting with wrong API key is a no-op (does not remove the target)
    """
    base_url = workspace_service
    api_header = "X-API-Key"
    key_a = "api-key-for-tests"
    key_b = "api-key-for-tests-2"

    client_a = _new_client(base_url, key_a, api_header)
    client_b = _new_client(base_url, key_b, api_header)

    # Create workspaces with same owner label under different API keys
    ws_a = _create_workspace_for_owner(client_a, "carol", wait_ready=False)
    ws_b = _create_workspace_for_owner(client_b, "carol", wait_ready=False)

    try:
        # Client A sees only its own workspaces
        ids_a_all = set(_list_ids(client_a.list_workspaces(owner=None, timeout=60)))
        ids_a_carol = set(_list_ids(client_a.list_workspaces(owner="carol", timeout=60)))
        assert ws_a in ids_a_all and ws_a in ids_a_carol, "Client A should see its own workspace"
        assert ws_b not in ids_a_all and ws_b not in ids_a_carol, "Client A should not see Client B's workspace"

        # Client B sees only its own workspaces
        ids_b_all = set(_list_ids(client_b.list_workspaces(owner=None, timeout=60)))
        ids_b_carol = set(_list_ids(client_b.list_workspaces(owner="carol", timeout=60)))
        assert ws_b in ids_b_all and ws_b in ids_b_carol, "Client B should see its own workspace"
        assert ws_a not in ids_b_all and ws_a not in ids_b_carol, "Client B should not see Client A's workspace"

        # Access enforcement: Client A cannot GET Client B's workspace
        r = requests.get(f"{base_url}/workspaces/{ws_b}", headers={api_header: key_a}, timeout=15)
        assert r.status_code == 404, f"Expected 404 when Client A requests Client B workspace, got {r.status_code}: {r.text}"

        # Access enforcement: Client B cannot GET Client A's workspace
        r = requests.get(f"{base_url}/workspaces/{ws_a}", headers={api_header: key_b}, timeout=15)
        assert r.status_code == 404, f"Expected 404 when Client B requests Client A workspace, got {r.status_code}: {r.text}"

        # Wrong-key delete is a no-op: Client B attempts to delete Client A's workspace
        _ = client_b.delete_workspace(ws_a, timeout=30)

        # Client A should still see its workspace after Client B attempted deletion
        ids_a_all_after = set(_list_ids(client_a.list_workspaces(owner=None, timeout=60)))
        assert ws_a in ids_a_all_after, "Client A workspace should remain after Client B's delete attempt"

    finally:
        # Cleanup with correct keys
        try:
            client_a.delete_workspace(ws_a, timeout=30)
        except Exception:
            pass
        try:
            client_b.delete_workspace(ws_b, timeout=30)
        except Exception:
            pass
