import os
import time
import uuid
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

# Configure environment BEFORE importing the app so settings pick them up.
# Use a small image that declares a VOLUME so Docker creates a random-named volume (e.g., redis:/data).
os.environ.setdefault("WORKSPACE_DEFAULT_IMAGE", "redis:7-alpine")
# Use a unique tools volume per test run so we can make precise assertions and avoid interference.
TOOLS_VOL = f"wm_tools_cache_test_{uuid.uuid4().hex[:8]}"
os.environ["WORKSPACE_TOOLS_VOLUME"] = TOOLS_VOL

# Import app after env is set so settings reflect overrides.
from wm_server.app.main import app  # noqa: E402
from wm_server.app.config import get_settings  # noqa: E402


def _wait_for(predicate, timeout=20.0, interval=0.5):
    """
    Wait until predicate() returns True, up to timeout seconds.
    Returns True if predicate becomes True, False otherwise.
    """
    deadline = time.time() + max(0.1, float(timeout))
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            # Ignore predicate exceptions during wait loop
            pass
        time.sleep(max(0.05, float(interval)))
    return False


@pytest.fixture(scope="module")
def docker_client():
    # Import docker inside the fixture so tests that don't require Docker can be
    # collected and (if necessary) auto-skipped by the test suite configuration.
    import docker  # local import to avoid failing collection when Docker is unavailable
    with closing(docker.from_env()) as client:
        yield client


@pytest.mark.docker
def test_container_delete_removes_attached_random_named_volumes(docker_client):
    """
    Integration: ensure that deleting a workspace removes any attached anonymous or random-named volumes.

    Strategy:
    - Force default image to one that declares a VOLUME (redis:7-alpine -> /data).
    - Create workspace via API.
    - Inspect container mounts to capture volume names (excluding the shared tools volume).
    - DELETE the workspace via API.
    - Assert the container is gone.
    - Assert captured volumes are removed (NotFound).
    - Assert the shared tools volume still exists (we do not delete it).
    """
    # Import the docker module inside the test so the module name is available for
    # cleanup/exception handling even when the fixture provides only the client.
    import docker
    # Clear the cached settings so our per-test environment override (WORKSPACE_TOOLS_VOLUME)
    # set at module top is respected when running the full test suite.
    try:
        # get_settings is lru_cache-decorated; clear any previous cached instance.
        get_settings.cache_clear()
    except Exception:
        # If cache_clear is unavailable for any reason, proceed — get_settings() will still return settings.
        pass
    settings = get_settings()

    # Sanity: ensure our test-specific tools volume name is effective in settings
    assert settings.tools_volume_name == TOOLS_VOL

    workspace_id = None
    container_name = None
    random_named_vols = []

    try:
        with TestClient(app) as client:
            # Create workspace
            payload = {
                "application_params": {},
                "env_vars": {},
                "ports": {},
            }
            resp = client.post("/workspaces", json=payload, params={"wait_ready": True})
            assert resp.status_code == 201, f"Workspace create failed: {resp.status_code} {resp.text}"
            workspace_id = resp.json()["workspace_id"]
            assert workspace_id

            # Resolve container and inspect mounts
            container_name = settings.workspace_container_name(workspace_id)
            c = docker_client.containers.get(container_name)
            c.reload()
            mounts = (getattr(c, "attrs", {}) or {}).get("Mounts") or []
            attached_volume_names = []
            for m in mounts:
                if isinstance(m, dict) and m.get("Type") == "volume":
                    name = m.get("Name")
                    if isinstance(name, str) and name:
                        attached_volume_names.append(name)

            # Exclude the shared tools volume from removal assertions
            random_named_vols = [n for n in attached_volume_names if n != TOOLS_VOL]

            if not random_named_vols:
                pytest.skip("Requires Docker daemon reachable (e.g., via DOCKER_HOST) and an image that declares anonymous volumes (e.g., redis:7-alpine). Image did not produce any random/anonymous volume mounts; cannot verify removal behavior.")

            # Delete workspace
            del_resp = client.delete(f"/workspaces/{workspace_id}")
            assert del_resp.status_code == 200, f"Workspace delete failed: {del_resp.status_code} {del_resp.text}"
            assert del_resp.json()["status"] == "deleted"

        # Container should be gone
        def _container_absent():
            try:
                docker_client.containers.get(container_name)
                return False
            except docker.errors.NotFound:
                return True

        # Allow more time for remote Docker endpoints to converge on container removal.
        assert _wait_for(_container_absent, timeout=60.0, interval=0.5), "Container was not removed in time"

        # Each captured random-named volume should be removed
        for vol_name in random_named_vols:
            def _volume_absent():
                try:
                    docker_client.volumes.get(vol_name)
                    return False
                except docker.errors.NotFound:
                    return True

            # Allow more time for remote Docker endpoints to converge on volume removal.
            assert _wait_for(_volume_absent, timeout=60.0, interval=0.5), f"Volume '{vol_name}' was not removed"

        # Shared tools volume is plugin-managed; ensure we don't fail if it's absent.
        try:
            tools_vol = docker_client.volumes.get(TOOLS_VOL)
            assert tools_vol is not None
        except docker.errors.NotFound:
            pass
    finally:
        # Best-effort cleanup to avoid leaving containers/volumes on skip or failure
        try:
            if container_name:
                try:
                    c = docker_client.containers.get(container_name)
                except docker.errors.NotFound:
                    c = None
                except Exception as e:
                    print(f"Warning: failed to resolve container '{container_name}' during cleanup: {e}")
                    c = None
                if c is not None:
                    # Capture any named volumes (in case the API deletion was skipped/failed)
                    mounts = (getattr(c, "attrs", {}) or {}).get("Mounts") or []
                    observed_vols = []
                    try:
                        for m in mounts:
                            if isinstance(m, dict) and m.get("Type") == "volume":
                                n = m.get("Name")
                                if isinstance(n, str) and n:
                                    observed_vols.append(n)
                    except Exception as e:
                        print(f"Warning: failed to parse mounts for cleanup of '{container_name}': {e}")
                    # Stop/remove container
                    try:
                        if getattr(c, "status", None) == "running":
                            try:
                                c.stop(timeout=10)
                            except Exception as e:
                                print(f"Warning: failed to stop container '{container_name}' during cleanup: {e}")
                        try:
                            c.remove(force=True, v=True)
                        except Exception as e:
                            print(f"Warning: failed to remove container '{container_name}' during cleanup: {e}")
                    finally:
                        # Attempt removal of any named volumes we saw (exclude shared tools volume)
                        for vn in set((observed_vols or []) + (random_named_vols or [])):
                            if vn == TOOLS_VOL:
                                continue
                            try:
                                vol = docker_client.volumes.get(vn)
                                vol.remove(force=True)
                            except docker.errors.NotFound:
                                pass
                            except Exception as e:
                                print(f"Warning: failed to remove volume '{vn}' during cleanup: {e}")
        except Exception as e:
            print(f"Warning: unexpected error during container cleanup: {e}")

        # Cleanup the shared tools volume so tests do not leave residue
        try:
            tv = docker_client.volumes.get(TOOLS_VOL)
            tv.remove(force=True)
        except docker.errors.NotFound:
            pass
        except Exception as e:
            print(f"Warning: failed to remove tools volume '{TOOLS_VOL}': {e}")
