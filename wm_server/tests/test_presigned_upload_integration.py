import os
import tarfile
from io import BytesIO
from types import SimpleNamespace
from typing import Dict, List, Optional

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def fake_container(tmp_path):
    """
    Minimal fake container that satisfies the upload endpoints.
    Stores files under a temp directory to simulate a container filesystem.
    """

    class FakeContainer:
        def __init__(self, workspace_id: str, api_key_suffix: Optional[str]) -> None:
            self.workspace_id = workspace_id
            self.status = "running"
            self.labels = {
                "splk.ws.managed": "true",
                "splk.ws.id": workspace_id,
            }
            if api_key_suffix:
                self.labels["splk.ws.owner_api_key_suffix"] = api_key_suffix
            self.root = tmp_path
            self.image = SimpleNamespace(tags=["fake:image"])

        def reload(self) -> None:
            return

        def start(self) -> None:
            self.status = "running"

        def unpause(self) -> None:
            self.status = "running"

        def exec_run(self, _cmd, **_kwargs):
            # Accept mkdir commands; other commands are treated as success no-ops.
            try:
                parts = _cmd[-1] if isinstance(_cmd, list) else ""
                if "mkdir" in parts:
                    # naive mkdir -p handling for the test
                    path = parts.split()[-1].strip("'\"")
                    self.root.joinpath(path.lstrip("/")).mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return SimpleNamespace(exit_code=0, output=(b"", b""))

        def put_archive(self, parent: str, data) -> None:
            # Extract tar stream into the fake filesystem rooted at tmp_path.
            buf = BytesIO(data.read())
            buf.seek(0)
            with tarfile.open(fileobj=buf, mode="r:*") as tar:
                tar.extractall(self.root.joinpath(parent.lstrip("/")))

    return FakeContainer


@pytest.fixture()
def fake_docker_client(fake_container):
    class FakeContainers:
        def __init__(self, container_map: Dict[str, object]):
            self._map = container_map

        def get(self, name: str):
            if name not in self._map:
                from docker.errors import NotFound

                raise NotFound(f"{name} not found")
            return self._map[name]

        def list(self, all: bool = True, filters: Optional[Dict[str, object]] = None) -> List[object]:
            if not filters or "label" not in filters:
                return list(self._map.values())
            labels = filters["label"]
            if isinstance(labels, str):
                labels = [labels]
            results = []
            for c in self._map.values():
                ok = True
                for label_filter in labels:
                    key, value = label_filter.split("=", 1)
                    if getattr(c, "labels", {}).get(key) != value:
                        ok = False
                        break
                if ok:
                    results.append(c)
            return results

    class FakeDockerClient:
        def __init__(self, container_map: Dict[str, object]) -> None:
            self.containers = FakeContainers(container_map)

        def close(self) -> None:
            return

    def _factory(container_map: Dict[str, object]) -> FakeDockerClient:
        return FakeDockerClient(container_map)

    return _factory


def test_presigned_upload_round_trip(monkeypatch, fake_container, fake_docker_client):
    # Configure env for API key auth and token secret
    api_key = "TESTKEY123"
    monkeypatch.setenv("WORKSPACE_API_KEY", api_key)
    monkeypatch.setenv("WORKSPACE_UPLOAD_TOKEN_SECRET", "test-upload-secret")
    # Clear cached settings to pick up env overrides
    from wm_server.app import config as cfg

    cfg.get_settings.cache_clear()
    new_settings = cfg.get_settings()

    # Build fake Docker client + container map
    workspace_id = "ws-integration"
    suffix = api_key[-8:]
    container = fake_container(workspace_id, api_key_suffix=suffix)

    # Monkeypatch docker client dependency and startup check
    from wm_server.app import main as wm_main
    from wm_server.app import deps
    from wm_server.app.routers import workspaces

    wm_main.ensure_docker_available_on_startup = lambda: None
    wm_main.settings = new_settings
    fake_client = fake_docker_client({f"{new_settings.container_name_prefix}{workspace_id}": container})
    # Patch docker.from_env where used to avoid touching real Docker
    monkeypatch.setattr("wm_server.app.deps.docker.from_env", lambda timeout=None: fake_client)
    monkeypatch.setattr("wm_server.app.main.docker.from_env", lambda timeout=None: fake_client)
    deps.docker_client = lambda settings=cfg.get_settings(): fake_client
    workspaces.docker_client = deps.docker_client  # ensure router uses override
    # Ensure router is attached when lifespan is bypassed/mocked
    if "/workspaces" not in {r.path for r in wm_main.app.router.routes}:
        wm_main.app.include_router(workspaces.router, prefix="/workspaces", tags=["workspaces"])
    wm_main.app.dependency_overrides[workspaces.docker_client] = lambda settings=cfg.get_settings(): fake_client

    # Create test client
    client = TestClient(wm_main.app)

    destination = "/tmp/workspace/staging/uploads/test.txt"

    # 1) Request upload token
    token_resp = client.post(
        f"/workspaces/{workspace_id}/generate-upload-token",
        params={"destination_path": destination},
        headers={"X-API-Key": api_key},
    )
    assert token_resp.status_code == 200, token_resp.text
    token_data = token_resp.json()
    header_name = token_data["header"]
    token_val = token_data["token"]

    # 2) Perform upload using returned token
    upload_resp = client.post(
        f"/workspaces/{workspace_id}/files/copy-to",
        params={"destination_path": destination},
        headers={header_name: token_val, "X-API-Key": api_key},
        files={"file": ("test.txt", b"hello world", "text/plain")},
    )
    assert upload_resp.status_code == 200, upload_resp.text

    # 3) Assert file written to fake container root
    saved = container.root.joinpath(destination.lstrip("/"))
    assert saved.read_text() == "hello world"
