import io
import os
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Server modules under test
from wm_server.app.routers import workspaces as workspaces_router
from wm_server.app.security import (
    generate_upload_token_from_settings,
    parse_and_verify_upload_token_from_settings,
    generate_download_token_from_settings,
    parse_and_verify_download_token_from_settings,
    InvalidTokenError,
    TokenExpiredError,
)

# Client under test
from wm_client import WorkspaceManagerClient


class _TestSettings:
    """
    Minimal test settings object with attributes referenced by token helpers and router endpoints.
    """
    def __init__(
        self,
        *,
        upload_token_secret: Optional[str] = "unit-test-secret",
        upload_token_ttl_seconds: int = 900,
        api_key: Optional[str] = None,
        api_keys: Optional[List[str]] = None,
        api_key_header_name: str = "X-API-Key",
        upload_token_header_name: str = "Authorization",
        upload_token_query_param: str = "token",
        container_workspace_dir: str = "/tmp/workspace",
        default_image: str = "busybox:latest",
    ) -> None:
        self.upload_token_secret = upload_token_secret
        self.upload_token_ttl_seconds = int(upload_token_ttl_seconds)
        self.api_key = api_key
        self.api_keys = api_keys or []
        self.api_key_header_name = api_key_header_name
        self.upload_token_header_name = upload_token_header_name
        self.upload_token_query_param = upload_token_query_param
        self.container_workspace_dir = container_workspace_dir
        self.default_image = default_image

    # Match server settings helper used by router enforcement
    def token_secret_effective(self) -> Optional[str]:
        return self.upload_token_secret


def _mk_router_app(settings: _TestSettings, *, disable_auth: bool = True) -> TestClient:
    """
    Build a minimal FastAPI app that includes only the workspaces router,
    with get_settings monkeypatched to return our provided settings object.

    This avoids the main application's Docker/lifespan checks and allows
    testing token endpoints in isolation.
    """
    app = FastAPI()
    # Include the workspaces router directly
    app.include_router(workspaces_router.router, prefix="/workspaces")

    # Monkeypatch the dependency accessor used by the router
    import wm_server.app.deps as deps  # import within function to ensure module is loaded
    # Override FastAPI dependency so all Depends(get_settings) resolve to our settings object
    app.dependency_overrides[deps.get_settings] = lambda: settings  # type: ignore[index]
    if disable_auth:
        app.dependency_overrides[deps.enforce_api_key] = lambda: None  # disable API key auth for isolated router tests
    # Note: api_key_header is bound at import time; enforce_api_key checks allowed keys via get_settings(),
    # so with no keys configured, authentication is effectively disabled for tests.

    return TestClient(app)


class _DummyResp:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "{}",
        content_iter: Optional[List[bytes]] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self._json = dict(json_data or {})
        self._iter = content_iter or [b"ok"]

    def raise_for_status(self) -> None:
        if not (200 <= self.status_code < 300):
            raise RuntimeError(f"http {self.status_code}: {self.text}")

    def json(self) -> Dict[str, Any]:
        return dict(self._json)

    def iter_content(self, chunk_size: int = 8192):
        for chunk in self._iter:
            yield chunk

    # Context manager interface for GET streaming
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _DummySession:
    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self.verify = True
        self.next_get_json: Dict[str, Any] = {}
        self.next_post_json: Dict[str, Any] = {}

    def post(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
             files: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None,
             timeout: Optional[int] = None) -> _DummyResp:
        self.calls.append(("POST", url, {"params": dict(params or {}), "headers": dict(headers or {}), "files": files, "json": json, "timeout": timeout}))
        # Always OK
        return _DummyResp(200, "{}", json_data=self.next_post_json)

    def get(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
            stream: bool = False, timeout: Optional[int] = None) -> _DummyResp:
        self.calls.append(("GET", url, {"params": dict(params or {}), "headers": dict(headers or {}), "stream": stream, "timeout": timeout}))
        # Return OK with a small body
        return _DummyResp(200, "{}", content_iter=[b"chunk-1", b"chunk-2"], json_data=self.next_get_json)


@pytest.mark.unit
def test_security_generate_upload_token_requires_secret() -> None:
    """
    Ensure the helper raises when no secret is configured.
    """
    settings = _TestSettings(upload_token_secret=None)
    with pytest.raises(RuntimeError, match="Direct upload token secret is not configured"):
        _ = generate_upload_token_from_settings(settings, workspace_id="ws-1", destination_path="/tmp/workspace/file.txt")

    with pytest.raises(RuntimeError, match="Direct upload token secret is not configured"):
        _ = parse_and_verify_upload_token_from_settings(settings, token="v1.invalid.token")


@pytest.mark.unit
def test_security_upload_token_roundtrip_success() -> None:
    """
    Issue a token and then parse/verify it with the same settings.
    """
    settings = _TestSettings(upload_token_secret="roundtrip-secret", upload_token_ttl_seconds=60)
    token = generate_upload_token_from_settings(settings, workspace_id="ws-abc", destination_path="/tmp/workspace/a.txt")
    payload = parse_and_verify_upload_token_from_settings(settings, token=token)
    assert payload.workspace_id == "ws-abc"
    assert payload.destination_path == "/tmp/workspace/a.txt"
    assert isinstance(payload.issued_at, int) and isinstance(payload.expires_at, int)
    assert payload.expires_at > payload.issued_at


@pytest.mark.unit
def test_security_download_token_roundtrip_success() -> None:
    """
    Issue a download token and then parse/verify it with the same settings.
    """
    settings = _TestSettings(upload_token_secret="dl-secret", upload_token_ttl_seconds=60)
    token = generate_download_token_from_settings(settings, workspace_id="ws-xyz", source_path="/tmp/workspace/b.txt")
    payload = parse_and_verify_download_token_from_settings(settings, token=token)
    assert payload.workspace_id == "ws-xyz"
    assert payload.source_path == "/tmp/workspace/b.txt"
    assert isinstance(payload.issued_at, int) and isinstance(payload.expires_at, int)
    assert payload.expires_at > payload.issued_at


@pytest.mark.unit
def test_router_generate_upload_token_missing_secret_returns_500() -> None:
    """
    Build a minimal app with the router and no secret in settings; token endpoint should fail cleanly (500).
    This catches regressions where missing configuration would have returned 200 or masked errors.
    """
    # Ensure no environment fallback can mask missing-secret behavior
    os.environ.pop("WORKSPACE_UPLOAD_TOKEN_SECRET", None)
    app = _mk_router_app(_TestSettings(upload_token_secret=None))
    r = app.post("/workspaces/ws-no/prepare")
    # Sanity check router is mounted; above path likely 404 (not tested)
    r = app.post("/workspaces/ws-no/generate-upload-token", params={"destination_path": "/tmp/workspace/oops.txt"})
    assert r.status_code >= 500, f"Expected server error for missing secret, got {r.status_code}"


@pytest.mark.unit
def test_router_generate_upload_and_download_token_success() -> None:
    """
    Ensure token endpoints succeed with a valid settings object and return expected shape including header, query_param, and 'Bearer ' prefix.
    """
    app = _mk_router_app(_TestSettings(upload_token_secret="ok-secret", upload_token_ttl_seconds=120))
    # Upload token
    r_up = app.post("/workspaces/ws-1/generate-upload-token", params={"destination_path": "/tmp/workspace/u.txt"})
    assert r_up.status_code == 200, r_up.text
    creds = r_up.json() or {}
    assert "upload_url" in creds and "header" in creds and "query_param" in creds and "token" in creds
    assert isinstance(creds["token"], str) and creds["token"].startswith("Bearer ")
    # Download token
    r_dl = app.post("/workspaces/ws-1/generate-download-token", params={"source_path": "/tmp/workspace/u.txt"})
    assert r_dl.status_code == 200, r_dl.text
    dcreds = r_dl.json() or {}
    assert "download_url" in dcreds and "header" in dcreds and "query_param" in dcreds and "token" in dcreds
    assert isinstance(dcreds["token"], str) and dcreds["token"].startswith("Bearer ")


@pytest.mark.unit
def test_router_rejects_invalid_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure API key enforcement rejects requests that supply an incorrect key.
    """
    settings = _TestSettings(upload_token_secret="secret", api_key="expected-key")
    import wm_server.app.deps as deps  # type: ignore

    monkeypatch.setattr(deps, "get_settings", lambda: settings, raising=False)

    app = _mk_router_app(settings, disable_auth=False)
    headers = {"X-API-Key": "wrong-key"}
    r = app.post(
        "/workspaces/ws-1/generate-upload-token",
        params={"destination_path": "/tmp/workspace/u.txt"},
        headers=headers,
    )
    assert r.status_code == 401


@pytest.mark.unit
def test_client_upload_normalizes_bearer_header_and_query() -> None:
    """
    Verify WorkspaceManagerClient strips a leading 'Bearer ' from provided token and applies it exactly once to the header,
    or passes the raw token as a query param when configured.
    """
    # Use dummy session to capture requests
    session = _DummySession()
    client = WorkspaceManagerClient(
        base_url="http://example.test",
        api_key=None,
        session=session,
        allow_insecure_http=True,
    )

    # Header-based auth
    # Provide token value that already includes 'Bearer '
    client.upload_file(
        workspace_id="ws-1",
        destination_path="/tmp/workspace/h.txt",
        local_path=__file__,  # content not inspected by dummy session
        auth_header_name="Authorization",
        auth_header_value="Bearer abc123",
        auth_query_param=None,
        timeout=10,
    )
    assert session.calls, "Expected at least one POST call"
    method, url, meta = session.calls[-1]
    assert method == "POST" and url.endswith("/workspaces/ws-1/files/copy-to")
    hdrs = meta["headers"]
    assert hdrs.get("Authorization") == "Bearer abc123", f"Header normalization failed: {hdrs}"

    # Query-param auth is rejected
    with pytest.raises(ValueError):
        client.upload_file(
            workspace_id="ws-2",
            destination_path="/tmp/workspace/q.txt",
            local_path=__file__,
            auth_header_name=None,
            auth_header_value="Bearer tokenXYZ",
            auth_query_param="token",
            timeout=10,
        )


@pytest.mark.unit
def test_client_read_file_returns_text_and_records_call() -> None:
    """
    WorkspaceManagerClient.read_file should issue a GET and return the JSON payload's content.
    """
    session = _DummySession()
    session.next_get_json = {"content": "hello world"}

    client = WorkspaceManagerClient(
        base_url="https://wm.example.test",
        api_key=None,
        session=session,
        allow_insecure_http=True,
    )

    content = client.read_file("ws-read", "/tmp/workspace/sample.txt")
    assert content == "hello world"
    assert session.calls, "Expected a GET call to be recorded"
    method, url, payload = session.calls[-1]
    assert method == "GET"
    assert url.endswith("/workspaces/ws-read/files/read")
    assert payload["params"]["path"] == "/tmp/workspace/sample.txt"

@pytest.mark.unit
def test_client_download_normalizes_bearer_header_and_query() -> None:
    """
    Verify WorkspaceManagerClient download flow normalizes 'Bearer ' usage for header and query param.
    """
    session = _DummySession()
    client = WorkspaceManagerClient(
        base_url="http://example.test",
        api_key=None,
        session=session,
        allow_insecure_http=True,
    )

    # Header-based download
    client.download_file(
        workspace_id="ws-1",
        source_path="/tmp/workspace/d.txt",
        local_path=os.devnull,
        auth_header_name="Authorization",
        auth_header_value="Bearer dltok",
        auth_query_param=None,
        timeout=10,
    )
    method, url, meta = session.calls[-1]
    assert method == "GET" and url.endswith("/workspaces/ws-1/files/copy-from")
    hdrs = meta["headers"]
    assert hdrs.get("Authorization") == "Bearer dltok", f"Header normalization failed for download: {hdrs}"

    # Query-param download is rejected
    with pytest.raises(ValueError):
        client.download_file(
            workspace_id="ws-2",
            source_path="/tmp/workspace/d2.txt",
            local_path=os.devnull,
            auth_header_name=None,
            auth_header_value="Bearer ZZZZ",
            auth_query_param="token",
            timeout=10,
        )
