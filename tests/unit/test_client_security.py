import io
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

import wm_client.config as client_config
from wm_client import WorkspaceManagerClient


class _DummyResponse:
    def __init__(self, status_code: int = 200, json_data: Optional[Dict[str, Any]] = None) -> None:
        self.status_code = status_code
        self._json = json_data or {}
        self.text = "{}"

    def json(self) -> Dict[str, Any]:
        return dict(self._json)

    def raise_for_status(self) -> None:
        if not (200 <= self.status_code < 300):
            raise RuntimeError(f"http {self.status_code}: {self.text}")


class _StreamingResponse(_DummyResponse):
    def __init__(self, chunks: List[bytes], status_code: int = 200) -> None:
        super().__init__(status_code=status_code)
        self._chunks = chunks

    def iter_content(self, chunk_size: int = 8192):
        for chunk in self._chunks:
            yield chunk

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _InstrumentedSession:
    def __init__(self, *, download_chunks: Optional[List[bytes]] = None, delete_status: int = 200) -> None:
        self.download_chunks = download_chunks
        self.delete_status = delete_status
        self.calls: List[Dict[str, Any]] = []

    def post(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> _DummyResponse:
        self.calls.append({"method": "POST", "url": url, "params": params, "headers": headers, "json": json})
        # Eagerly read any provided file objects to simulate requests' behaviour.
        if files:
            for _name, (_filename, fh, _ctype) in files.items():
                while True:
                    chunk = fh.read(1024)
                    if not chunk:
                        break
        return _DummyResponse()

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        stream: bool = False,
        timeout: Optional[int] = None,
    ):
        self.calls.append({"method": "GET", "url": url, "params": params, "headers": headers, "stream": stream})
        if stream and self.download_chunks is not None:
            return _StreamingResponse(self.download_chunks)
        return _DummyResponse()

    def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> _DummyResponse:
        self.calls.append({"method": "DELETE", "url": url, "headers": headers})
        return _DummyResponse(status_code=self.delete_status)


@pytest.fixture(autouse=True)
def _reset_client_config():
    """
    Ensure each test can freely mutate environment variables consumed by the client config.
    """
    client_config.get_settings.cache_clear()
    yield
    client_config.get_settings.cache_clear()


def _https_client(session: Optional[_InstrumentedSession] = None, **kwargs) -> WorkspaceManagerClient:
    sess = session or _InstrumentedSession()
    return WorkspaceManagerClient(
        base_url="https://example.test",
        api_key=None,
        session=sess,
        **kwargs,
    )


@pytest.mark.unit
def test_create_workspace_requires_application_params_when_flagged() -> None:
    client = _https_client()
    with pytest.raises(ValueError):
        client.create_workspace(require_application_params=True)


@pytest.mark.unit
def test_create_workspace_accepts_application_params() -> None:
    client = _https_client()
    client.create_workspace(application_params={"foo": "bar"}, require_application_params=True)


@pytest.mark.unit
def test_create_workspace_allows_image_and_kind() -> None:
    session = _InstrumentedSession()
    client = _https_client(session=session)
    client.create_workspace(image="aire-workspace:latest", application_kind="aire")
    call = session.calls[-1]
    body = call.get("json") or {}
    assert body.get("image") == "aire-workspace:latest"
    assert body.get("application_kind") == "aire"


@pytest.mark.unit
def test_create_workspace_rejects_blocked_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPLUNK_PASSWORD", "DevPassw0rd!")
    client = _https_client()
    with pytest.raises(ValueError):
        client.create_workspace(env_vars={"LD_PRELOAD": "libhack.so"})


@pytest.mark.unit
def test_create_workspace_blocks_privileged_host_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("Privileged-port guard only applies to non-root test environments")
    monkeypatch.setenv("SPLUNK_PASSWORD", "DevPassw0rd!")
    client = _https_client()
    with pytest.raises(PermissionError):
        client.create_workspace(ports={"8089/tcp": 80})


@pytest.mark.unit
def test_upload_file_enforces_max_bytes(tmp_path: Path) -> None:
    big_file = tmp_path / "big.bin"
    big_file.write_bytes(b"A" * 10)
    client = _https_client()
    with pytest.raises(ValueError):
        client.upload_file(
            workspace_id="ws1",
            destination_path="/tmp/workspace/big.bin",
            local_path=str(big_file),
            max_bytes=5,
        )


@pytest.mark.unit
def test_upload_bytes_enforces_limits_for_streams() -> None:
    session = _InstrumentedSession()
    client = _https_client(session=session)
    data = io.BytesIO(b"0123456789")
    with pytest.raises(ValueError):
        client.upload_bytes(
            workspace_id="ws-stream",
            destination_path="/tmp/workspace/stream.bin",
            data=data,
            max_bytes=5,
        )


@pytest.mark.unit
def test_download_file_enforces_limit(tmp_path: Path) -> None:
    target = tmp_path / "download.bin"
    session = _InstrumentedSession(download_chunks=[b"abc", b"def"])
    client = _https_client(session=session)
    with pytest.raises(ValueError):
        client.download_file(
            workspace_id="ws1",
            source_path="/tmp/workspace/source.bin",
            local_path=str(target),
            max_bytes=5,
        )
    assert not target.exists(), "Partial download should be removed when exceeding limit"


@pytest.mark.unit
def test_delete_workspace_status_handling() -> None:
    session = _InstrumentedSession(delete_status=404)
    client = _https_client(session=session)
    assert client.delete_workspace("missing") is False

    session_conflict = _InstrumentedSession(delete_status=409)
    client_conflict = _https_client(session=session_conflict)
    with pytest.raises(RuntimeError):
        client_conflict.delete_workspace("bad-state")


@pytest.mark.unit
def test_http_base_url_requires_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WM_ALLOW_INSECURE_HTTP", raising=False)
    client_config.get_settings.cache_clear()
    with pytest.raises(ValueError):
        WorkspaceManagerClient(base_url="http://example.test", api_key=None, session=_InstrumentedSession())
