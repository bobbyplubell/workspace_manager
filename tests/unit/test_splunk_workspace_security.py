import os
from typing import Any, Dict, List

import pytest

from wm_client.applications.splunk_workspace import SplunkWorkspace


class _ExecRecorder:
    def __init__(self) -> None:
        self.exec_calls: List[Dict[str, Any]] = []
        self.verify_tls = True

    def exec(
        self,
        workspace_id: str,
        command: str,
        user: str = "splunk",
        cwd: str | None = None,
        env_vars: Dict[str, str] | None = None,
        timeout: int = 60,
    ) -> tuple[int, str, str]:
        self.exec_calls.append(
            {
                "workspace_id": workspace_id,
                "command": command,
                "user": user,
                "cwd": cwd,
                "env_vars": env_vars or {},
                "timeout": timeout,
            }
        )
        if "curl" in command:
            body = "ok\n___SPLUNK_CURL_STATUS___:200\n"
            return 0, body, ""
        return 0, "splunkd is running", ""


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SPLUNK_PASSWORD", raising=False)
    monkeypatch.delenv("SPLUNK_USERNAME", raising=False)


@pytest.mark.unit
def test_splunk_workspace_requires_credentials() -> None:
    client = _ExecRecorder()
    with pytest.raises(ValueError):
        SplunkWorkspace(client)


@pytest.mark.unit
def test_splunk_commands_run_as_non_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPLUNK_USERNAME", "admin")
    monkeypatch.setenv("SPLUNK_PASSWORD", "Testing123!")
    client = _ExecRecorder()
    sw = SplunkWorkspace(client)
    sw.splunk_status("ws-1")
    sw.splunk_start("ws-1", timeout=10)
    for call in client.exec_calls:
        assert call["user"] == "splunk", f"Expected splunk user, got {call['user']}"


@pytest.mark.unit
def test_splunk_rest_respects_tls_flag_and_hides_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPLUNK_USERNAME", "admin")
    monkeypatch.setenv("SPLUNK_PASSWORD", "Testing123!")
    client = _ExecRecorder()
    sw = SplunkWorkspace(client, verify_tls=True)
    status, body = sw.splunk_rest("ws-1", "GET", "services/server/info", timeout=5)
    assert status == 200
    assert "ok" in body
    cmd = client.exec_calls[-1]["command"]
    env_vars = client.exec_calls[-1]["env_vars"]
    assert "--netrc-file" in cmd
    assert "-k" not in cmd, "Insecure curl flag should not be present when verify_tls=True"
    assert "-u" not in cmd, "Credentials must not be embedded directly in curl command"
    assert env_vars.get("SPLUNK_ADMIN_PASSWORD") == "Testing123!"

    insecure_client = _ExecRecorder()
    sw_insecure = SplunkWorkspace(insecure_client, verify_tls=False)
    monkeypatch.setenv("SPLUNK_USERNAME", "admin")
    monkeypatch.setenv("SPLUNK_PASSWORD", "Testing123!")
    sw_insecure.splunk_rest("ws-2", "GET", "services/server/info", timeout=5)
    insecure_cmd = insecure_client.exec_calls[-1]["command"]
    assert "-k" in insecure_cmd, "curl should include -k when verify_tls is false"
