"""
Splunk workspace helpers.

This module defines `SplunkWorkspace`, a small helper focused on interacting with
a Splunk instance running inside a WorkspaceManager workspace. It wraps common
operations like checking status, starting Splunk, and making REST calls via
`curl` executed through the WorkspaceManager API.

Example:
    from wm_client import WorkspaceManagerClient
    from wm_client.applications.splunk_workspace import SplunkWorkspace

    client = WorkspaceManagerClient(base_url="https://wm.example.test")
    sw = SplunkWorkspace(client, verify_tls=False)  # allow self-signed Splunk certs if needed
    ws = client.create_workspace(
        application_params={"splunk_password": "use-a-strong-password"},
        require_application_params=True,
    )
    wsid = ws["workspace_id"]

    # Ensure Splunk started (idempotent)
    sw.splunk_start(wsid, timeout=600)

    # Check status
    print(sw.splunk_status(wsid))

    # REST call
    code, body = sw.splunk_rest(wsid, "GET", "services/server/info", params={"output_mode": "json"})
"""

from __future__ import annotations

import os
import shlex
import time
from typing import Dict, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .. import WorkspaceManagerClient
from ..constants import (
    ENV_SPLUNK_PASSWORD,
    ENV_SPLUNK_USERNAME,
    SPLUNK_DEFAULT_HOME,
    SPLUNKD_SCHEME,
    SPLUNKD_HOST,
    SPLUNKD_PORT,
)
from ..config import get_settings as get_client_settings


class SplunkWorkspace:
    """
    Convenience helpers for interacting with Splunk inside a workspace via the API.

    Example:
        sw = SplunkWorkspace(client)
        sw.splunk_start(wsid, timeout=600)
        txt = sw.splunk_status(wsid)
        code, body = sw.splunk_rest(
            wsid, "GET", "services/server/info", params={"output_mode":"json"}
        )
    """

    def __init__(
        self,
        client: WorkspaceManagerClient,
        splunk_username: Optional[str] = None,
        splunk_password: Optional[str] = None,
        verify_tls: Optional[bool] = None,
        run_as_user: str = "splunk",
    ) -> None:
        self.client = client
        cfg = get_client_settings()
        self.splunk_username = splunk_username or os.environ.get(ENV_SPLUNK_USERNAME)
        if not self.splunk_username:
            raise ValueError("splunk_username is required (set SPLUNK_USERNAME or pass explicitly)")
        pwd = splunk_password or os.environ.get(ENV_SPLUNK_PASSWORD) or cfg.splunk_password
        if not pwd:
            raise ValueError(
                "splunk_password is required. Provide it explicitly or via the SPLUNK_PASSWORD environment variable."
            )
        self.splunk_password = pwd
        self.verify_tls = bool(verify_tls if verify_tls is not None else getattr(client, "verify_tls", True))
        self.run_as_user = run_as_user or "splunk"

    def splunk_status(self, workspace_id: str, timeout: int = 120) -> str:
        rc, out, err = self.client.exec(
            workspace_id,
            f"SPLUNK_HOME=${{SPLUNK_HOME:-{SPLUNK_DEFAULT_HOME}}}; $SPLUNK_HOME/bin/splunk status",
            user=self.run_as_user,
            timeout=timeout,
        )
        return out or err or ""

    def splunk_start(self, workspace_id: str, timeout: int = 600) -> None:
        """
        Ensure Splunk is running inside the workspace.

        The method now waits for Splunk to report a running status after issuing
        the start command, rather than assuming 'splunk start' is synchronous.
        """

        total_timeout = max(60, int(timeout or 60))
        status_timeout = min(120, total_timeout)

        def _is_running() -> bool:
            rc, out, err = self.client.exec(
                workspace_id,
                f"SPLUNK_HOME=${{SPLUNK_HOME:-{SPLUNK_DEFAULT_HOME}}}; $SPLUNK_HOME/bin/splunk status",
                user=self.run_as_user,
                timeout=status_timeout,
            )
            txt = (out or "") + (err or "")
            return rc == 0 and "running" in txt.lower()

        if _is_running():
            return

        rc_start, _start_out, start_err = self.client.exec(
            workspace_id,
            f"SPLUNK_HOME=${{SPLUNK_HOME:-{SPLUNK_DEFAULT_HOME}}}; "
            f"$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt",
            user=self.run_as_user,
            timeout=total_timeout,
        )
        if rc_start != 0:
            raise RuntimeError(f"Failed to start Splunk (rc={rc_start}): {start_err}")

        deadline = time.time() + total_timeout
        while time.time() < deadline:
            if _is_running():
                return
            time.sleep(5)

        raise RuntimeError("Splunk did not report a running status before timeout")

    def splunk_rest(
        self,
        workspace_id: str,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        timeout: int = 60,
    ) -> Tuple[int, str]:
        """
        Perform a Splunk REST call via curl executed inside the container.

        Returns (http_status_code, response_body_text)
        """
        scheme = SPLUNKD_SCHEME
        host = SPLUNKD_HOST
        port = SPLUNKD_PORT
        rel = path.lstrip("/")
        url = f"{scheme}://{host}:{port}/{rel}"
        status_tag = "___SPLUNK_CURL_STATUS___"
        trailer = "-w '\\n{tag}:%{{http_code}}\\n'".format(tag=status_tag)
        m = (method or "GET").upper()
        try:
            total = int(timeout or 60)
        except Exception:
            total = 60
        connect_timeout = max(1, min(30, (total // 2) or 5))
        max_time = max(1, total - 2)

        if rel.startswith("services/search/jobs/export") and m == "GET":
            merged: Dict[str, str] = {}
            merged.update(dict(params or {}))
            merged.update(dict(data or {}))
            data = merged
            params = {}
            m = "POST"

        curl_parts = [
            "curl -s",
            f"--connect-timeout {connect_timeout}",
            f"--max-time {max_time}",
            "--netrc-file \"$auth_file\"",
        ]
        if not self.verify_tls:
            curl_parts.append("-k")

        exec_env = {
            "SPLUNK_ADMIN_USERNAME": self.splunk_username,
            "SPLUNK_ADMIN_PASSWORD": self.splunk_password,
        }

        if m == "GET":
            params = dict(params or {})
            params.setdefault("output_mode", "json")
            qs = ""
            if params:
                qs = "?" + "&".join([f"{k}={v}" for k, v in params.items()])
            target = shlex.quote(f"{url}{qs}")
            curl_parts.extend([trailer, target])
        else:
            data = dict(data or {})
            data.setdefault("output_mode", "json")
            form = "&".join([f"{k}={v}" for k, v in data.items()])
            curl_parts.extend(
                [
                    f"-X {m}",
                    "-H 'Content-Type: application/x-www-form-urlencoded'",
                    f"--data {shlex.quote(form)}",
                    trailer,
                    shlex.quote(url),
                ]
            )

        curl_cmd = " ".join(part for part in curl_parts if part)
        cmd = (
            "auth_file=$(mktemp /tmp/splk_auth.XXXXXX) && "
            "trap 'rm -f \"$auth_file\"' INT TERM EXIT && "
            "chmod 600 \"$auth_file\" && "
            "printf 'machine {host}\\nlogin %s\\npassword %s\\n' "
            "\"$SPLUNK_ADMIN_USERNAME\" \"$SPLUNK_ADMIN_PASSWORD\" > \"$auth_file\" && "
            "{curl}; "
            "rc=$?; rm -f \"$auth_file\"; trap - INT TERM EXIT; exit $rc"
        ).format(host=host, curl=curl_cmd)

        rc, out, err = self.client.exec(
            workspace_id,
            cmd,
            user=self.run_as_user,
            env_vars=exec_env,
            timeout=timeout,
        )
        text = out or ""
        marker = f"\n{status_tag}:"
        status = 0
        body = text
        if marker in text:
            body, code_str = text.rsplit(marker, 1)
            try:
                status = int(code_str.strip())
            except Exception:
                status = 0
        return status, body


__all__ = ["SplunkWorkspace"]
