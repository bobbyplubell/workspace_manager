"""
WorkspaceManager Python Client (minimal SDK)

This module provides a thin, synchronous client for the WorkspaceManager API (wm_server),
along with Splunk-specific convenience helpers used in integration tests.

Features implemented (minimal surface):
- health()
- create_workspace(...)
- delete_workspace(wsid)
- exec(wsid, command, user="splunk", cwd=None, env_vars=None, timeout=300)
- mkdir(wsid, path, parents=True, mode=None)
- write_file(wsid, path, content)
- SplunkHelpers:
  - splunk_start(wsid, timeout=600)
  - splunk_status(wsid, timeout=120)
  - splunk_rest(wsid, method, path, params=None, data=None, timeout=60)
"""

from __future__ import annotations

import io
import logging
import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

from .constants import (
    DEFAULT_API_KEY_HEADER,
    COMMAND_ENV_PREFIX,
)
from .config import get_settings as get_client_settings


logger = logging.getLogger(__name__)
_PORT_KEY_PATTERN = re.compile(r"^(?P<container>\d{1,5})/(?P<proto>tcp|udp)$", re.IGNORECASE)
_ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BLOCKED_ENV_VARS = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "PYTHONPATH",
    "PYTHONHOME",
    "PATH",
    "IFS",
    "ENV",
    "BASH_ENV",
    "PROMPT_COMMAND",
    "HOME",
    "PWD",
    "SHELL",
}
_BLOCKED_ENV_PREFIXES = ("LD_", "DYLD_")


def _running_as_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows/other platforms do not expose geteuid; assume non-root for safety.
        return False


_IS_ROOT = _running_as_root()


class _LimitedStream:
    """
    Wrap a file-like object and enforce a maximum byte count while streaming.
    """

    def __init__(self, raw, limit: int) -> None:
        self._raw = raw
        self._limit = int(limit)
        self._count = 0

    def read(self, size: int = -1):  # pragma: no cover - exercised indirectly via requests
        chunk = self._raw.read(size)
        if not chunk:
            return chunk
        chunk_len = len(chunk)
        self._count += chunk_len
        if self._count > self._limit:
            raise ValueError("Upload exceeded max_bytes limit while streaming")
        return chunk

    def __getattr__(self, item):
        return getattr(self._raw, item)


class WorkspaceManagerClient:
    """
    Minimal synchronous client for the WorkspaceManager API.

    Example:
        client = WorkspaceManagerClient(
            base_url="https://wm.example.test",
            api_key="my-secret",  # optional (server may run without auth)
        )
        # Provide app-specific parameters explicitly; no insecure defaults are shipped.
        ws = client.create_workspace(application_params={"splunk_password": "use-a-strong-password"})
        wsid = ws.get("workspace_id")
        rc, out, err = client.exec(wsid, "echo hello")
        client.delete_workspace(wsid)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_header_name: Optional[str] = None,
        session: Optional[requests.Session] = None,
        *,
        verify_tls: Optional[bool] = None,
        allow_insecure_http: Optional[bool] = None,
        allow_insecure_tls: Optional[bool] = None,
        max_file_transfer_bytes: Optional[int] = None,
    ) -> None:
        cfg = get_client_settings()
        self.verify_tls = bool(cfg.verify_tls if verify_tls is None else verify_tls)
        self.allow_insecure_http = bool(cfg.allow_insecure_http if allow_insecure_http is None else allow_insecure_http)
        self.allow_insecure_tls = bool(cfg.allow_insecure_tls if allow_insecure_tls is None else allow_insecure_tls)
        if self.verify_tls is False and not self.allow_insecure_tls:
            raise ValueError(
                "TLS verification cannot be disabled without explicitly allowing insecure TLS "
                "(set allow_insecure_tls=True or WM_ALLOW_INSECURE_TLS=true)."
            )
        self.max_file_transfer_bytes = int(
            max_file_transfer_bytes if max_file_transfer_bytes is not None else cfg.max_file_transfer_bytes
        )
        if self.max_file_transfer_bytes <= 0:
            raise ValueError("max_file_transfer_bytes must be greater than zero")

        raw_base_url = (base_url or cfg.base_url_normalized).rstrip("/")
        self._enforce_transport_policy(raw_base_url)
        self.base_url = raw_base_url
        self.api_key = api_key if api_key is not None else cfg.api_key
        self.api_key_header_name = (api_key_header_name or cfg.api_key_header_name or DEFAULT_API_KEY_HEADER)
        self._session = session or requests.Session()

        try:
            if session is None:
                self._session.verify = self.verify_tls
            elif verify_tls is not None:
                session.verify = self.verify_tls
        except Exception:
            # best-effort; requests.Session.verify assignment may vary in unusual environments
            pass

    # -----------------------
    # Internal helpers
    # -----------------------

    def _enforce_transport_policy(self, url: str) -> None:
        """
        Ensure callers explicitly opt in before using insecure HTTP transports.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported WorkspaceManager base_url scheme: {scheme or 'missing'}")
        if scheme == "http" and not self.allow_insecure_http:
            raise ValueError(
                "Plain HTTP base URLs are disabled. "
                "Set allow_insecure_http=True (or WM_ALLOW_INSECURE_HTTP=true) "
                "only when running in a trusted development environment."
            )

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {}
        if self.api_key:
            h[self.api_key_header_name] = self.api_key
        return h

    @staticmethod
    def _sanitize_env_vars(env_vars: Optional[Dict[str, str]]) -> Dict[str, str]:
        if not env_vars:
            return {}
        sanitized: Dict[str, str] = {}
        for key, value in env_vars.items():
            if not isinstance(key, str) or not key:
                raise ValueError("Environment variable names must be non-empty strings")
            if not _ENV_KEY_PATTERN.match(key):
                raise ValueError(f"Environment variable name {key!r} contains unsupported characters")
            upper = key.upper()
            if upper in _BLOCKED_ENV_VARS or any(upper.startswith(prefix) for prefix in _BLOCKED_ENV_PREFIXES):
                raise ValueError(f"Environment variable {key!r} is blocked for workspace safety")
            if not isinstance(value, str):
                raise ValueError(f"Environment variable {key!r} must map to a string value")
            sanitized[key] = value
        return sanitized

    @staticmethod
    def _sanitize_application_params(params: Optional[Dict[str, Any]]) -> Dict[str, str]:
        if not params:
            return {}
        sanitized: Dict[str, str] = {}
        for key, value in params.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Application parameter names must be non-empty strings")
            sanitized[key] = value if isinstance(value, str) else str(value)
        return sanitized

    @staticmethod
    def _validate_ports(ports: Optional[Dict[str, int]]) -> Dict[str, int]:
        if not ports:
            return {}
        validated: Dict[str, int] = {}
        structured = []
        for key, host_port in ports.items():
            if not isinstance(key, str):
                raise ValueError("Port mappings must use string keys like '8000/tcp'")
            match = _PORT_KEY_PATTERN.match(key.strip())
            if not match:
                raise ValueError(f"Invalid port mapping key {key!r}; expected '<port>/<tcp|udp>'")
            container_port = int(match.group("container"))
            proto = match.group("proto").lower()
            if container_port < 1 or container_port > 65535:
                raise ValueError(f"Container port {container_port} out of range (1-65535)")
            try:
                host_port_int = 0 if host_port in (None, "") else int(host_port)
            except Exception as exc:  # pragma: no cover - ValueError path
                raise ValueError(f"Host port for {key!r} must be an integer") from exc
            if host_port_int < 0 or host_port_int > 65535:
                raise ValueError(f"Host port {host_port_int} out of range (0-65535)")
            privileged = host_port_int not in (0,) and host_port_int < 1024
            if privileged and not _IS_ROOT:
                raise PermissionError(
                    f"Host port {host_port_int} is privileged (<1024) and cannot be requested when not running as root"
                )
            normalized_key = f"{container_port}/{proto}"
            validated[normalized_key] = host_port_int
            structured.append(
                {
                    "container_port": container_port,
                    "host_port": host_port_int,
                    "protocol": proto,
                    "privileged_host_port": privileged,
                }
            )
        if structured:
            logger.info("workspace.ports.validated", extra={"ports": structured})
        return validated

    def _resolve_transfer_limit(self, override: Optional[int]) -> int:
        limit = int(override if override is not None else self.max_file_transfer_bytes)
        if limit <= 0:
            raise ValueError("max_bytes must be a positive integer")
        return limit

    @staticmethod
    def _normalize_token(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        token = value.strip()
        if token.startswith("Bearer "):
            token = token[len("Bearer ") :]
        return token or None

    @staticmethod
    def _wrap_with_env_prefix(command: str) -> str:
        """
        Ensure SPLUNK_HOME/bin and common tool bins are on PATH for all commands
        (splunk, slim, appinspect, etc.)
        """
        return f"{COMMAND_ENV_PREFIX}{command}"

    # -----------------------
    # Public API
    # -----------------------

    def health(self, timeout: int = 5) -> Dict[str, object]:
        r = self._session.get(f"{self.base_url}/health", timeout=timeout)
        r.raise_for_status()
        return r.json() or {}

    def create_workspace(
        self,
        application_params: Optional[Dict[str, Any]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        ports: Optional[Dict[str, int]] = None,
        labels: Optional[Dict[str, str]] = None,
        image: Optional[str] = None,
        application_kind: Optional[str] = None,
        wait_ready: bool = True,
        timeout: int = 1200,
        *,
        require_application_params: bool = False,
    ) -> Dict[str, object]:
        """
        Create a new workspace and optionally wait for readiness.

        Returns the server response JSON (expected to include workspace_id).
        """
        sanitized_params = self._sanitize_application_params(application_params)
        if require_application_params and not sanitized_params:
            raise ValueError("application_params are required but were not provided")
        sanitized_env = self._sanitize_env_vars(env_vars)
        validated_ports = self._validate_ports(ports)
        payload = {
            "application_params": sanitized_params,
            "env_vars": sanitized_env,
            "ports": validated_ports,
            "labels": labels or {},
        }
        if image:
            payload["image"] = image
        if application_kind:
            payload["application_kind"] = application_kind.strip().lower()
        r = self._session.post(
            f"{self.base_url}/workspaces",
            params={"wait_ready": "true" if wait_ready else "false"},
            json=payload,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json() or {}

    def delete_workspace(self, workspace_id: str, timeout: int = 30) -> bool:
        """
        Delete a workspace. Returns True if the request was sent successfully.
        """
        r = self._session.delete(
            f"{self.base_url}/workspaces/{workspace_id}",
            headers=self._headers(),
            timeout=timeout,
        )
        if r.status_code == 404:
            return False
        r.raise_for_status()
        return True

    def list_workspaces(self, owner: Optional[str] = None, timeout: int = 60) -> Dict[str, object]:
        """
        List managed workspaces. Optionally filter by owner label.
        """
        params: Dict[str, str] = {}
        if owner:
            params["owner"] = owner
        r = self._session.get(
            f"{self.base_url}/workspaces",
            params=params or None,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json() or {}

    def get_workspace(self, workspace_id: str, timeout: int = 30) -> Dict[str, object]:
        """
        Get detailed information for a specific workspace.
        """
        r = self._session.get(
            f"{self.base_url}/workspaces/{workspace_id}",
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json() or {}

    def exec(
        self,
        workspace_id: str,
        command: str,
        user: str = "splunk",
        cwd: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
        timeout: int = 300,
    ) -> Tuple[int, str, str]:
        """
        Execute a command inside the workspace container.

        Returns (exit_code, stdout, stderr)
        """
        wrapped = self._wrap_with_env_prefix(command)
        payload = {
            "command": wrapped,
            "user": user,
            "timeout": int(timeout),
        }
        if cwd:
            payload["cwd"] = cwd
        if env_vars:
            payload["env_vars"] = env_vars

        r = self._session.post(
            f"{self.base_url}/workspaces/{workspace_id}/exec",
            json=payload,
            headers=self._headers(),
            timeout=timeout + 30,
        )
        # The server returns 200 with a JSON body (exit_code, stdout, stderr)
        # If a different status is returned, surface it as a failure with defaults.
        if not (200 <= r.status_code < 300):
            return 1, "", f"exec failed: {r.status_code} {r.text}"

        data = r.json() or {}
        exit_code = int(data.get("exit_code", 1))
        stdout = data.get("stdout", "") or ""
        stderr = data.get("stderr", "") or ""
        return exit_code, stdout, stderr

    def mkdir(
        self,
        workspace_id: str,
        path: str,
        parents: bool = True,
        mode: Optional[str] = None,
        timeout: int = 60,
    ) -> bool:
        """
        Create a directory in the workspace container.
        """
        payload = {"path": path, "parents": bool(parents), "mode": mode}
        r = self._session.post(
            f"{self.base_url}/workspaces/{workspace_id}/files/mkdir",
            json=payload,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return True

    def write_file(
        self,
        workspace_id: str,
        path: str,
        content: str,
        timeout: int = 60,
    ) -> bool:
        """
        Write a file in the workspace container.
        """
        payload = {"path": path, "content": content}
        r = self._session.post(
            f"{self.base_url}/workspaces/{workspace_id}/files/write",
            json=payload,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return True

    def read_file(
        self,
        workspace_id: str,
        path: str,
        timeout: int = 60,
    ) -> str:
        """
        Read a text file from the workspace container and return its content.
        """
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("path must be an absolute container path")

        params = {"path": path}
        r = self._session.get(
            f"{self.base_url}/workspaces/{workspace_id}/files/read",
            params=params,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json() or {}
        content = data.get("content", "")
        return str(content) if content is not None else ""

    def get_direct_upload_credentials(
        self,
        workspace_id: str,
        destination_path: str,
        ttl_seconds: Optional[int] = None,
        timeout: int = 30,
    ) -> Dict[str, object]:
        """
        Request short-lived direct-upload credentials from the server.

        Returns a dict with:
          - upload_url: str
          - header: str (header name to use, e.g., 'Authorization')
          - query_param: str (alternative query param name if not using header)
          - token: str (value to supply for the header or query param, e.g., 'Bearer <token>')
          - expires_in: int (seconds until expiration)
          - workspace_id: str
          - destination_path: str
        """
        params: Dict[str, str] = {"destination_path": str(destination_path)}
        if ttl_seconds is not None:
            params["ttl_seconds"] = str(int(ttl_seconds))
        r = self._session.post(
            f"{self.base_url}/workspaces/{workspace_id}/generate-upload-token",
            params=params,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json() or {}

    def upload_file(
        self,
        workspace_id: str,
        destination_path: str,
        local_path: str,
        timeout: int = 1200,
        auth_header_name: Optional[str] = None,
        auth_header_value: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_query_param: Optional[str] = None,
        upload_url: Optional[str] = None,
        max_bytes: Optional[int] = None,
    ) -> bool:
        """
        Upload a local file directly to the workspace container.

        If provided, includes short-lived auth via header-based bearer token.
        Query parameters are disallowed to avoid credential leakage in logs.

        Use get_direct_upload_credentials(...) to obtain these values.
        """
        params: Dict[str, str] = {"destination_path": str(destination_path)}
        headers = dict(self._headers())
        if auth_headers:
            headers.update(auth_headers)
        if auth_query_param:
            raise ValueError("auth_query_param is not supported; pass credentials via headers.")

        limit = self._resolve_transfer_limit(max_bytes)
        file_size = os.path.getsize(local_path)
        if file_size > limit:
            raise ValueError(
                f"File size {file_size} exceeds the configured limit of {limit} bytes for upload_file"
            )

        norm_token = self._normalize_token(auth_header_value)

        if norm_token and not auth_header_name:
            raise ValueError("auth_header_name is required when providing auth_header_value for uploads")

        if auth_header_name and norm_token:
            headers[auth_header_name] = f"Bearer {norm_token}"

        with open(local_path, "rb") as f:
            files = {"file": (os.path.basename(local_path) or "upload.bin", f, "application/octet-stream")}
            target_url = upload_url or f"{self.base_url}/workspaces/{workspace_id}/files/copy-to"
            r = self._session.post(
                target_url,
                params=params,
                headers=headers,
                files=files,
                timeout=timeout,
            )
        r.raise_for_status()
        return True

    def upload_bytes(
        self,
        workspace_id: str,
        destination_path: str,
        data,
        filename: Optional[str] = None,
        content_type: str = "application/octet-stream",
        timeout: int = 1200,
        auth_header_name: Optional[str] = None,
        auth_header_value: Optional[str] = None,
        auth_query_param: Optional[str] = None,
        max_bytes: Optional[int] = None,
    ) -> bool:
        """
        Upload in-memory bytes or a file-like stream directly to the workspace container.

        Accepts either:
          - 'data' as bytes or bytearray (wrapped internally)
          - 'data' as a binary file-like object (must support .read())

        Use get_direct_upload_credentials(...) to obtain short-lived auth hints when needed.
        """
        params: Dict[str, str] = {"destination_path": str(destination_path)}
        headers = dict(self._headers())
        if auth_query_param:
            raise ValueError("auth_query_param is not supported; pass credentials via headers.")

        limit = self._resolve_transfer_limit(max_bytes)
        norm_token = self._normalize_token(auth_header_value)

        if norm_token and not auth_header_name:
            raise ValueError("auth_header_name is required when providing auth_header_value for uploads")

        if auth_header_name and norm_token:
            headers[auth_header_name] = f"Bearer {norm_token}"

        file_name = filename or (os.path.basename(destination_path) or "upload.bin")

        # Prepare file tuple for requests
        if isinstance(data, (bytes, bytearray)):
            if len(data) > limit:
                raise ValueError(
                    f"Byte payload size {len(data)} exceeds the configured limit of {limit} bytes for upload_bytes"
                )
            file_obj = io.BytesIO(data)
        else:
            file_obj = _LimitedStream(data, limit)

        files = {"file": (file_name, file_obj, content_type)}
        r = self._session.post(
            f"{self.base_url}/workspaces/{workspace_id}/files/copy-to",
            params=params,
            headers=headers,
            files=files,
            timeout=timeout,
        )
        r.raise_for_status()
        return True

    def get_direct_download_credentials(
        self,
        workspace_id: str,
        source_path: str,
        ttl_seconds: Optional[int] = None,
        timeout: int = 30,
    ) -> Dict[str, object]:
        """
        Request short-lived direct-download credentials from the server.

        Returns a dict with:
          - download_url: str
          - header: str (header name to use, e.g., 'Authorization')
          - query_param: str (alternative query param name if not using header)
          - token: str (value to supply for the header or query param, e.g., 'Bearer <token>')
          - expires_in: int (seconds until expiration)
          - workspace_id: str
          - source_path: str
        """
        params: Dict[str, str] = {"source_path": str(source_path)}
        if ttl_seconds is not None:
            params["ttl_seconds"] = str(int(ttl_seconds))
        r = self._session.post(
            f"{self.base_url}/workspaces/{workspace_id}/generate-download-token",
            params=params,
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json() or {}

    def download_file(
        self,
        workspace_id: str,
        source_path: str,
        local_path: str,
        timeout: int = 1200,
        auth_header_name: Optional[str] = None,
        auth_header_value: Optional[str] = None,
        auth_query_param: Optional[str] = None,
        max_bytes: Optional[int] = None,
    ) -> bool:
        """
        Download a file directly from the workspace container using an optional
        short-lived authorization token (header only; tokens in URLs are rejected).

        Use get_direct_download_credentials(...) to obtain these values.
        """
        params: Dict[str, str] = {"source_path": str(source_path)}
        headers = dict(self._headers())
        if auth_query_param:
            raise ValueError("auth_query_param is not supported; pass credentials via headers.")

        limit = self._resolve_transfer_limit(max_bytes)

        norm_token = self._normalize_token(auth_header_value)
        if norm_token and not auth_header_name:
            raise ValueError("auth_header_name is required when providing auth_header_value for downloads")
        if auth_header_name and norm_token:
            headers[auth_header_name] = f"Bearer {norm_token}"

        tmp_bytes = 0
        try:
            with self._session.get(
                f"{self.base_url}/workspaces/{workspace_id}/files/copy-from",
                params=params,
                headers=headers,
                stream=True,
                timeout=timeout,
            ) as resp:
                resp.raise_for_status()
                with open(local_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=128 * 1024):
                        if not chunk:
                            continue
                        tmp_bytes += len(chunk)
                        if tmp_bytes > limit:
                            raise ValueError(
                                f"Download exceeded the configured limit of {limit} bytes "
                                f"(received {tmp_bytes} bytes so far)"
                            )
                        f.write(chunk)
        except Exception:
            # Remove partial file on failure to avoid consuming disk with incomplete downloads.
            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
            except Exception:
                pass
            raise
        return True

    def get_app_status(self, workspace_id: str, timeout: int = 30) -> Dict[str, object]:
        """
        Fetch application status for a workspace, including mapped web/mgmt ports and readiness flags.
        """
        r = self._session.get(
            f"{self.base_url}/workspaces/{workspace_id}/app/status",
            headers=self._headers(),
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json() or {}


from .applications.splunk_workspace import SplunkWorkspace

# Backward compatibility export
SplunkHelpers = SplunkWorkspace


__all__ = ["WorkspaceManagerClient", "SplunkWorkspace", "SplunkHelpers"]
