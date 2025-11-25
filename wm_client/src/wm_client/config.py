"""
SDK configuration for WorkspaceManager (wm_client).

This module centralizes:
- Defaults for the client (timeouts, auth header name)
- Loading values from environment variables
- Convenience helpers (normalized base_url, auth headers, etc.)

Typical usage:
    from wm_client.config import get_settings
    from wm_client import WorkspaceManagerClient

    cfg = get_settings()
    client = WorkspaceManagerClient(
        base_url=cfg.base_url_normalized,
        api_key=cfg.api_key,
        api_key_header_name=cfg.api_key_header_name,
    )

- Environment variables (client-side):
  - WORKSPACE_API_URL or WM_BASE_URL: Base URL of the WorkspaceManager server (defaults to https://127.0.0.1:8081)
  - WORKSPACE_API_KEY: API key if the server requires one
  - WORKSPACE_API_KEY_HEADER: Header name for API key (default: X-API-Key)
  - WM_REQUEST_TIMEOUT: Default HTTP timeout in seconds for short calls (default: 60)
  - WM_EXEC_TIMEOUT: Default exec timeout seconds (default: 300)
  - WM_CREATE_TIMEOUT: Default create_workspace timeout seconds (default: 1200)
  - WM_FILE_TIMEOUT: Default file operations timeout seconds (default: 120)
  - WM_VERIFY_TLS: "true"/"false" for TLS verification on https URLs (default: "true"; disabling requires WM_ALLOW_INSECURE_TLS=true)
  - WM_ALLOW_INSECURE_HTTP: Explicit opt-in to allow http:// base URLs (default: false)
  - WM_ALLOW_INSECURE_TLS: Explicit opt-in to disable TLS verification (default: false)
  - WM_MAX_FILE_TRANSFER_BYTES: Absolute cap for file uploads/downloads initiated by the client (default: 1 GiB)
  - SPLUNK_USERNAME: Default Splunk admin username exposed to helpers (optional)
  - SPLUNK_PASSWORD: Default Splunk admin password to use for Splunk helpers (required; if unset helpers must be configured explicitly)
  - CONTAINER_WORKSPACE_DIR: Container workspace dir (default: /tmp/workspace); informational for SDK consumers

Notes:
- This module does not modify process environment variables.
- Values are read once and cached; call get_settings.cache_clear() if you need to reload during a process lifetime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Optional
from urllib.parse import urlparse

from .constants import (
    DEFAULT_API_KEY_HEADER,
    DEFAULT_SPLUNK_PASSWORD,
    ENV_SPLUNK_PASSWORD,
)


def _str2bool(val: Optional[str], default: bool) -> bool:
    if val is None:
        return default
    s = val.strip().lower()
    return s in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class ClientConfig:
    """
    Immutable configuration for the WorkspaceManager Python SDK.
    Construct via ClientConfig.from_env() or use get_settings().
    """

    # Server connection
    base_url: str
    verify_tls: bool
    allow_insecure_http: bool
    allow_insecure_tls: bool

    # Auth
    api_key: Optional[str]
    api_key_header_name: str

    # Defaults for request timeouts (seconds)
    request_timeout: int
    exec_timeout: int
    create_workspace_timeout: int
    file_timeout: int

    # Optional public base URL to hand out to third parties (not required).
    # If set, UI/services that need to present a URL to end-users can prefer this
    # instead of `base_url`. The SDK itself does not enforce or rewrite to this value.
    public_base_url: Optional[str]

    # Convenience: defaults used by helpers/consumers
    splunk_password: Optional[str]
    container_workspace_dir: str
    max_file_transfer_bytes: int

    @property
    def base_url_normalized(self) -> str:
        """
        Base URL with any trailing slash removed to avoid double slashes in requests.
        """
        return (self.base_url or "").rstrip("/")

    @property
    def public_base_url_normalized(self) -> Optional[str]:
        """
        Public base URL with trailing slash removed if present.
        """
        if not self.public_base_url:
            return None
        return str(self.public_base_url).rstrip("/")

    def auth_headers(self) -> Dict[str, str]:
        """
        Construct headers containing the API key if configured.
        """
        if not self.api_key:
            return {}
        return {self.api_key_header_name: self.api_key}

    @staticmethod
    def from_env() -> "ClientConfig":
        """
        Build ClientConfig from environment variables with sensible defaults.
        """
        # Base URL: prefer WORKSPACE_API_URL (used throughout tests); fallback to WM_BASE_URL.
        base_url = os.getenv("WORKSPACE_API_URL") or os.getenv("WM_BASE_URL") or "https://127.0.0.1:8081"
        parsed = urlparse(base_url)
        if not parsed.scheme:
            raise ValueError(f"Invalid WORKSPACE_API_URL/WM_BASE_URL (missing scheme): {base_url!r}")
        scheme = parsed.scheme.lower()

        allow_insecure_http = _str2bool(os.getenv("WM_ALLOW_INSECURE_HTTP"), default=False)
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported base_url scheme {scheme!r}; only http/https are supported")
        if scheme == "http" and not allow_insecure_http:
            raise ValueError(
                "Insecure HTTP base_url detected. "
                "Set WM_ALLOW_INSECURE_HTTP=true only when running in a trusted development environment."
            )

        verify_env = os.getenv("WM_VERIFY_TLS")
        allow_insecure_tls = _str2bool(os.getenv("WM_ALLOW_INSECURE_TLS"), default=False)
        if verify_env is None:
            verify_tls = True
        else:
            verify_tls = _str2bool(verify_env, default=True)
            if verify_tls is False and not allow_insecure_tls:
                raise ValueError(
                    "TLS verification cannot be disabled unless WM_ALLOW_INSECURE_TLS=true "
                    "in a trusted development environment."
                )

        # Auth
        api_key = os.getenv("WORKSPACE_API_KEY") or None
        api_key_header = os.getenv("WORKSPACE_API_KEY_HEADER", DEFAULT_API_KEY_HEADER)

        # Timeouts
        def _int_env(name: str, default_s: int) -> int:
            try:
                return int(os.getenv(name, str(default_s)))
            except Exception:
                return default_s

        request_timeout = _int_env("WM_REQUEST_TIMEOUT", 60)
        exec_timeout = _int_env("WM_EXEC_TIMEOUT", 300)
        create_timeout = _int_env("WM_CREATE_TIMEOUT", 1200)
        file_timeout = _int_env("WM_FILE_TIMEOUT", 120)

        # Optional public base url for handoff scenarios behind proxies
        public_base_url = os.getenv("WORKSPACE_PUBLIC_BASE_URL") or None

        # Convenience defaults
        splunk_password = os.getenv(ENV_SPLUNK_PASSWORD, DEFAULT_SPLUNK_PASSWORD)
        container_workspace_dir = os.getenv("CONTAINER_WORKSPACE_DIR", "/tmp/workspace")
        max_file_transfer_bytes = _int_env("WM_MAX_FILE_TRANSFER_BYTES", 1 * 1024 * 1024 * 1024)
        if max_file_transfer_bytes <= 0:
            raise ValueError("WM_MAX_FILE_TRANSFER_BYTES must be a positive integer number of bytes")

        return ClientConfig(
            base_url=base_url,
            verify_tls=verify_tls,
            allow_insecure_http=allow_insecure_http,
            allow_insecure_tls=allow_insecure_tls,
            api_key=api_key,
            api_key_header_name=api_key_header,
            request_timeout=request_timeout,
            exec_timeout=exec_timeout,
            create_workspace_timeout=create_timeout,
            file_timeout=file_timeout,
            public_base_url=public_base_url,
            splunk_password=splunk_password,
            container_workspace_dir=container_workspace_dir,
            max_file_transfer_bytes=max_file_transfer_bytes,
        )


@lru_cache(maxsize=1)
def get_settings() -> ClientConfig:
    """
    Cached accessor for the SDK configuration.
    Call get_settings.cache_clear() to reload after environment changes.
    """
    return ClientConfig.from_env()


__all__ = ["ClientConfig", "get_settings"]
