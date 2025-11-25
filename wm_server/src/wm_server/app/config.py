"""
Unified server configuration for WorkspaceManager (wm_server).

This module centralizes:
- Defaults for all server settings
- Loading from environment variables
- Optional .env file hydration (best-effort, only for allowed keys)
- Convenient helpers for resource parsing and derived values

Usage:
    from wm_server.app.config import get_settings

    settings = get_settings()
    print(settings.default_image)
    # ...use settings...

Notes:
- Environment variables always take precedence.
- A minimal, best-effort .env loader will populate process env for allowed keys
  if they are not already present. This keeps side effects contained and
  predictable during tests and local runs.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional


# ----------------------------
# Helpers: env, parsing, types
# ----------------------------

_ALLOWED_DOTENV_KEYS = {
    # Auth
    "WORKSPACE_API_KEY",
    "WORKSPACE_API_KEY_HEADER",
    "WORKSPACE_API_KEYS",
    # Workspace defaults
    "WORKSPACE_DEFAULT_IMAGE",
    "WORKSPACE_DEFAULT_CPU",
    "WORKSPACE_DEFAULT_MEM",
    "WORKSPACE_NETWORK_MODE",
    "CONTAINER_WORKSPACE_DIR",
    # Docker settings
    "DOCKER_CLIENT_TIMEOUT",
    "DOCKER_PLATFORM",
    # Server behavior
    "WORKSPACE_IDLE_TTL_SECONDS",
    "WORKSPACE_CONTAINER_PREFIX",
    "WORKSPACE_JANITOR_INTERVAL_SECONDS",
    "WORKSPACE_MANAGER_VERSION",
    "WORKSPACE_STOP_TIMEOUT_SECONDS",
    "WORKSPACE_ENABLE_CHECKPOINTS",
    "WORKSPACE_TOOLS_VOLUME",
    "LOG_LEVEL",
    # CORS
    "CORS_ALLOW_ORIGINS",
    # Direct upload/download handoff tokens
    "WORKSPACE_UPLOAD_TOKEN_SECRET",
    "WORKSPACE_UPLOAD_TOKEN_HEADER",
    "WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM",
    "WORKSPACE_UPLOAD_TOKEN_TTL_SECONDS",
    # Plugin system
    "WM_PLUGINS_ENABLED",
    "WM_PLUGINS_ENTRYPOINT_GROUPS",
    "WM_PLUGINS_MODULES",
        "WM_PLUGINS_ALLOWLIST",
    "WM_PLUGINS_DENYLIST",
    "WM_PLUGINS_FAIL_FAST",
}

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)([kKmMgG]?[bB]?)?\s*$")
_CPU_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(c|cpu|cpus)?\s*$")


def _str2bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    s = val.strip().lower()
    return s in ("1", "true", "yes", "y", "on")


def _split_csv(s: str | None) -> List[str]:
    if not s:
        return []
    return [part.strip() for part in s.split(",") if part.strip()]


def _parse_mem_limit_to_bytes(mem_limit: Optional[str]) -> Optional[int]:
    """
    Parse human-readable memory limit into bytes for Docker (e.g., '512m', '2g', '1024').
    Returns None if not provided or invalid.
    """
    if not mem_limit:
        return None
    s = mem_limit.strip()
    m = _SIZE_RE.match(s)
    if not m:
        return None
    val = float(m.group(1))
    unit = (m.group(2) or "").lower()

    if unit in ("", "b"):
        mult = 1
    elif unit in ("k", "kb"):
        mult = 1024
    elif unit in ("m", "mb"):
        mult = 1024**2
    elif unit in ("g", "gb"):
        mult = 1024**3
    else:
        return None
    return int(val * mult)


def _parse_cpu_limit_to_nano_cpus(cpu_limit: Optional[str]) -> Optional[int]:
    """
    Parse CPU limit into nano_cpus for Docker (1.0 CPU == 1e9 nano_cpus).
    Accepts forms like '1', '1.5', '2c', '0.5cpu'.
    Returns None if not provided or invalid.
    """
    if not cpu_limit:
        return None
    s = cpu_limit.strip()
    m = _CPU_RE.match(s)
    if not m:
        return None
    val = float(m.group(1))
    return int(val * 1_000_000_000)


def _build_run_resource_kwargs(cpu_limit: Optional[str], mem_limit: Optional[str]) -> Dict[str, object]:
    """
    Convert human-friendly cpu/mem strings into Docker run/create kwargs.
    - cpu_limit -> nano_cpus
    - mem_limit -> mem_limit (bytes)
    """
    kwargs: Dict[str, object] = {}
    nano = _parse_cpu_limit_to_nano_cpus(cpu_limit)
    if nano is not None and nano > 0:
        kwargs["nano_cpus"] = nano
    mem_bytes = _parse_mem_limit_to_bytes(mem_limit)
    if mem_bytes is not None and mem_bytes > 0:
        kwargs["mem_limit"] = mem_bytes
    return kwargs


def _load_dotenv_into_env(dotenv_path: Optional[Path] = None, allowed_keys: Optional[set[str]] = None) -> None:
    """
    Best-effort .env loader:
    - Loads from wm_server/.env by default (relative to this file)
    - Only sets variables from allowed_keys if not already present in os.environ
    - Strips surrounding quotes on values
    - Ignores malformed lines
    """
    try:
        if dotenv_path:
            path = Path(dotenv_path)
        else:
            path = None
            here = Path(__file__).resolve()
            for ancestor in list(here.parents)[:5]:
                candidate = ancestor / ".env"
                if candidate.is_file():
                    path = candidate
                    break
            if path is None:
                return
        if not path.is_file():
            return
        allow = set(allowed_keys or _ALLOWED_DOTENV_KEYS)
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            if key and key in allow and key not in os.environ:
                os.environ[key] = val
    except Exception:
        # Best-effort; never fail startup due to .env parsing
        pass


# ----------------------------
# Unified configuration object
# ----------------------------

@dataclass(frozen=True)
class ServerConfig:
    """
    Unified configuration for WorkspaceManager.

    All fields are immutable once created. Use from_env() to construct an instance.
    """

    # Security / auth
    api_key: Optional[str]
    api_key_header_name: str
    api_keys: List[str]

    # Defaults for workspace/container creation
    default_image: str
    default_cpu_limit: str
    default_mem_limit: str
    network_mode: str
    container_workspace_dir: str

    # Docker client
    docker_client_timeout: int

    # Idle cleanup
    workspace_idle_ttl_seconds: int

    # Container naming
    container_name_prefix: str

    # Stop/kill behavior
    workspace_stop_timeout_seconds: int

    # Feature flags
    enable_checkpoints: bool

    # CORS and service metadata
    cors_allow_origins: List[str]
    service_version: str
    log_level: str

    # Janitor
    janitor_interval_seconds: int

    # Shared tools volume
    tools_volume_name: str

    # Optional platform override for docker (e.g., linux/amd64)
    docker_platform: Optional[str]

    # Direct upload/download tokens for handoff
    upload_token_secret: Optional[str]
    upload_token_header_name: str
    upload_token_query_param: str
    upload_token_ttl_seconds: int

    # Plugin system
    plugins_enabled: bool
    plugin_entrypoint_groups: List[str]
    plugin_modules: List[str]
    plugin_allowlist: List[str]
    plugin_denylist: List[str]
    plugin_fail_fast: bool

    @staticmethod
    def from_env(dotenv: bool = True, dotenv_path: Optional[str | Path] = None) -> "ServerConfig":
        """
        Construct ServerConfig with values pulled from the current environment,
        optionally hydrated by a .env file if dotenv=True.
        """
        if dotenv:
            _load_dotenv_into_env(Path(dotenv_path) if dotenv_path else None, _ALLOWED_DOTENV_KEYS)

        # Security
        api_key = os.getenv("WORKSPACE_API_KEY") or None
        api_key_header = os.getenv("WORKSPACE_API_KEY_HEADER", "X-API-Key")
        api_keys_csv = os.getenv("WORKSPACE_API_KEYS")
        api_keys = _split_csv(api_keys_csv)
        if api_key and api_key not in api_keys:
            api_keys.insert(0, api_key)

        # Workspace defaults
        default_image = os.getenv("WORKSPACE_DEFAULT_IMAGE", "ubuntu:22.04")
        default_cpu = os.getenv("WORKSPACE_DEFAULT_CPU", "1c")
        default_mem = os.getenv("WORKSPACE_DEFAULT_MEM", "2g")
        cws_dir = os.getenv("CONTAINER_WORKSPACE_DIR", "/tmp/workspace")

        # Docker client
        docker_timeout = int(os.getenv("DOCKER_CLIENT_TIMEOUT", "180"))

        # Cleanup / lifecycle
        idle_ttl = int(os.getenv("WORKSPACE_IDLE_TTL_SECONDS", "7200"))
        container_prefix = os.getenv("WORKSPACE_CONTAINER_PREFIX", "wm_ws_")
        enable_checkpoints = _str2bool(os.getenv("WORKSPACE_ENABLE_CHECKPOINTS", "true"), default=True)
        try:
            stop_timeout = int(os.getenv("WORKSPACE_STOP_TIMEOUT_SECONDS", "5"))
        except ValueError:
            stop_timeout = 5
        stop_timeout = max(0, stop_timeout)

        # CORS and metadata
        cors_allow = _split_csv(os.getenv("CORS_ALLOW_ORIGINS", "*"))
        version = os.getenv("WORKSPACE_MANAGER_VERSION", "0.1.0")
        log_level = os.getenv("LOG_LEVEL", "INFO")

        # Janitor and tools
        janitor_interval = int(os.getenv("WORKSPACE_JANITOR_INTERVAL_SECONDS", "3600"))
        tools_volume = os.getenv("WORKSPACE_TOOLS_VOLUME", "wm_tools_cache")

        # Optional docker platform override
        docker_platform = os.getenv("DOCKER_PLATFORM") or None

        # Direct upload/download token settings
        # Default to a safe development secret when not provided via env to keep token endpoints functional in local tests.
        token_secret = os.getenv("WORKSPACE_UPLOAD_TOKEN_SECRET") or "dev-upload-token-secret"
        token_header = os.getenv("WORKSPACE_UPLOAD_TOKEN_HEADER", "Authorization")
        token_query = os.getenv("WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM", "token")
        token_ttl = int(os.getenv("WORKSPACE_UPLOAD_TOKEN_TTL_SECONDS", "900"))

        # Plugin system
        plugins_enabled = _str2bool(os.getenv("WM_PLUGINS_ENABLED"), default=True)
        ep_groups = _split_csv(os.getenv("WM_PLUGINS_ENTRYPOINT_GROUPS")) or ["wm_server.app_plugins"]
        modules = _split_csv(os.getenv("WM_PLUGINS_MODULES"))
        allowlist = _split_csv(os.getenv("WM_PLUGINS_ALLOWLIST"))
        denylist = _split_csv(os.getenv("WM_PLUGINS_DENYLIST"))
        plugins_fail_fast = _str2bool(os.getenv("WM_PLUGINS_FAIL_FAST"), default=False)

        return ServerConfig(
            api_key=api_key,
            api_key_header_name=api_key_header,
            api_keys=api_keys,
            default_image=default_image,
            default_cpu_limit=default_cpu,
            default_mem_limit=default_mem,
            network_mode=os.getenv("WORKSPACE_NETWORK_MODE", "none"),
            container_workspace_dir=cws_dir,
            docker_client_timeout=docker_timeout,
            workspace_idle_ttl_seconds=idle_ttl,
            container_name_prefix=container_prefix,
            workspace_stop_timeout_seconds=stop_timeout,
            enable_checkpoints=enable_checkpoints,
            cors_allow_origins=cors_allow or ["*"],
            service_version=version,
            log_level=log_level,
            janitor_interval_seconds=janitor_interval,
            tools_volume_name=tools_volume,
            docker_platform=docker_platform,
            upload_token_secret=token_secret,
            upload_token_header_name=token_header,
            upload_token_query_param=token_query,
            upload_token_ttl_seconds=token_ttl,
            plugins_enabled=plugins_enabled,
            plugin_entrypoint_groups=ep_groups,
            plugin_modules=modules,
            plugin_allowlist=allowlist,
            plugin_denylist=denylist,
            plugin_fail_fast=plugins_fail_fast,
        )

    # ----------------------------
    # Derived helpers / utilities
    # ----------------------------

    def build_run_resource_kwargs(self) -> Dict[str, object]:
        """
        Convert configured cpu/mem strings into Docker run/create kwargs.
        """
        return _build_run_resource_kwargs(self.default_cpu_limit, self.default_mem_limit)

    def workspace_container_name(self, workspace_id: str) -> str:
        """
        Produce a deterministic container name for a given workspace_id.
        """
        return f"{self.container_name_prefix}{workspace_id}"

    def token_secret_effective(self) -> Optional[str]:
        """
        Effective token secret for direct upload/download handoff.
        Falls back to environment variable if not set in this config instance.
        """
        return self.upload_token_secret or os.getenv("WORKSPACE_UPLOAD_TOKEN_SECRET")


# ----------------------------
# Cached accessor
# ----------------------------

@lru_cache(maxsize=1)
def get_settings() -> ServerConfig:
    """
    Cached settings accessor. Safe to import and call across the app.
    """
    return ServerConfig.from_env(dotenv=True)


__all__ = [
    "ServerConfig",
    "get_settings",
]
