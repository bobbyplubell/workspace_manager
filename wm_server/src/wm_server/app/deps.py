from __future__ import annotations

"""
Shared FastAPI dependencies and utilities for WorkspaceManager.

Contents:
- ServiceConfig: central configuration loaded from environment.
- get_settings(): cached accessor for ServiceConfig.
- enforce_api_key(): API key authentication dependency for routes.
- docker_client(): Docker client factory dependency.
- Resource limit helpers for Docker run/create options.

Project policy notes:
- No lazy imports.
- No try/except guards around imports; failures should be explicit.
"""

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader

import docker
from docker import DockerClient


# -------------
# Configuration
# -------------

from wm_server.app.config import ServerConfig as ServiceConfig, get_settings as _config_get_settings


def get_settings() -> ServiceConfig:
    """
    Cached settings accessor. Delegates to unified ServerConfig provider.
    """
    return _config_get_settings()


# -------------------
# API Key Auth (FastAPI)
# -------------------

api_key_header = APIKeyHeader(name=get_settings().api_key_header_name, auto_error=False)


async def enforce_api_key(
    provided_key: Optional[str] = Security(api_key_header)
) -> None:
    """
    Enforce API key authentication using the configured header.

    Behavior:
    - If WORKSPACE_API_KEY or WORKSPACE_API_KEYS are set, requests must provide an exact match of one of the configured keys.
    - If neither is set, authentication is disabled (accept all).
    """
    settings = get_settings()
    # Build allowed keys set: include primary api_key and any from api_keys
    allowed: set[str] = set()
    if settings.api_key:
        allowed.add(settings.api_key)
    for k in getattr(settings, "api_keys", []) or []:
        if isinstance(k, str) and k:
            allowed.add(k)
    # Auth disabled if no keys configured
    if not allowed:
        return
    if not provided_key or provided_key not in allowed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


# --------------------------
# Docker client dependency
# --------------------------

def docker_client(settings: ServiceConfig = Depends(get_settings)) -> DockerClient:
    """
    Provide a DockerClient configured via environment.

    Note:
    - Caller is responsible for closing the client if they keep it beyond a request scope.
    """
    return docker.from_env(timeout=settings.docker_client_timeout)


# --------------------------
# Resource limit utilities
# --------------------------

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)([kKmMgG]?[bB]?)?\s*$")
_CPU_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(c|cpu|cpus)?\s*$")


def parse_mem_limit_to_bytes(mem_limit: Optional[str]) -> Optional[int]:
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
        # Unrecognized unit
        return None
    return int(val * mult)


def parse_cpu_limit_to_nano_cpus(cpu_limit: Optional[str]) -> Optional[int]:
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


def build_run_resource_kwargs(cpu_limit: Optional[str], mem_limit: Optional[str]) -> Dict[str, object]:
    """
    Convert human-friendly cpu/mem strings into Docker run/create kwargs.
    - cpu_limit -> nano_cpus
    - mem_limit -> mem_limit (bytes)
    """
    kwargs: Dict[str, object] = {}
    nano = parse_cpu_limit_to_nano_cpus(cpu_limit)
    if nano is not None and nano > 0:
        kwargs["nano_cpus"] = nano
    mem_bytes = parse_mem_limit_to_bytes(mem_limit)
    if mem_bytes is not None and mem_bytes > 0:
        kwargs["mem_limit"] = mem_bytes
    return kwargs


# --------------------------
# Container naming helpers
# --------------------------

def workspace_container_name(workspace_id: str, settings: Optional[ServiceConfig] = None) -> str:
    """
    Produce a deterministic container name for a given workspace_id.
    """
    cfg = settings or get_settings()
    return cfg.workspace_container_name(workspace_id)


__all__ = [
    "ServiceConfig",
    "get_settings",
    "enforce_api_key",
    "docker_client",
    "parse_mem_limit_to_bytes",
    "parse_cpu_limit_to_nano_cpus",
    "build_run_resource_kwargs",
    "workspace_container_name",
]