from __future__ import annotations

"""
Core helpers for workspace utilities: time, ids, labels, and last-used tracking.

This module centralizes small, side-effect-free helpers and a minimal amount
of in-memory state used by the WorkspaceManager. It is intentionally import-only
(no lazy imports) and free of external dependencies.

Contents:
- Time helpers
- Workspace ID generation
- Labels used to mark managed containers
- In-memory "last used" index with helper functions
"""

from datetime import datetime, timezone
from typing import Dict, Optional

import time
import uuid

# --------------------------
# Labels (public constants)
# --------------------------

LABEL_MANAGED = "splk.ws.managed"
LABEL_WORKSPACE_ID = "splk.ws.id"
LABEL_CREATED_AT = "splk.ws.created_at"
LABEL_IMAGE = "splk.ws.image"
LABEL_CONTAINER_WORKDIR = "splk.ws.workdir"
LABEL_VERSION = "splk.ws.version"
LABEL_OWNER = "splk.ws.owner"
LABEL_OWNER_API_KEY_SUFFIX = "splk.ws.owner_api_key_suffix"
LABEL_APPLICATION_KIND = "splk.ws.app_kind"
LABEL_PLUGIN_NAME = "splk.ws.plugin_name"
LABEL_PLUGIN_VERSION = "splk.ws.plugin_version"


# --------------------------
# Owner label helpers
# --------------------------

def build_owner_labels(owner: Optional[str] = None, api_key_suffix: Optional[str] = None) -> Dict[str, str]:
    """
    Build a labels dict for associating a workspace with an owner identity.

    owner: stable user identifier
    api_key_suffix: optional suffix of the Workspace API key used by the client (for coarse grouping)
    """
    labels: Dict[str, str] = {}
    if owner:
        labels[LABEL_OWNER] = owner
    if api_key_suffix:
        labels[LABEL_OWNER_API_KEY_SUFFIX] = api_key_suffix
    return labels


def extract_owner(labels: Optional[Dict[str, str]]) -> Optional[str]:
    """
    Extract the owner value from a container labels mapping.
    """
    return (labels or {}).get(LABEL_OWNER)


def docker_label_filters_for_owner(owner: str) -> Dict[str, list[str]]:
    """
    Build Docker SDK filters for listing containers managed by the WorkspaceManager for a given owner.
    Usage:
        client.containers.list(all=True, filters=docker_label_filters_for_owner(owner))
    """
    return {"label": [f"{LABEL_MANAGED}=true", f"{LABEL_OWNER}={owner}"]}


# --------------------------
# Time helpers
# --------------------------

def now_utc_iso() -> str:
    """
    Current UTC time in ISO-8601 format with timezone info.
    """
    return datetime.now(timezone.utc).isoformat()


def epoch_now() -> float:
    """
    Current time as epoch seconds (float).
    """
    return time.time()


# --------------------------
# Workspace IDs
# --------------------------

def gen_workspace_id() -> str:
    """
    Generate a short, URL-safe workspace id.
    """
    return uuid.uuid4().hex[:12]


# --------------------------
# "Last used" tracking
# --------------------------

# In-memory index of workspace_id -> last used epoch seconds
# This is intentionally volatile and will reset on process restart.
_last_used_index: Dict[str, float] = {}


def mark_last_used(workspace_id: str) -> None:
    """
    Set the last-used time for a workspace to now.
    """
    _last_used_index[workspace_id] = epoch_now()


def get_last_used(workspace_id: str, fallback: Optional[float] = None) -> float:
    """
    Get the last-used time for a workspace.

    If the workspace was never seen, returns the provided fallback value.
    If fallback is None, returns the current time.
    """
    return _last_used_index.get(workspace_id, fallback if fallback is not None else epoch_now())


def clear_last_used(workspace_id: str) -> None:
    """
    Remove a workspace from the last-used index (no-op if absent).
    """
    _last_used_index.pop(workspace_id, None)


def snapshot_last_used_index() -> Dict[str, float]:
    """
    Return a shallow copy snapshot of the last-used index.
    """
    return dict(_last_used_index)