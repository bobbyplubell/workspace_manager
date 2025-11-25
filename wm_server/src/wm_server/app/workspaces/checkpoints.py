from __future__ import annotations

"""
Checkpoint-related Docker API helper wrappers.

This module centralizes thin wrappers around the Docker low-level API methods
used for container checkpoint management. All imports are eager; no lazy imports
or guarded imports are used.

Provided helpers:
- docker_api: Access the low-level API adapter from a DockerClient
- checkpoint_create: Create a new checkpoint for a container
- checkpoint_list_raw: Retrieve the raw checkpoint listing payload
- checkpoint_list_names: Convenience helper to parse checkpoint names from raw payload
- checkpoint_delete: Delete a checkpoint for a container
- start_from_checkpoint: Start a container from a given checkpoint
"""

from typing import Any, List, Optional

from docker import DockerClient  # type: ignore


__all__ = [
    "docker_api",
    "checkpoint_create",
    "checkpoint_list_raw",
    "checkpoint_list_names",
    "checkpoint_delete",
    "start_from_checkpoint",
]


def docker_api(client: DockerClient) -> Any:
    """
    Return the low-level API adapter from docker.DockerClient.

    This exposes methods like checkpoint_create, checkpoint_list, etc.
    """
    return getattr(client, "api")


def checkpoint_create(
    client: DockerClient,
    container_id: str,
    name: str,
    exit: bool = False,
    checkpoint_dir: Optional[str] = None,
) -> None:
    """
    Create a container checkpoint.

    Args:
        client: Docker client instance.
        container_id: ID of the target container.
        name: Checkpoint identifier.
        exit: If True, stop the container after checkpointing.
        checkpoint_dir: Optional directory on the host where checkpoints are stored.
    """
    docker_api(client).checkpoint_create(
        container_id,
        id=name,
        exit=exit,
        checkpoint_dir=checkpoint_dir,
    )


def checkpoint_list_raw(client: DockerClient, container_id: str) -> Any:
    """
    Return the raw response from the Docker API for checkpoint listing.

    The typical response shape:
        {
            "Checkpoints": [
                {"Name": "cp-1"},
                {"Name": "cp-2"},
                ...
            ]
        }

    Args:
        client: Docker client instance.
        container_id: ID of the target container.

    Returns:
        The raw API response (dict-like), or raises on API error.
    """
    return docker_api(client).checkpoint_list(container_id)


def checkpoint_list_names(client: DockerClient, container_id: str) -> List[str]:
    """
    Convenience helper: return a list of checkpoint names for a container.

    Args:
        client: Docker client instance.
        container_id: ID of the target container.

    Returns:
        List of checkpoint names (may be empty).
    """
    try:
        resp = checkpoint_list_raw(client, container_id)
    except Exception:
        # Propagate errors to caller for consistent handling, but keep parsing strict.
        raise

    names: List[str] = []
    if isinstance(resp, dict) and "Checkpoints" in resp:
        for item in (resp.get("Checkpoints") or []):
            if isinstance(item, dict):
                name = item.get("Name")
                if isinstance(name, str) and name:
                    names.append(name)
    return names


def checkpoint_delete(
    client: DockerClient,
    container_id: str,
    name: str,
    checkpoint_dir: Optional[str] = None,
) -> None:
    """
    Delete a named checkpoint for a container.

    Args:
        client: Docker client instance.
        container_id: ID of the target container.
        name: Checkpoint name to delete.
        checkpoint_dir: Optional directory on the host where checkpoints are stored.
    """
    docker_api(client).checkpoint_delete(
        container_id,
        id=name,
        checkpoint_dir=checkpoint_dir,
    )


def start_from_checkpoint(
    client: DockerClient,
    container_id: str,
    name: str,
    checkpoint_dir: Optional[str] = None,
) -> None:
    """
    Start (or restart) a container from a given checkpoint.

    Args:
        client: Docker client instance.
        container_id: ID of the target container.
        name: Checkpoint name to restore from.
        checkpoint_dir: Optional directory on the host where checkpoints are stored.
    """
    docker_api(client).start(
        container_id,
        checkpoint=name,
        checkpoint_dir=checkpoint_dir,
    )