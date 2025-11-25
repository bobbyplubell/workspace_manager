from __future__ import annotations

"""
Docker/container utility helpers for WorkspaceManager.

This module provides:
- Container resolution by workspace_id with label verification
- Runtime state enforcement (ensure container is running)
- Tar stream creation from in-memory bytes
- Stream aggregation for Docker API responses

All helpers are import-only and do not perform lazy imports.
"""

import io
import tarfile
import threading
import queue
import time
from typing import Iterable, List, AsyncIterator, BinaryIO

from fastapi import HTTPException, status

from docker import DockerClient
from docker.errors import NotFound
from docker.models.containers import Container

from wm_server.app.deps import workspace_container_name
from wm_server.app.workspaces.core import LABEL_WORKSPACE_ID


__all__ = [
    "get_container_by_workspace_id",
    "ensure_running",
    "tar_from_bytes",
    "collect_stream",
    "stream_single_file_as_tar",
    "aiter_from_sync_iter",
    "reader_from_iterable",
]


def get_container_by_workspace_id(client: DockerClient, workspace_id: str) -> Container:
    """
    Resolve a Docker container for a workspace_id.

    Strategy:
    1) Try deterministic name via workspace_container_name
    2) Fallback to label-based lookup (LABEL_WORKSPACE_ID=workspace_id)

    Raises:
        HTTPException 404 if not found or not a managed container.
    """
    name = workspace_container_name(workspace_id)
    try:
        c = client.containers.get(name)
        # Ensure it's our managed workspace
        if not getattr(c, "labels", None) or c.labels.get(LABEL_WORKSPACE_ID) != workspace_id:
            raise NotFound(f"Container found but not managed workspace: {name}")
        return c
    except NotFound:
        # Fallback to label filter
        candidates = client.containers.list(
            all=True,
            filters={"label": f"{LABEL_WORKSPACE_ID}={workspace_id}"},
        )
        if not candidates:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found",
            )
        return candidates[0]


def ensure_running(c: Container, retries: int = 5, delay: float = 0.5) -> None:
    """
    Ensure a container is in 'running' state.

    Attempts to recover from common stopped states by starting or unpausing the
    container before giving up. Raises HTTP 409 only after the container fails
    to reach the running state within the allotted retries.

    Raises:
        HTTPException 500 on reload/start errors.
        HTTPException 409 if the container cannot reach running state.
    """

    def _reload() -> None:
        try:
            c.reload()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to access container: {e}")

    attempts = max(1, int(retries or 1))
    _reload()

    for attempt in range(attempts + 1):
        status = getattr(c, "status", "")
        if status == "running":
            return

        if attempt == attempts:
            break

        try:
            # Attempt to transition the container into a runnable state when it is safe to do so.
            if status in {"created", "exited", "dead", "stopped"}:
                c.start()
            elif status == "paused":
                c.unpause()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to transition workspace to running state: {e}")

        time.sleep(max(0.0, float(delay)))
        _reload()

    raise HTTPException(
        status_code=409,
        detail=f"Workspace is not running (status={c.status})",
    )


def tar_from_bytes(name: str, data: bytes, mode: int = 0o644) -> io.BytesIO:
    """
    Create a tar archive (in-memory) containing a single file.

    Args:
        name: The filename inside the tar archive.
        data: Raw file contents.
        mode: File mode (permissions) for the entry.

    Returns:
        BytesIO positioned at start, ready for Docker put_archive.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        ti = tarfile.TarInfo(name=name)
        ti.size = len(data)
        ti.mode = mode
        tar.addfile(ti, io.BytesIO(data))
    buf.seek(0)
    return buf


def collect_stream(stream: Iterable[bytes]) -> bytes:
    """
    Aggregate a byte-stream iterable (e.g., from Docker API) into a single bytes object.
    """
    chunks: List[bytes] = []
    for chunk in stream:
        if isinstance(chunk, (bytes, bytearray)):
            chunks.append(bytes(chunk))
    return b"".join(chunks)


def stream_single_file_as_tar(name: str, size: int, src: BinaryIO, queue_size: int = 8, mode: int = 0o644) -> io.RawIOBase:
    """
    Create a readable file-like object that yields a tar stream containing a single file.

    This is streaming and memory-efficient: a background thread writes the tar stream
    into a queue-backed writer while the returned reader pulls data out on demand.

    Args:
        name: Filename inside the tar archive.
        size: Exact size (in bytes) of src to include in the tar entry.
        src:  BinaryIO providing the file content (seekable or not).
        queue_size: Max queued chunks to buffer between producer and consumer.

    Returns:
        A file-like object supporting read() that yields the tar stream incrementally.
    """
    q: "queue.Queue[bytes | object]" = queue.Queue(maxsize=max(1, int(queue_size)))
    sentinel = object()

    class _QueueWriter(io.RawIOBase):
        def writable(self) -> bool:
            return True

        def write(self, b) -> int:
            if b:
                q.put(bytes(b))
            return len(b)

    class _QueueReader(io.RawIOBase):
        def __init__(self) -> None:
            self._buf = bytearray()
            self._done = False
            self._exc = None  # type: ignore[assignment]

        def readable(self) -> bool:
            return True

        def read(self, n: int = -1) -> bytes:
            # Fill buffer if empty and producer still active
            while not self._buf and not self._done:
                item = q.get()
                if item is sentinel:
                    self._done = True
                    break
                if isinstance(item, BaseException):
                    # Producer encountered an error; propagate to reader
                    self._exc = item
                    self._done = True
                    break
                self._buf += item  # type: ignore[arg-type]
            # Raise any deferred producer exception
            if self._exc is not None:
                raise self._exc  # type: ignore[misc]
            if n is None or n < 0:
                out = bytes(self._buf)
                self._buf.clear()
                return out
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

    def _producer() -> None:
        try:
            w = _QueueWriter()
            with tarfile.open(fileobj=w, mode="w|") as tar:
                ti = tarfile.TarInfo(name=name)
                ti.size = int(size)
                ti.mode = int(mode)
                tar.addfile(ti, src)
        except BaseException as e:
            # Pass exception to consumer; avoid unhandled thread exceptions
            q.put(e)
        finally:
            q.put(sentinel)

    reader = _QueueReader()
    threading.Thread(target=_producer, daemon=True).start()
    return reader


def reader_from_iterable(stream: Iterable[bytes]) -> io.RawIOBase:
    """
    Adapt an iterable of bytes into a file-like object with read(), suitable for tarfile streaming.
    """
    class _IterReader(io.RawIOBase):
        def __init__(self, iterator):
            self._it = iter(iterator)
            self._buf = bytearray()
            self._eof = False

        def readable(self) -> bool:
            return True

        def read(self, n: int = -1) -> bytes:
            # Refill buffer from the iterator as needed
            while (n is None or n < 0) and not self._eof:
                try:
                    chunk = next(self._it)
                except StopIteration:
                    self._eof = True
                    break
                if chunk:
                    self._buf += chunk  # type: ignore[arg-type]
            while n is not None and n >= 0 and len(self._buf) < n and not self._eof:
                try:
                    chunk = next(self._it)
                except StopIteration:
                    self._eof = True
                    break
                if chunk:
                    self._buf += chunk  # type: ignore[arg-type]

            if n is None or n < 0:
                out = bytes(self._buf)
                self._buf.clear()
                return out
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

    return _IterReader(stream)


async def aiter_from_sync_iter(stream: Iterable[bytes]) -> AsyncIterator[bytes]:
    """
    Convert a synchronous iterable of bytes into an async iterator of bytes.

    Useful for adapting blocking/streaming sources (like Docker exec_run(stream=True),
    which yields chunks synchronously) into something FastAPI's StreamingResponse
    can consume via 'async for'.
    """
    for chunk in stream:
        if not chunk:
            continue
        yield bytes(chunk)
