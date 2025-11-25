from __future__ import annotations

"""
Filesystem helpers for WorkspaceManager.

This module provides:
- parse_ls_la: Parse `ls -la` output from a container into FileInfoModel entries.
- emulate_find: Emulate a recursive file discovery (similar to `find`) by parsing `ls -1RA` output.

Notes:
- No lazy imports.
- No guarded imports around third-party packages.
"""

from typing import List, Optional

from docker import DockerClient  # type: ignore
from docker.models.containers import Container  # type: ignore

from wm_server.app.models import FileInfoModel


__all__ = [
    "parse_ls_la",
    "emulate_find",
]


def parse_ls_la(output: str, base_path: str) -> List[FileInfoModel]:
    """
    Parse `ls -la` output (without the "total" header line) into FileInfoModel items.

    The function expects typical `ls -la` columns:
      perms links owner group size month day time/year name

    Args:
        output: Raw textual output from `ls -la | tail -n +2`.
        base_path: Absolute base directory path used to construct full paths.

    Returns:
        List of FileInfoModel entries for each listed item.
    """
    items: List[FileInfoModel] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Expect at least 9 columns; the 9th (index 8) is file/dir name which may include spaces
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue

        perms, _links, owner, group, size_s, _month, _day, _time_or_year, name = parts

        # Skip dot entries
        if name in (".", ".."):
            continue

        is_dir = perms.startswith("d")
        try:
            size = int(size_s)
        except Exception:
            size = 0

        # Compose absolute path
        base = base_path.rstrip("/")
        if base == "":
            base = "/"
        full_path = f"{base}/{name}" if base != "/" else f"/{name}"

        items.append(
            FileInfoModel(
                path=full_path,
                is_directory=is_dir,
                size=size,
                permissions=perms,
                owner=owner,
                group=group,
            )
        )
    return items


def emulate_find(
    client: Optional[DockerClient],
    c: Container,
    base_path: str,
    limit: int = 500,
) -> List[str]:
    """
    Emulate a recursive discovery of files/directories by parsing `ls -1RA` output.

    This is a lightweight alternative to invoking `find`, which may not be available
    in minimal images. It traverses using `ls -1RA` and reconstructs relative paths.

    Args:
        client: Unused placeholder for compatibility with existing call sites.
        c: Docker Container to execute the command within.
        base_path: Absolute directory path inside the container to scan.
        limit: Maximum number of entries to return (0 or None means unlimited).

    Returns:
        A list of relative paths (from base_path) for discovered entries.
    """
    # Use a subshell to avoid erroring out when base_path doesn't exist
    cmd = f"sh -lc \"cd '{base_path}' 2>/dev/null && ls -1RA || true\""
    res = c.exec_run(["sh", "-lc", cmd], demux=True)
    stdout_b, _stderr_b = (res.output if res and hasattr(res, "output") else (b"", b"")) if res else (b"", b"")
    out = stdout_b.decode("utf-8", errors="replace")

    results: List[str] = []
    current_dir = ""

    for raw in (out or "").splitlines():
        line = raw.rstrip()
        if not line:
            continue

        # Directory header lines end with a colon (e.g., "." or "./subdir:")
        if line.endswith(":"):
            hdr = line[:-1].strip()
            if hdr in (".", "./"):
                current_dir = ""
            else:
                if hdr.startswith("./"):
                    hdr = hdr[2:]
                current_dir = hdr
            continue

        # Skip total lines and pseudo-entries
        if line == "." or line.startswith("total "):
            continue

        name = line.strip()
        if not name:
            continue

        # Normalize directory entries that may include trailing slash in some ls variants
        if name.endswith("/"):
            name = name[:-1]

        rel = f"{current_dir}/{name}" if current_dir else name
        if rel.startswith("./"):
            rel = rel[2:]

        if rel:
            results.append(rel)

        if limit and len(results) >= limit:
            break

    return results[:limit] if limit else results