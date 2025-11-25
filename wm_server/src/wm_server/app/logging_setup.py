"""
Centralized rotating file logging for WorkspaceManager (wm_server).

This module configures a RotatingFileHandler that ALWAYS writes logs to a file,
with a sensible fallback strategy for choosing a writable log path. The file
handler captures DEBUG and above so issues can be diagnosed post-mortem.

Usage (call once during app startup, before creating the FastAPI app):

    from wm_server.app.logging_setup import initialize_from_env

    # Must run before FastAPI/uvicorn wires its own handlers to ensure our
    # file handler is attached early and receives all logs.
    log_path = initialize_from_env(service_name="workspace_manager")

    # Optionally print or log where the logs are going:
    import logging
    logging.getLogger("workspace_manager").info("Logging to: %s", log_path)

Environment variables (optional):
- WM_LOG_FILE: Absolute path to the desired log file.
- WM_LOG_DIR:  Directory where the log file should be created.
- WM_LOG_NAME: File name to use (default: "<service_name>.log").
- WM_LOG_MAX_BYTES: Max file size before rotate (default: 10485760 = 10MB).
- WM_LOG_BACKUP_COUNT: Number of rotated files to keep (default: 10).
- WM_LOG_LEVEL: Base log level for app logs (default: INFO).
- LOG_LEVEL: Fallback for WM_LOG_LEVEL when unset.
- WM_CONSOLE: "1"/"true" to add a console handler (default: disabled here).
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Union

__all__ = [
    "initialize_from_env",
    "setup_logging",
    "configure_third_party_loggers",
]

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10MB
_DEFAULT_BACKUP_COUNT = 10
_DEFAULT_FORMAT_FILE = "%(asctime)s %(levelname)s [wm_server] %(name)s pid=%(process)d %(filename)s:%(lineno)d - %(message)s"
_DEFAULT_FORMAT_CONSOLE = "%(asctime)s %(levelname)s [wm_server] %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Sentinel to avoid adding duplicate file handlers
_ATTACHED_LOG_PATHS: set[str] = set()


def _coerce_level(level: Optional[Union[int, str]], default: int = logging.INFO) -> int:
    if isinstance(level, int):
        return level
    if isinstance(level, str):
        upper = level.strip().upper()
        return getattr(logging, upper, default)
    return default


def _candidate_paths(
    service_name: str,
    log_dir: Optional[Union[str, Path]],
    log_file_name: Optional[str],
) -> List[Path]:
    """
    Compute a prioritized list of candidate paths to use for the log file.
    """
    candidates: List[Path] = []

    # 1) Explicitly specified file via env has highest priority
    env_file = os.getenv("WM_LOG_FILE")
    if env_file:
        candidates.append(Path(env_file).expanduser())

    # Determine a file name
    file_name = (log_file_name or os.getenv("WM_LOG_NAME") or f"{service_name}.log").strip()

    # 2) Explicit log_dir argument takes precedence, then env var
    if log_dir:
        candidates.append(Path(log_dir).expanduser() / file_name)
    env_dir = os.getenv("WM_LOG_DIR")
    if env_dir:
        candidates.append(Path(env_dir).expanduser() / file_name)

    # 3) Project directories (package root and repo root)
    try:
        pkg_root = Path(__file__).resolve().parents[1]  # wm_server/
        candidates.append(pkg_root / file_name)
        repo_root = pkg_root.parents[1]  # workspace_manager/
        candidates.append(repo_root / file_name)
    except Exception:
        # Best-effort; skip if path resolution fails in zipped/zipapp contexts
        pass

    # 4) User home: ~/.workspace_manager/logs/
    candidates.append(Path.home() / ".workspace_manager" / "logs" / file_name)

    # 5) OS temp: <tmp>/workspace_manager/logs/
    candidates.append(Path(tempfile.gettempdir()) / "workspace_manager" / "logs" / file_name)

    return candidates


def _ensure_writable_file(path: Path) -> Tuple[bool, Optional[str]]:
    """
    Ensure parent directory exists and the file is creatable/appendable.

    Returns:
        (True, None) on success
        (False, reason) on failure
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Attempt to open/close to validate writability
        with open(path, mode="a", encoding="utf-8"):
            pass
        return True, None
    except OSError as e:
        return False, f"{e.__class__.__name__}: {e}"
    except Exception as e:  # Catch-all to surface unexpected conditions
        return False, f"{e.__class__.__name__}: {e}"


def _pick_log_path(
    service_name: str,
    log_dir: Optional[Union[str, Path]],
    log_file_name: Optional[str],
) -> Path:
    """
    Choose the first writable path from a prioritized list of candidates.
    Raises RuntimeError if none are writable.
    """
    attempts: List[Tuple[str, str]] = []  # (path, error)
    for candidate in _candidate_paths(service_name, log_dir, log_file_name):
        ok, reason = _ensure_writable_file(candidate)
        if ok:
            return candidate
        attempts.append((str(candidate), reason or "unknown error"))

    reasons = "; ".join([f"{p} -> {r}" for p, r in attempts]) or "no candidates were attempted"
    raise RuntimeError(f"Failed to initialize wm_server file logging (no writable paths). Attempts: {reasons}")


def configure_third_party_loggers(base_level: int) -> None:
    """
    Tame noisy third-party libraries while allowing escalation via DEBUG when needed.
    """
    noisy = [
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
        "fastapi",
        "httpx",
        "urllib3",
        "docker",
        "asyncio",
        "websockets",
    ]
    # If base is DEBUG, allow INFO for libraries; otherwise WARNING
    lib_level = logging.INFO if base_level <= logging.DEBUG else logging.WARNING
    for name in noisy:
        logging.getLogger(name).setLevel(lib_level)

    # Keep these quiet unless explicitly debugging
    for name in ("urllib3.connectionpool", "asyncio", "concurrent.futures"):
        logging.getLogger(name).setLevel(logging.WARNING)


def setup_logging(
    service_name: str = "workspace_manager",
    *,
    level: Optional[Union[int, str]] = None,
    log_dir: Optional[Union[str, Path]] = None,
    log_file_name: Optional[str] = None,
    max_bytes: Optional[int] = None,
    backup_count: Optional[int] = None,
    add_console: bool = False,
) -> Path:
    """
    Configure root logging with a rotating file handler that always writes to disk.

    - File handler captures DEBUG and above (full fidelity).
    - Root logger is set to DEBUG to ensure handlers can down-filter as needed.
    - Optionally attaches a simple console handler for interactive runs.

    Returns:
        Path to the active log file.

    Raises:
        RuntimeError if no writable log path could be created.
    """
    # Resolve effective levels and sizing
    base_level = _coerce_level(
        level if level is not None else (os.getenv("WM_LOG_LEVEL") or os.getenv("LOG_LEVEL") or "INFO"),
        default=logging.INFO,
    )
    bytes_limit = int(os.getenv("WM_LOG_MAX_BYTES", str(max_bytes if max_bytes is not None else _DEFAULT_MAX_BYTES)))
    keep_files = int(os.getenv("WM_LOG_BACKUP_COUNT", str(backup_count if backup_count is not None else _DEFAULT_BACKUP_COUNT)))

    # Choose a writable file path (fatal if none)
    log_path = _pick_log_path(service_name, log_dir, log_file_name)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # capture everything; handlers decide what to emit

    # Avoid duplicating the same file handler across multiple invocations
    target_key = str(Path(log_path).resolve())
    already_attached = any(
        getattr(h, "baseFilename", None) and str(Path(getattr(h, "baseFilename")).resolve()) == target_key
        for h in root.handlers
    )
    if not already_attached and target_key not in _ATTACHED_LOG_PATHS:
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_path,
            maxBytes=max(1, bytes_limit),
            backupCount=max(1, keep_files),
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT_FILE, datefmt=_DEFAULT_DATEFMT))
        root.addHandler(file_handler)
        _ATTACHED_LOG_PATHS.add(target_key)

    # Optionally add a console handler (kept minimalist; uvicorn typically configures console itself)
    if add_console:
        has_console = any(isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) in (sys.stdout, sys.stderr) for h in root.handlers)
        if not has_console:
            ch = logging.StreamHandler(stream=sys.stdout)
            ch.setLevel(base_level)
            ch.setFormatter(logging.Formatter(_DEFAULT_FORMAT_CONSOLE, datefmt=_DEFAULT_DATEFMT))
            root.addHandler(ch)

    # Set application logger level (others can remain inherited)
    logging.getLogger("workspace_manager").setLevel(base_level)

    # Tame third-party noise relative to our base_level
    configure_third_party_loggers(base_level)

    # Emit a one-time notice with the resolved configuration
    logging.getLogger("workspace_manager").info(
        "Logging initialized: file=%s level=%s rotate=%s bytes backup=%s",
        str(log_path),
        logging.getLevelName(base_level),
        "size",
        keep_files,
    )

    return log_path


def initialize_from_env(service_name: str = "workspace_manager") -> Path:
    """
    Convenience initializer for app startup.

    Always attaches a console handler at process start so startup INFO logs are visible.
    Reads other settings from environment. Returns the Path to the active log file.

    Example (in wm_server.app.main):
        from wm_server.app.logging_setup import initialize_from_env
        LOG_PATH = initialize_from_env()  # call before creating FastAPI app
    """
    return setup_logging(service_name=service_name, add_console=True)
