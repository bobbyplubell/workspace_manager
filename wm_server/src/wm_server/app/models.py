from __future__ import annotations

"""
Pydantic models for the WorkspaceManager FastAPI service.

These models define the API contracts for:
- Workspace lifecycle
- Command execution
- File system operations
- Checkpoints (optional Docker feature)
- Directory listing and file existence
- Logs

Notes:
- We keep validation conservative and user-friendly.
- Paths for container operations are expected to be absolute inside the container.
"""

import enum
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# -----------------------
# Enums and simple types
# -----------------------

class WorkspaceState(str, enum.Enum):
    creating = "creating"
    starting = "starting"
    running = "running"
    stopping = "stopping"
    stopped = "stopped"
    deleting = "deleting"
    deleted = "deleted"
    error = "error"


# -----------------------
# Workspace lifecycle
# -----------------------

class WorkspaceConfig(BaseModel):
    """
    Request model to create a workspace and backing container.
    """
    application_params: Dict[str, str] = Field(
        default_factory=dict,
        description="Application-specific parameters or secrets (e.g., {'token': '...'}).",
    )
    env_vars: Dict[str, str] = Field(default_factory=dict, description="Additional environment variables for the app")
    ports: Dict[str, int] = Field(default_factory=dict, description="Docker port mappings (e.g., {'8000/tcp': 8000})")
    image: Optional[str] = Field(
        default=None,
        description="Optional Docker image override for this workspace.",
    )
    application_kind: Optional[str] = Field(
        default=None,
        description="Optional application kind hint passed to plugins.",
    )



    @field_validator("application_params", mode="before")
    def v_application_params(cls, v: Dict[str, Any]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, val in (v or {}).items():
            if not isinstance(k, str) or not k.strip():
                raise ValueError("Application parameter keys must be non-empty strings")
            out[k] = str(val) if not isinstance(val, str) else val
        return out

    @field_validator("env_vars", mode="before")
    def v_env_vars(cls, v: Dict[str, Any]) -> Dict[str, str]:
        # Coerce values to str; keys must be non-empty strings
        out: Dict[str, str] = {}
        for k, val in (v or {}).items():
            if not isinstance(k, str) or not k.strip():
                raise ValueError("Environment variable keys must be non-empty strings")
            out[k] = str(val) if not isinstance(val, str) else val
        return out

    @field_validator("image")
    def v_image(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if " " in v:
            raise ValueError("image must not contain whitespace")
        return v

    @field_validator("application_kind")
    def v_app_kind(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            return None
        return v



class PluginRef(BaseModel):
    """
    Minimal plugin reference used across API responses.
    """

    name: str
    version: Optional[str] = None



class WorkspaceCreateResponse(BaseModel):
    workspace_id: str
    status: WorkspaceState = Field(..., description="Current lifecycle state of the workspace")
    created_at: datetime
    application_plugin: Optional[PluginRef] = Field(
        default=None,
        description="Plugin selected for this workspace (name/version).",
    )


class WorkspaceDeleteResponse(BaseModel):
    workspace_id: str
    status: WorkspaceState = Field(..., description="State after deletion attempt (e.g., 'deleted')")


class WorkspaceStatus(BaseModel):
    """
    Detailed workspace status, suitable for listing or querying a specific workspace.
    """
    workspace_id: str
    status: WorkspaceState
    created_at: datetime
    started_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    container_id: Optional[str] = None
    image: Optional[str] = None
    owner: Optional[str] = None
    application_plugin: Optional[PluginRef] = None


class WorkspaceListResponse(BaseModel):
    workspaces: List[WorkspaceStatus] = Field(default_factory=list)


# -----------------------
# Command execution
# -----------------------

class ExecPayload(BaseModel):
    """
    Execute a shell command inside a workspace container.
    The default cwd should be resolved by the service using its configured container workspace dir.
    """
    command: str = Field(..., min_length=1)
    user: Optional[str] = Field(
        default=None,
        description="User to run inside the container; plugin default is used when omitted.",
    )
    cwd: Optional[str] = Field(None, description="Working directory; if None, service will use configured workspace dir")
    env_vars: Dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(60, ge=1, le=36000, description="Soft timeout in seconds")

    @field_validator("env_vars", mode="before")
    def v_env_vars(cls, v: Dict[str, Any]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, val in (v or {}).items():
            if not isinstance(k, str) or not k.strip():
                raise ValueError("Environment variable keys must be non-empty strings")
            out[k] = str(val) if not isinstance(val, str) else val
        return out


class ExecResult(BaseModel):
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True


# -----------------------
# File operations
# -----------------------

class WriteFilePayload(BaseModel):
    """
    Write a text file inside the container. Parent directories will be created.
    Paths must be absolute inside the container.
    """
    path: str = Field(..., description="Absolute path inside the container")
    content: str = Field("", description="Text content to write")

    @field_validator("path")
    def v_path_absolute(cls, v: str) -> str:
        if not isinstance(v, str) or not v.startswith("/"):
            raise ValueError("path must be an absolute path inside the container")
        return v


class FileWriteResult(BaseModel):
    path: str
    bytes_written: int


class FileReadResult(BaseModel):
    content: str


class FileInfoModel(BaseModel):
    path: str
    is_directory: bool
    size: int
    permissions: str
    owner: str
    group: str


class ListDirResult(BaseModel):
    items: List[FileInfoModel] = Field(default_factory=list)


class ExistsResult(BaseModel):
    exists: bool


class CopyToResponse(BaseModel):
    destination_path: str
    status: str = Field("copied")


# -----------------------
# Checkpoints (optional)
# -----------------------

class CheckpointCreatePayload(BaseModel):
    name: str = Field(..., min_length=1)
    exit: bool = Field(False, description="Stop the container after creating the checkpoint")
    checkpoint_dir: Optional[str] = Field(None, description="Custom checkpoint directory (Docker daemon dependent)")


class CheckpointActionResponse(BaseModel):
    ok: bool


class CheckpointListResponse(BaseModel):
    checkpoints: List[str] = Field(default_factory=list)


# -----------------------
# Logs and diagnostics
# -----------------------

class LogsResponse(BaseModel):
    logs: str


class MkdirPayload(BaseModel):
    path: str = Field(..., description="Absolute directory path inside the container")
    parents: bool = Field(True, description="Create parent directories as needed")
    mode: Optional[str] = Field(None, description="Octal mode like '755' to apply after create")

    @field_validator("path")
    def v_path_absolute(cls, v: str) -> str:
        if not isinstance(v, str) or not v.startswith("/"):
            raise ValueError("path must be an absolute path inside the container")
        return v


class MkdirResult(BaseModel):
    path: str
    created: bool = True


class ChownPayload(BaseModel):
    path: str = Field(..., description="Absolute path inside the container")
    owner: str = Field("root")
    group: str = Field("root")
    recursive: bool = Field(True, description="Apply recursively")

    @field_validator("path")
    def v_path_absolute(cls, v: str) -> str:
        if not isinstance(v, str) or not v.startswith("/"):
            raise ValueError("path must be an absolute path inside the container")
        return v


class ChownResult(BaseModel):
    path: str
    ok: bool = True


class StatResult(BaseModel):
    path: str
    is_directory: bool
    size: int
    permissions: str
    owner: str
    group: str
    mtime: Optional[float] = None


class ApplicationStatus(BaseModel):
    """
    Standardized application status for a workspace.

    Intended to be returned by an application-specific status endpoint so clients
    do not need to parse CLI output. Each plugin is responsible for the semantics
    of the optional fields (REST readiness, provisioning state, etc.).
    """
    app_name: str = Field(..., description="Human-friendly application name.")
    running: bool = Field(False, description="True if the primary service process is running.")
    rest_ready: bool = Field(False, description="True if application REST management endpoint responds 2xx")
    provisioning: bool = Field(False, description="True while initial provisioning (e.g., Ansible) is still in progress")
    provisioning_message: Optional[str] = Field(None, description="Last-known provisioning phase/detail when provisioning=True")
    version: Optional[str] = Field(None, description="Application version string when available")
    build: Optional[str] = Field(None, description="Application build identifier when available")
    web_port: Optional[int] = Field(None, description="Primary web UI port when applicable")
    web_host: Optional[str] = Field(None, description="Host where the mapped web port is reachable")
    mgmt_port: Optional[int] = Field(None, description="Primary management/REST port when applicable")
    mgmt_host: Optional[str] = Field(None, description="Host where the mapped management port is reachable")
    status_text: Optional[str] = Field(None, description="Raw status text for diagnostics")


class PluginSummary(BaseModel):
    name: str
    version: str
    api_version: str
    provides: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    origin: Optional[str] = None
    config_schema: Optional[Dict[str, object]] = None


class PluginErrorInfo(BaseModel):
    name: str
    origin: str
    error_type: str
    message: str


class PluginListResponse(BaseModel):
    plugins: List[PluginSummary] = Field(default_factory=list)


class PluginErrorsResponse(BaseModel):
    errors: List[PluginErrorInfo] = Field(default_factory=list)


__all__ = [
    "WorkspaceState",
    "WorkspaceConfig",
    "WorkspaceCreateResponse",
    "WorkspaceDeleteResponse",
    "WorkspaceStatus",
    "WorkspaceListResponse",
    "ExecPayload",
    "ExecResult",
    "WriteFilePayload",
    "FileWriteResult",
    "FileReadResult",
    "FileInfoModel",
    "ListDirResult",
    "ExistsResult",
    "CopyToResponse",
    "MkdirPayload",
    "MkdirResult",
    "ChownPayload",
    "ChownResult",
    "StatResult",
    "CheckpointCreatePayload",
    "CheckpointActionResponse",
    "CheckpointListResponse",
    "LogsResponse",
    "ApplicationStatus",
    "PluginRef",
    "PluginSummary",
    "PluginErrorInfo",
    "PluginListResponse",
    "PluginErrorsResponse",
]
