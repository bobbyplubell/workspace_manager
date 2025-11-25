from __future__ import annotations

"""
WorkspaceManager router: lifecycle, exec, filesystem, checkpoints, and logs.

Design:
- Stateless API that manages per-workspace Docker containers.
- Each workspace is a separate container identified by a workspace_id.
- API key auth enforced via dependency.
- Idle cleanup is handled by the FastAPI app lifespan, helpers imported from workspace modules.

Notes:
- No lazy imports.
- No guarded imports around third-party packages.
"""

import os
import time
import asyncio
import tarfile
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import urlparse

from docker import DockerClient
from docker.errors import NotFound, APIError
from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    HTTPException,
    Path,
    Query,
    Response,
    UploadFile,
    status,
    Request,
)
from fastapi.responses import StreamingResponse

from wm_server.app.applications.factory import resolve_application_with_metadata
from wm_server.app.deps import (
    ServiceConfig,
    docker_client,
    enforce_api_key,
    get_settings,
)
from wm_server.app.models import (
    CheckpointActionResponse,
    CheckpointCreatePayload,
    CheckpointListResponse,
    CopyToResponse,
    ExecPayload,
    ExecResult,
    ExistsResult,
    FileReadResult,
    FileWriteResult,
    ListDirResult,
    LogsResponse,
    WorkspaceConfig,
    WorkspaceCreateResponse,
    WorkspaceDeleteResponse,
    WorkspaceListResponse,
    WorkspaceState,
    WorkspaceStatus,
    ApplicationStatus,
)
from wm_server.app import models as m

# Refactored helpers imported from dedicated modules
from wm_server.app.workspaces.core import (
    LABEL_MANAGED,
    LABEL_WORKSPACE_ID,
    LABEL_CREATED_AT,
    LABEL_IMAGE,
    LABEL_CONTAINER_WORKDIR,
    LABEL_VERSION,
    LABEL_OWNER,
    LABEL_OWNER_API_KEY_SUFFIX,
    LABEL_APPLICATION_KIND,
    LABEL_PLUGIN_NAME,
    LABEL_PLUGIN_VERSION,
    now_utc_iso,

    mark_last_used,
    get_last_used,
    gen_workspace_id,
    clear_last_used,
)
from wm_server.app.workspaces.docker_utils import (
    get_container_by_workspace_id,
    ensure_running,
    tar_from_bytes,
    stream_single_file_as_tar,
    aiter_from_sync_iter,
    reader_from_iterable,
)
from wm_server.app.workspaces.fs_utils import (
    parse_ls_la,
    emulate_find,
)
from wm_server.app.workspaces.lifecycle import (
    wait_for_app_ready,
)
from wm_server.app.workspaces.checkpoints import (
    checkpoint_create,
    checkpoint_list_raw,
    checkpoint_delete,
    start_from_checkpoint as docker_start_from_checkpoint,
)

router = APIRouter(dependencies=[Depends(enforce_api_key)])

# --------------------------
# Access scoping helpers (per-caller API key)
# --------------------------

def _api_key_suffix_from_request(request: Request, settings: ServiceConfig) -> str | None:
    """
    Extract a short suffix of the provided API key to associate and filter workspaces.
    Returns None when no API key was provided.
    """
    try:
        header_name = settings.api_key_header_name or "X-API-Key"
        key_val = request.headers.get(header_name) if request is not None else None
        if not key_val:
            return None
        # Use the last 8 characters as a suffix (short identifier, avoids leaking full key)
        return key_val[-8:] if len(key_val) >= 8 else key_val
    except Exception:
        return None
def _resolve_port_proxy_host(settings: ServiceConfig) -> str:
    """
    Determine the host name/IP where Docker-published ports are reachable.

    Priority:
      1. WORKSPACE_PORT_PROXY_HOST environment variable
      2. Host component of DOCKER_HOST when using a tcp:// connection
      3. Default to 127.0.0.1 for local Docker Desktop/socket setups
    """
    env_host = os.getenv("WORKSPACE_PORT_PROXY_HOST", "").strip()
    if env_host:
        return env_host
    docker_host = os.getenv("DOCKER_HOST", "").strip()
    if docker_host.startswith("tcp://"):
        try:
            parsed = urlparse(docker_host)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
    return "127.0.0.1"


def _plugin_ref_from_labels(labels: Optional[Dict[str, str]]) -> Optional[m.PluginRef]:
    if not labels:
        return None
    name = labels.get(LABEL_PLUGIN_NAME)
    if not name:
        return None
    return m.PluginRef(name=name, version=labels.get(LABEL_PLUGIN_VERSION))


def _application_resolution_for_container(
    container,
    settings: ServiceConfig,
    cfg: Optional[WorkspaceConfig] = None,
):
    labels = getattr(container, "labels", {}) or {}
    plugin_name = labels.get(LABEL_PLUGIN_NAME)
    kind_hint = labels.get(LABEL_APPLICATION_KIND)
    image_label = labels.get(LABEL_IMAGE)
    if image_label:
        image_str = image_label
    else:
        try:
            tags = getattr(container.image, "tags", None) or []
            image_str = tags[0] if tags else ""
        except Exception:
            image_str = ""
    return resolve_application_with_metadata(
        image=image_str,
        kind=kind_hint,
        cfg=cfg,
        plugin_name=plugin_name,
        settings=settings,
    )


# --------------------------
# Routes: Filesystem admin (mkdir/chown/stat)
# --------------------------

@router.post(
    "/{workspace_id}/files/mkdir",
    response_model=m.MkdirResult,
)
async def mkdir_path(
    workspace_id: str = Path(...),
    payload: m.MkdirPayload = Body(...),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> m.MkdirResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)
    mkdir_flag = "-p " if payload.parents else ""
    cmd = f"mkdir {mkdir_flag}'{payload.path}'"
    res = c.exec_run(["sh", "-lc", cmd], user="root", demux=True)
    if payload.mode:
        try:
            c.exec_run(["sh", "-lc", f"chmod {payload.mode} '{payload.path}'"], user="root", demux=True)
        except Exception:
            # best-effort
            pass
    mark_last_used(workspace_id)
    return m.MkdirResult(path=payload.path, created=(int(getattr(res, "exit_code", 1)) == 0))


@router.post(
    "/{workspace_id}/files/chown",
    response_model=m.ChownResult,
)
async def chown_path(
    workspace_id: str = Path(...),
    payload: m.ChownPayload = Body(...),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> m.ChownResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)
    flag = "-R " if payload.recursive else ""
    cmd = f"chown {flag}{payload.owner}:{payload.group} '{payload.path}'"
    res = c.exec_run(["sh", "-lc", cmd], user="root", demux=True)
    ok = int(getattr(res, "exit_code", 1)) == 0
    mark_last_used(workspace_id)
    return m.ChownResult(path=payload.path, ok=ok)


@router.get(
    "/{workspace_id}/files/stat",
    response_model=m.StatResult,
)
async def stat_path(
    workspace_id: str = Path(...),
    path: str = Query(..., description="Absolute path inside the container"),
    client: DockerClient = Depends(docker_client),
    settings: ServiceConfig = Depends(get_settings),
    request: Request = None,
) -> m.StatResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, settings)
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)
    # Prefer GNU stat format; if unavailable, this may fail and return 404
    res = c.exec_run(
        ["sh", "-lc", f"stat -c '%F|%s|%a|%U|%G|%Y' '{path}'"],
        demux=True,
    )
    exit_code = int(getattr(res, "exit_code", 1))
    stdout_b, stderr_b = (res.output if res and hasattr(res, "output") else (b"", b"")) if res else (b"", b"")
    if exit_code != 0:
        raise HTTPException(
            status_code=404,
            detail=(stderr_b or stdout_b).decode("utf-8", errors="replace") or "Path not found",
        )
    txt = stdout_b.decode("utf-8", errors="replace").strip()
    parts = txt.split("|")
    type_s = parts[0] if len(parts) > 0 else ""
    size_s = parts[1] if len(parts) > 1 else "0"
    perm_s = parts[2] if len(parts) > 2 else ""
    owner = parts[3] if len(parts) > 3 else ""
    group = parts[4] if len(parts) > 4 else ""
    mtime_s = parts[5] if len(parts) > 5 else ""
    try:
        size = int(size_s)
    except Exception:
        size = 0
    try:
        mtime = float(mtime_s)
    except Exception:
        mtime = None
    is_dir = type_s.lower().startswith("directory")
    mark_last_used(workspace_id)
    return m.StatResult(
        path=path,
        is_directory=is_dir,
        size=size,
        permissions=perm_s,
        owner=owner,
        group=group,
        mtime=mtime,
    )


# --------------------------
# Routes: Lifecycle
# --------------------------

@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=WorkspaceCreateResponse,
)
async def create_workspace(
    cfg: WorkspaceConfig = Body(...),
    wait_ready: bool = Query(True, description="Wait for application readiness before returning"),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> WorkspaceCreateResponse:
    """
    Create a new workspace (container) and wait until the application inside is ready.
    """
    workspace_id = gen_workspace_id()
    name = settings.workspace_container_name(workspace_id)
    requested_image = cfg.image or settings.default_image
    resolution = resolve_application_with_metadata(
        requested_image,
        cfg.application_kind,
        cfg=cfg,
        settings=settings,
    )
    app_impl = resolution.application
    try:
        app_impl.validate_config(cfg, settings)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    image = requested_image or app_impl.default_image(settings)
    env: Dict[str, str] = app_impl.build_environment(cfg, settings)

    labels = {
        LABEL_MANAGED: "true",
        LABEL_WORKSPACE_ID: workspace_id,
        LABEL_CREATED_AT: now_utc_iso(),
        LABEL_IMAGE: image,
        LABEL_CONTAINER_WORKDIR: settings.container_workspace_dir,
        LABEL_VERSION: "v1",
    }
    if cfg.application_kind:
        labels[LABEL_APPLICATION_KIND] = cfg.application_kind
    if resolution.plugin_name:
        labels[LABEL_PLUGIN_NAME] = resolution.plugin_name
    if resolution.plugin_version:
        labels[LABEL_PLUGIN_VERSION] = resolution.plugin_version

    # Merge client-provided labels (e.g., owner) when present
    try:
        if request is not None:
            body = await request.json()
            extra_labels = body.get("labels") or {}
            if isinstance(extra_labels, dict):
                for k, v in extra_labels.items():
                    if isinstance(k, str) and isinstance(v, str):
                        labels[k] = v
    except Exception:
        # best-effort; ignore invalid or missing labels
        pass

    # Tie workspace to the creating client's API key suffix (server-controlled)
    try:
        api_suffix = _api_key_suffix_from_request(request, settings)
        if api_suffix:
            labels[LABEL_OWNER_API_KEY_SUFFIX] = api_suffix
    except Exception:
        # best-effort; do not fail workspace creation if suffix assignment fails
        pass

    run_kwargs: Dict[str, Any] = dict(
        name=name,
        hostname=app_impl.hostname(workspace_id),
        detach=True,
        environment=env,
        labels=labels,
        # Avoid restarts to prevent runaway container reuse past idle TTL
        restart_policy={"Name": "no"},
        # Keep default command/entrypoint from the image
    )
    if settings.network_mode:
        run_kwargs["network_mode"] = settings.network_mode
    platform = settings.docker_platform
    if platform:
        run_kwargs["platform"] = platform
    if cfg.ports:
        run_kwargs["ports"] = cfg.ports
    else:
        # Assign dynamic host ports for application-exposed container ports
        try:
            exp = app_impl.exposed_ports(settings) or {}
            if isinstance(exp, dict) and exp:
                bindings: Dict[str, object] = {}
                for _name, _p in exp.items():
                    try:
                        port_int = int(_p)
                        # Let Docker choose a random available host port for this container port
                        bindings[f"{port_int}/tcp"] = None
                    except Exception:
                        # Skip invalid port entries
                        continue
                if bindings:
                    run_kwargs["ports"] = bindings
        except Exception:
            # Best-effort; fallback to no explicit port bindings
            pass
    run_kwargs.update(settings.build_run_resource_kwargs())
    try:
        run_overrides = app_impl.docker_run_overrides(settings) or {}
        if isinstance(run_overrides, dict):
            run_kwargs.update(run_overrides)
    except Exception:
        # Ignore override errors to avoid breaking workspace creation
        pass
    try:
        app_impl.prepare_run(client, settings)
    except Exception as exc:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.warning("prepare_run hook failed for workspace %s: %s", workspace_id, exc)

    try:
        c = client.containers.run(image, **run_kwargs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start container: {e}")

    # Post-create setup (e.g., ensure workspace dir exists and fix ownership)
    try:
        app_impl.post_create_setup(c, settings)
    except Exception:
        # non-fatal
        pass

    # Wait for application readiness (optional)
    if wait_ready:
        await wait_for_app_ready(c, app_impl, timeout_s=1200)

    mark_last_used(workspace_id)
    plugin_ref = None
    if resolution.plugin_name:
        plugin_ref = m.PluginRef(name=resolution.plugin_name, version=resolution.plugin_version)
    return WorkspaceCreateResponse(
        workspace_id=workspace_id,
        status=WorkspaceState.running if wait_ready else WorkspaceState.starting,
        created_at=datetime.now(timezone.utc),
        application_plugin=plugin_ref,
    )


@router.delete(
    "/{workspace_id}",
    response_model=WorkspaceDeleteResponse,
)
async def delete_workspace(
    workspace_id: str = Path(...),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> WorkspaceDeleteResponse:
    """
    Kill and remove the workspace container, and ensure all attached anonymous or randomly-named volumes are removed.
    Raises HTTP 500 on any failure to remove the container or its volumes.
    """
    logger = __import__("logging").getLogger("workspace_manager")
    delete_started = time.monotonic()

    # Resolve container and enforce per-caller API key scoping
    try:
        c = get_container_by_workspace_id(client, workspace_id)
        api_suffix = _api_key_suffix_from_request(request, settings)
        if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
            # Hide existence details for unauthorized callers
            return WorkspaceDeleteResponse(workspace_id=workspace_id, status=WorkspaceState.deleted)
    except HTTPException:
        # Idempotent deletion: return deleted even if not found
        return WorkspaceDeleteResponse(workspace_id=workspace_id, status=WorkspaceState.deleted)

    # Collect names of attached named volumes prior to removal (to catch random-name volumes)
    try:
        c.reload()
    except Exception as e:
        logger.error(f"Failed to reload container state for {workspace_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to access container: {e}")

    mounts = (getattr(c, "attrs", {}) or {}).get("Mounts") or []
    attached_volume_names: list[str] = []
    try:
        for m in mounts:
            if isinstance(m, dict) and m.get("Type") == "volume":
                name = m.get("Name")
                if isinstance(name, str) and name:
                    attached_volume_names.append(name)
    except Exception as e:
        logger.error(f"Failed to parse container mounts for {workspace_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to inspect container mounts: {e}")

    # Skip graceful stop; directly send kill signal before removal for faster teardown.
    kill_error: Exception | None = None
    if (getattr(c, "status", "") or "") == "running":
        try:
            c.kill()
            logger.info(f"Container {workspace_id} kill signal issued before removal.")
        except Exception as e:
            kill_error = e
            logger.warning(f"Failed to kill container for {workspace_id}: {e}. Proceeding with force removal.")

    # Remove container and its anonymous (auto-created) volumes
    try:
        c.remove(force=True, v=True)
    except Exception as e:
        logger.error(f"Failed to remove container for {workspace_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove container: {e}")
    if kill_error is not None:
        logger.info(f"Container {workspace_id} force-removed after kill error: {kill_error}")

    # Explicitly remove attached named volumes with random names (excluding shared tools volume)
    tools_vol = settings.tools_volume_name
    for vol_name in attached_volume_names:
        if vol_name == tools_vol:
            continue
        try:
            vol = client.volumes.get(vol_name)
            vol.remove(force=True)
        except NotFound:
            # Volume already removed; it's safe to proceed
            continue
        except Exception as e:
            logger.error(f"Failed to remove volume '{vol_name}' for {workspace_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to remove volume '{vol_name}': {e}")

    clear_last_used(workspace_id)
    duration = time.monotonic() - delete_started
    logger.info(
        "Workspace %s deleted in %.2fs (volumes_removed=%d)",
        workspace_id,
        duration,
        len([v for v in attached_volume_names if v != tools_vol]),
    )
    return WorkspaceDeleteResponse(workspace_id=workspace_id, status=WorkspaceState.deleted)


@router.get(
    "",
    response_model=WorkspaceListResponse,
)
async def list_workspaces(
    owner: Optional[str] = Query(None, description="Filter managed workspaces by owner label"),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> WorkspaceListResponse:
    filters = {"label": [f"{LABEL_MANAGED}=true"]}
    if owner:
        filters["label"].append(f"{LABEL_OWNER}={owner}")
    # Scope results to the caller's API key suffix when auth is enabled
    api_suffix = _api_key_suffix_from_request(request, settings)
    if api_suffix:
        filters["label"].append(f"{LABEL_OWNER_API_KEY_SUFFIX}={api_suffix}")
    managed = client.containers.list(all=True, filters=filters)
    items: List[WorkspaceStatus] = []
    for c in managed:
        try:
            c.reload()
        except Exception as e:
            logger = __import__("logging").getLogger("workspace_manager")
            logger.error(f"Failed to reload container {getattr(c, 'name', '<unknown>')} while listing workspaces: {e}")
            # Continue building the list using best-effort container attributes.
        wsid = c.labels.get(LABEL_WORKSPACE_ID) if c.labels else None
        created_at_iso = c.labels.get(LABEL_CREATED_AT) if c.labels else None
        created_at = None
        if created_at_iso:
            try:
                created_at = datetime.fromisoformat(created_at_iso)
            except Exception:
                created_at = None
        state = WorkspaceState.running if c.status == "running" else WorkspaceState.stopped
        owner_label = c.labels.get(LABEL_OWNER) if c.labels else None
        items.append({
            "workspace_id": wsid or c.name,
            "status": state,
            "created_at": created_at or datetime.now(timezone.utc),
            "started_at": None,
            "last_used_at": datetime.fromtimestamp(get_last_used(wsid or c.name)) if (wsid or c.name) else None,
            "container_id": c.id,
            "image": c.labels.get(LABEL_IMAGE) if c.labels else None,
            "owner": owner_label,
            "application_plugin": _plugin_ref_from_labels(c.labels),
        })
    return WorkspaceListResponse(workspaces=items)


@router.get(
    "/{workspace_id}",
    response_model=WorkspaceStatus,
)
async def get_workspace(
    workspace_id: str = Path(...),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> WorkspaceStatus:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, settings)
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    try:
        c.reload()
    except Exception as e:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.error(f"Failed to reload container {workspace_id} for status query: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to access container: {e}")
    created_at = None
    if c.labels and c.labels.get(LABEL_CREATED_AT):
        try:
            created_at = datetime.fromisoformat(c.labels[LABEL_CREATED_AT])
        except Exception:
            created_at = None
    status_state = WorkspaceState.running if c.status == "running" else WorkspaceState.stopped
    owner_label = (c.labels or {}).get(LABEL_OWNER)
    return {
        "workspace_id": workspace_id,
        "status": status_state,
        "created_at": created_at or datetime.now(timezone.utc),
        "started_at": None,
        "last_used_at": datetime.fromtimestamp(get_last_used(workspace_id)),
        "container_id": c.id,
        "image": (c.labels or {}).get(LABEL_IMAGE),
        "owner": owner_label,
        "application_plugin": _plugin_ref_from_labels(c.labels),
    }


# --------------------------
# Routes: Exec
# --------------------------

@router.post(
    "/{workspace_id}/exec",
    response_model=ExecResult,
)
async def exec_command(
    workspace_id: str = Path(...),
    payload: ExecPayload = Body(...),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> ExecResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)

    # Resolve application for this container using label or image tag
    resolution = _application_resolution_for_container(c, settings)
    app_impl = resolution.application

    user = payload.user or app_impl.default_exec_user()
    cwd = payload.cwd or settings.container_workspace_dir
    env = payload.env_vars or {}

    # Wrap in sh -lc for shell semantics
    exec_cmd = ["sh", "-lc", payload.command]
    total_timeout = int(payload.timeout or 60)
    if total_timeout <= 0:
        total_timeout = 60
    deadline = time.monotonic() + total_timeout

    last_stdout = ""
    last_stderr = ""
    last_exit = 1
    success = False

    # Bounded retries within the caller-provided timeout budget to avoid early startup hiccups
    attempt = 0
    while time.monotonic() < deadline and attempt < 5:
        attempt += 1
        remaining = max(1, int(deadline - time.monotonic()))
        per_attempt_timeout = max(1, remaining)
        try:
            # Run the blocking docker exec in a worker thread with an async timeout
            res = await asyncio.wait_for(
                asyncio.to_thread(
                    c.exec_run,
                    exec_cmd,
                    user=user,
                    workdir=cwd,
                    environment=env,
                    demux=True,
                ),
                timeout=per_attempt_timeout,
            )
            last_exit = int(getattr(res, "exit_code", 1))
            stdout_b, stderr_b = (res.output if res and hasattr(res, "output") else (b"", b"")) if res else (b"", b"")
            last_stdout = stdout_b.decode("utf-8", errors="replace") if isinstance(stdout_b, (bytes, bytearray)) else ""
            last_stderr = stderr_b.decode("utf-8", errors="replace") if isinstance(stderr_b, (bytes, bytearray)) else ""
            success = (last_exit == 0)
            # Break on first successful completion or if no time remains
            if success or (time.monotonic() >= deadline):
                break
        except asyncio.TimeoutError:
            # Attempt timed out; loop again if time remains
            last_exit = 124
            last_stdout = last_stdout or ""
            last_stderr = last_stderr or "execution timed out"
            if time.monotonic() >= deadline:
                break
        except APIError as e:
            last_exit = 1
            last_stdout = last_stdout or ""
            last_stderr = f"docker exec failed: {e.explanation or str(e)}"
            status_code = getattr(e, "status_code", None)
            if status_code == 409 and time.monotonic() < deadline:
                logger = __import__("logging").getLogger("workspace_manager")
                logger.debug("exec_run conflict for %s (wsid=%s); retrying", command[:60], workspace_id)
                await asyncio.sleep(2)
                continue
            break

    mark_last_used(workspace_id)
    return ExecResult(stdout=last_stdout, stderr=last_stderr, exit_code=last_exit, success=success)


# --------------------------
# Routes: Filesystem
# --------------------------

@router.post(
    "/{workspace_id}/files/write",
    response_model=FileWriteResult,
)
async def write_file(
    workspace_id: str = Path(...),
    payload: m.WriteFilePayload = Body(...),
    client: DockerClient = Depends(docker_client),
    settings: ServiceConfig = Depends(get_settings),
    request: Request = None,
) -> FileWriteResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, settings)
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)
    p = payload.path
    # Ensure parent dir
    parent, base = os.path.split(p.rstrip("/"))
    parent = parent or "/"
    c.exec_run(["sh", "-lc", f"mkdir -p '{parent}'"], user="root")
    data = (payload.content or "").encode("utf-8")
    tar_stream = tar_from_bytes(base, data, mode=0o644)
    c.put_archive(parent, tar_stream.getvalue())
    mark_last_used(workspace_id)
    return FileWriteResult(path=p, bytes_written=len(data))


@router.get(
    "/{workspace_id}/files/read",
    response_model=FileReadResult,
)
async def read_file(
    workspace_id: str = Path(...),
    path: str = Query(..., description="Absolute path inside the container"),
    client: DockerClient = Depends(docker_client),
) -> FileReadResult:
    c = get_container_by_workspace_id(client, workspace_id)
    ensure_running(c)
    res = c.exec_run(["sh", "-lc", f"cat '{path}'"], demux=True)
    stdout_b, stderr_b = (res.output if res and hasattr(res, "output") else (b"", b"")) if res else (b"", b"")
    if int(getattr(res, "exit_code", 1)) != 0:
        raise HTTPException(status_code=404, detail=(stderr_b or stdout_b).decode("utf-8", errors="replace"))
    mark_last_used(workspace_id)
    return FileReadResult(content=stdout_b.decode("utf-8", errors="replace"))


@router.post(
    "/{workspace_id}/generate-upload-token",
)
async def generate_upload_token(
    workspace_id: str = Path(...),
    destination_path: str = Query(..., description="Absolute path inside the container"),
    ttl_seconds: Optional[int] = Query(None, description="Optional override for token TTL (seconds)"),
    settings: ServiceConfig = Depends(get_settings),
    request: Request = None,
):
    """
    Issue a short-lived, signed token for direct upload to a specific destination_path.
    Requires API key auth (router dependency).
    """
    # Import locally to keep top-level imports minimal and avoid cycles
    from wm_server.app.security import generate_upload_token_from_settings

    # Enforce presence of token secret in configuration; fail loudly on misconfiguration
    if not settings.token_secret_effective():
        raise HTTPException(
            status_code=500,
            detail="Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).",
        )

    token = generate_upload_token_from_settings(
        settings,
        workspace_id=workspace_id,
        destination_path=destination_path,
        ttl_seconds=ttl_seconds,
    )
    base_url = str(request.base_url).rstrip("/") if request is not None else ""
    upload_url = f"{base_url}/workspaces/{workspace_id}/files/copy-to"
    return {
        "upload_url": upload_url,
        "header": settings.upload_token_header_name,
        "query_param": settings.upload_token_query_param,
        "token": f"Bearer {token}",
        "expires_in": int(ttl_seconds if ttl_seconds is not None else settings.upload_token_ttl_seconds),
        "workspace_id": workspace_id,
        "destination_path": destination_path,
    }


@router.post(
    "/{workspace_id}/generate-download-token",
)
async def generate_download_token(
    workspace_id: str = Path(...),
    source_path: str = Query(..., description="Absolute path inside the container"),
    ttl_seconds: Optional[int] = Query(None, description="Optional override for token TTL (seconds)"),
    settings: ServiceConfig = Depends(get_settings),
    request: Request = None,
):
    """
    Issue a short-lived, signed token for direct download of a specific source_path.
    Requires API key auth (router dependency).
    """
    from wm_server.app.security import generate_download_token_from_settings

    # Enforce presence of token secret in configuration; fail loudly on misconfiguration
    if not settings.token_secret_effective():
        raise HTTPException(
            status_code=500,
            detail="Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).",
        )

    token = generate_download_token_from_settings(
        settings,
        workspace_id=workspace_id,
        source_path=source_path,
        ttl_seconds=ttl_seconds,
    )
    base_url = str(request.base_url).rstrip("/") if request is not None else ""
    download_url = f"{base_url}/workspaces/{workspace_id}/files/copy-from"
    return {
        "download_url": download_url,
        "header": settings.upload_token_header_name,
        "query_param": settings.upload_token_query_param,
        "token": f"Bearer {token}",
        "expires_in": int(ttl_seconds if ttl_seconds is not None else settings.upload_token_ttl_seconds),
        "workspace_id": workspace_id,
        "source_path": source_path,
    }


@router.post(
    "/{workspace_id}/files/copy-to",
    response_model=CopyToResponse,
)
async def copy_to(
    workspace_id: str = Path(...),
    file: UploadFile = File(...),
    destination_path: str = Query(..., description="Absolute path inside the container"),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> CopyToResponse:
    """
    Secure, efficient direct upload:
    - Requires a short-lived signed token (via header or query param).
    - Streams the uploaded file into a tar stream and into Docker via put_archive.
    """
    # Import locally to keep top-level imports minimal and avoid cycles
    from wm_server.app.security import (
        parse_and_verify_upload_token_from_settings,
        assert_token_matches_request,
        InvalidTokenError,
        TokenExpiredError,
    )

    # Enforce presence of token secret (service configuration)
    token_secret = settings.token_secret_effective()
    if not token_secret:
        raise HTTPException(
            status_code=500,
            detail="Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).",
        )

    # Extract token from configured header or query param
    header_name = settings.upload_token_header_name
    query_param = settings.upload_token_query_param
    provided = None
    if request is not None:
        provided = request.headers.get(header_name)
        if not provided:
            provided = request.query_params.get(query_param)

    if not provided:
        raise HTTPException(status_code=401, detail="Missing direct upload token.")

    token_str = provided.strip()
    if token_str.lower().startswith("bearer "):
        token_str = token_str[7:].strip()

    try:
        payload = parse_and_verify_upload_token_from_settings(settings, token=token_str)
        # Verify the token is scoped to this workspace and destination path
        assert_token_matches_request(payload, workspace_id=workspace_id, destination_path=destination_path)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Upload token expired.")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e) or "Invalid upload token.")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid upload token.")

    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, settings)
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)

    parent, base = os.path.split(destination_path.rstrip("/"))
    parent = parent or "/"
    c.exec_run(["sh", "-lc", f"mkdir -p '{parent}'"], user="root")

    filename = base or file.filename or "uploaded.bin"
    raw = file.file
    raw.seek(0, os.SEEK_END)
    size = raw.tell()
    raw.seek(0)
    tar_reader = stream_single_file_as_tar(filename, size, raw)
    c.put_archive(parent, tar_reader)
    # Ensure readable-by-others permissions for the uploaded file (best-effort)
    try:
        c.exec_run(["sh", "-lc", f"chmod 0644 '{destination_path}'"], user="root")
    except Exception as e:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.warning(f"Failed to chmod uploaded file '{destination_path}' in container {workspace_id}: {e}")
        # Non-fatal: continue, but surface the warning

    # App-specific post-copy adjustments
    resolution = _application_resolution_for_container(c, settings)
    app_impl = resolution.application
    try:
        app_impl.post_copy_adjust(c, destination_path, settings)
    except Exception as e:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.error(f"post_copy_adjust hook failed for '{destination_path}' in container {workspace_id}: {e}")
        # Surface the error to the caller: copying completed but post-copy adjustments failed.
        raise HTTPException(status_code=500, detail=f"Post-copy adjustment failed: {e}")
    mark_last_used(workspace_id)
    return CopyToResponse(destination_path=destination_path, status="copied")


@router.get(
    "/{workspace_id}/files/copy-from",
)
async def copy_from(
    workspace_id: str = Path(...),
    source_path: str = Query(..., description="Absolute path inside the container"),
    client: DockerClient = Depends(docker_client),
    settings: ServiceConfig = Depends(get_settings),
    request: Request = None,
):
    """
    Download a file or directory from the container.

    - For files: returns raw bytes (application/octet-stream).
    - For directories: returns a tar stream (application/x-tar).
    - Requires a short-lived download token (header or query param).
    """
    # Import locally to keep top-level imports minimal and avoid cycles
    from wm_server.app.security import (
        parse_and_verify_download_token_from_settings,
        assert_download_token_matches_request,
        InvalidTokenError,
        TokenExpiredError,
    )

    # Enforce presence of token secret (service configuration)
    token_secret = settings.token_secret_effective()
    if not token_secret:
        raise HTTPException(
            status_code=500,
            detail="Direct download token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).",
        )

    # Extract token from configured header or query param
    header_name = settings.upload_token_header_name
    query_param = settings.upload_token_query_param
    provided = None
    if request is not None:
        provided = request.headers.get(header_name)
        if not provided:
            provided = request.query_params.get(query_param)

    if not provided:
        raise HTTPException(status_code=401, detail="Missing direct download token.")

    token_str = provided.strip()
    if token_str.lower().startswith("bearer "):
        token_str = token_str[7:].strip()

    try:
        payload = parse_and_verify_download_token_from_settings(settings, token=token_str)
        assert_download_token_matches_request(payload, workspace_id=workspace_id, source_path=source_path)
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="Download token expired.")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e) or "Invalid download token.")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid download token.")

    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)

    # Determine if path is a directory
    is_dir_res = c.exec_run(["sh", "-lc", f"test -d '{source_path}'"], demux=True)
    is_dir = int(getattr(is_dir_res, "exit_code", 1)) == 0

    if is_dir:
        stream, _stat = c.get_archive(source_path.rstrip("/"))
        headers = {
            "Content-Disposition": f'attachment; filename="{os.path.basename(source_path.rstrip("/")) or "archive"}.tar"',
        }

        async def _aiter() -> AsyncIterator[bytes]:
            for chunk in stream:
                yield bytes(chunk)

        mark_last_used(workspace_id)
        return StreamingResponse(_aiter(), media_type="application/x-tar", headers=headers)

    # Pre-check the single file is readable to return a clean 404 on error
    check_res = c.exec_run(["sh", "-lc", f"test -r '{source_path}'"], demux=True, user="root")
    if int(getattr(check_res, "exit_code", 1)) != 0:
        stdout_b, stderr_b = (check_res.output if check_res and hasattr(check_res, "output") else (b"", b"")) if check_res else (b"", b"")
        # Prefer stderr when available; include a generic message if both are empty
        # Normalize potential None outputs; prefer stderr when available
        err_b = stderr_b if isinstance(stderr_b, (bytes, bytearray)) else (stderr_b or b"")
        out_b = stdout_b if isinstance(stdout_b, (bytes, bytearray)) else (stdout_b or b"")
        raw = err_b if err_b else out_b
        msg = (raw or b"").decode("utf-8", errors="replace").strip() or "File not found or not readable"
        raise HTTPException(status_code=404, detail=msg)

    # Stream file content via Docker get_archive and tar extraction to avoid exec I/O corner cases
    tar_stream, _stat = c.get_archive(source_path)
    _reader = reader_from_iterable(tar_stream)
    _tar = tarfile.open(fileobj=_reader, mode="r|*")
    _member = None
    for _m in _tar:
        if _m and _m.isreg():
            _member = _m
            break
    if _member is None:
        raise HTTPException(status_code=404, detail="File not found")
    _fobj = _tar.extractfile(_member)
    if _fobj is None:
        raise HTTPException(status_code=404, detail="File not found")

    headers = {
        "Content-Disposition": f'attachment; filename="{os.path.basename(source_path) or "file"}"',
    }
    # Content-Length intentionally omitted for streaming stability

    mark_last_used(workspace_id)
    async def _file_aiter() -> AsyncIterator[bytes]:
        while True:
            chunk = _fobj.read(64 * 1024)
            if not chunk:
                break
            yield bytes(chunk)

    return StreamingResponse(_file_aiter(), media_type="application/octet-stream", headers=headers)


@router.get(
    "/{workspace_id}/files/list",
    response_model=ListDirResult,
)
async def list_directory(
    workspace_id: str = Path(...),
    path: str = Query(..., description="Absolute directory path inside the container"),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> ListDirResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)
    res = c.exec_run(["sh", "-lc", f"ls -la '{path}' | tail -n +2"], demux=True)
    stdout_b, stderr_b = (res.output if res and hasattr(res, "output") else (b"", b"")) if res else (b"", b"")
    if int(getattr(res, "exit_code", 1)) != 0:
        raise HTTPException(status_code=404, detail=(stderr_b or stdout_b).decode("utf-8", errors="replace"))
    items = parse_ls_la(stdout_b.decode("utf-8", errors="replace"), base_path=path)
    mark_last_used(workspace_id)
    return ListDirResult(items=items)


@router.get(
    "/{workspace_id}/files/exists",
    response_model=ExistsResult,
)
async def file_exists(
    workspace_id: str = Path(...),
    path: str = Query(..., description="Absolute path inside the container"),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> ExistsResult:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    ensure_running(c)
    res = c.exec_run(["sh", "-lc", f"test -e '{path}'"], demux=True)
    exists = int(getattr(res, "exit_code", 1)) == 0
    mark_last_used(workspace_id)
    return ExistsResult(exists=exists)


@router.delete(
    "/{workspace_id}/files",
    response_model=ExistsResult,
)
async def delete_file(
    workspace_id: str = Path(...),
    path: str = Query(..., description="Absolute path inside the container"),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> ExistsResult:
    c = get_container_by_workspace_id(client, workspace_id)
    ensure_running(c)
    res = c.exec_run(["sh", "-lc", f"rm -rf '{path}'"], user="root", demux=True)
    ok = int(getattr(res, "exit_code", 1)) == 0
    mark_last_used(workspace_id)
    return ExistsResult(exists=not ok)


# Emulated discovery helpers (find/tree)

@router.get(
    "/{workspace_id}/fs/find",
)
async def fs_find(
    workspace_id: str = Path(...),
    base_path: str = Query(..., description="Base path to list under"),
    max_depth: int = Query(50, ge=1),
    limit: int = Query(500, ge=1),
    client: DockerClient = Depends(docker_client),
) -> List[str]:
    c = get_container_by_workspace_id(client, workspace_id)
    ensure_running(c)
    rels = emulate_find(client, c, base_path, limit=limit)
    mark_last_used(workspace_id)
    return rels


@router.get(
    "/{workspace_id}/fs/tree",
)
async def fs_tree(
    workspace_id: str = Path(...),
    base_path: str = Query(..., description="Base path to render as a tree"),
    limit: int = Query(2000, ge=1),
    client: DockerClient = Depends(docker_client),
) -> List[Dict[str, Any]]:
    c = get_container_by_workspace_id(client, workspace_id)
    ensure_running(c)
    rels = emulate_find(client, c, base_path, limit=limit)

    root_name = os.path.basename(base_path.rstrip("/")) or base_path.rstrip("/")
    root: Dict[str, Any] = {"type": "directory", "name": root_name, "path": base_path.rstrip("/"), "children": []}

    def insert(parts: List[str]) -> None:
        node: Dict[str, Any] = root
        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            nxt: Optional[Dict[str, Any]] = None
            for ch in node.get("children", []):
                if isinstance(ch, dict) and ch.get("name") == part:
                    nxt = ch
                    break
            if nxt is None:
                parent_path_val = node.get("path") or base_path.rstrip("/")
                parent_path = str(parent_path_val) if parent_path_val is not None else ""
                nxt = {
                    "type": "file" if is_last else "directory",
                    "name": part,
                    "path": f"{parent_path}/{part}" if parent_path else part,
                }
                if not is_last:
                    nxt["children"] = []
                children_val = node.setdefault("children", [])
                if isinstance(children_val, list):
                    children_val.append(nxt)
                else:
                    node["children"] = [nxt]
            node = nxt

    for rel in rels:
        parts = [p for p in rel.split("/") if p and p != "."]
        if parts:
            insert(parts)

    mark_last_used(workspace_id)
    return [root]


# --------------------------
# Routes: Checkpoints
# --------------------------

@router.post(
    "/{workspace_id}/checkpoints",
    response_model=CheckpointActionResponse,
)
async def create_checkpoint(
    workspace_id: str = Path(...),
    payload: CheckpointCreatePayload = Body(...),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
) -> CheckpointActionResponse:
    if not settings.enable_checkpoints:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Checkpoints are disabled on this server")
    c = get_container_by_workspace_id(client, workspace_id)
    try:
        checkpoint_create(client, c.id or "", payload.name, payload.exit, payload.checkpoint_dir)
        ok = True
    except Exception:
        ok = False
    mark_last_used(workspace_id)
    return CheckpointActionResponse(ok=ok)


@router.get(
    "/{workspace_id}/checkpoints",
    response_model=CheckpointListResponse,
)
async def list_checkpoints(
    workspace_id: str = Path(...),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
) -> CheckpointListResponse:
    if not settings.enable_checkpoints:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Checkpoints are disabled on this server")
    c = get_container_by_workspace_id(client, workspace_id)
    try:
        resp = checkpoint_list_raw(client, c.id or "")
        names: List[str] = []
        if isinstance(resp, dict) and "Checkpoints" in resp:
            for item in (resp.get("Checkpoints") or []):
                if isinstance(item, dict) and item.get("Name"):
                    names.append(item["Name"])
    except Exception:
        names = []
    mark_last_used(workspace_id)
    return CheckpointListResponse(checkpoints=names)


@router.delete(
    "/{workspace_id}/checkpoints/{name}",
    response_model=CheckpointActionResponse,
)
async def delete_checkpoint(
    workspace_id: str = Path(...),
    name: str = Path(...),
    checkpoint_dir: Optional[str] = Query(None),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
) -> CheckpointActionResponse:
    if not settings.enable_checkpoints:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Checkpoints are disabled on this server")
    c = get_container_by_workspace_id(client, workspace_id)
    try:
        checkpoint_delete(client, c.id or "", name, checkpoint_dir)
        ok = True
    except Exception as e:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.error(f"Failed to delete checkpoint '{name}' for {workspace_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete checkpoint: {e}")
    mark_last_used(workspace_id)
    return CheckpointActionResponse(ok=ok)


@router.post(
    "/{workspace_id}/start-from-checkpoint",
    response_model=CheckpointActionResponse,
)
async def start_from_checkpoint(
    workspace_id: str = Path(...),
    name: str = Query(..., min_length=1),
    checkpoint_dir: Optional[str] = Query(None),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
) -> CheckpointActionResponse:
    """
    Stop the workspace (if running) and start it from a given checkpoint.
    """
    if not settings.enable_checkpoints:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Checkpoints are disabled on this server")
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, settings)
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    try:
        c.reload()
        if c.status == "running":
            try:
                c.stop(timeout=30)
            except Exception as e:
                logger = __import__("logging").getLogger("workspace_manager")
                logger.error(f"Failed to stop container {workspace_id} before checkpoint restore: {e}")
                # This is a critical failure for the checkpoint restore flow; surface it.
                raise HTTPException(status_code=500, detail=f"Failed to stop container: {e}")
        docker_start_from_checkpoint(client, c.id or "", name, checkpoint_dir)
        ok = True
    except Exception as e:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.error(f"Failed to start from checkpoint '{name}' for {workspace_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to start from checkpoint: {e}")
    mark_last_used(workspace_id)
    return CheckpointActionResponse(ok=ok)


# --------------------------
# Routes: Logs
# --------------------------

@router.get(
    "/{workspace_id}/logs",
    response_model=LogsResponse,
)
async def get_logs(
    workspace_id: str = Path(...),
    tail: int = Query(100, ge=1, le=10000),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> LogsResponse:
    c = get_container_by_workspace_id(client, workspace_id)
    # Enforce per-caller API key scoping
    api_suffix = _api_key_suffix_from_request(request, get_settings())
    if api_suffix and (getattr(c, "labels", None) or {}).get(LABEL_OWNER_API_KEY_SUFFIX) != api_suffix:
        raise HTTPException(status_code=404, detail="Workspace not found")
    try:
        logs = c.logs(tail=tail)
        txt = logs.decode("utf-8", errors="replace") if isinstance(logs, (bytes, bytearray)) else str(logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get logs: {e}")
    mark_last_used(workspace_id)
    return LogsResponse(logs=txt)


# --------------------------
# Route: Application status
# --------------------------

@router.get(
    "/{workspace_id}/app/status",
    response_model=ApplicationStatus,
)
async def get_app_status(
    workspace_id: str = Path(...),
    settings: ServiceConfig = Depends(get_settings),
    client: DockerClient = Depends(docker_client),
    request: Request = None,
) -> ApplicationStatus:
    """
    Return standardized application status for the workspace using the application-specific
    implementation (e.g., Splunk). This avoids clients having to parse CLI output.
    """
    c = get_container_by_workspace_id(client, workspace_id)
    try:
        c.reload()
    except Exception as e:
        logger = __import__("logging").getLogger("workspace_manager")
        logger.error(f"Failed to reload container {workspace_id} while gathering app status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to access container: {e}")

    resolution = _application_resolution_for_container(c, settings)
    app_impl = resolution.application

    # Delegate to application-specific status reporter
    status = app_impl.get_status(c, settings)

    # If dynamic host ports were assigned, map app-exposed container ports to host ports for convenience.
    try:
        # Reload container attributes to inspect port mappings
        try:
            c.reload()
        except Exception as e:
            logger = __import__("logging").getLogger("workspace_manager")
            logger.error(f"Failed to reload container {workspace_id} while refreshing dynamic ports for app status: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to access container: {e}")

        ports = getattr(c, "attrs", {}).get("NetworkSettings", {}).get("Ports", {}) or {}
        host_port_map: Dict[str, int | None] = {}
        for key, binds in ports.items():
            if isinstance(binds, list) and binds:
                hp = binds[0].get("HostPort")
                try:
                    host_port_map[key] = int(hp) if hp is not None else None
                except Exception:
                    host_port_map[key] = None

        # Resolve app-exposed ports and translate to host ports when available
        exp = {}
        try:
            exp = app_impl.exposed_ports(settings) or {}
        except Exception:
            exp = {}

        def _host_for(container_port: int | None) -> int | None:
            if not container_port:
                return None
            return host_port_map.get(f"{int(container_port)}/tcp")

        # Override web/mgmt ports in status to the mapped host ports if present
        try:
            port_host = _resolve_port_proxy_host(settings)
            if "web" in exp:
                hp = _host_for(exp.get("web"))
                if hp:
                    status.web_port = hp
                    status.web_host = port_host
            if "mgmt" in exp:
                hp = _host_for(exp.get("mgmt"))
                if hp:
                    status.mgmt_port = hp
                    status.mgmt_host = port_host
        except Exception:
            # Best-effort: keep original values on any error
            pass
    except Exception:
        # Ignore mapping errors; return app-reported status as-is
        pass

    mark_last_used(workspace_id)
    return status
