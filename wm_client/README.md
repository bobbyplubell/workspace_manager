# WorkspaceManager Python Client (wm_client)

A minimal Python SDK for interacting with the WorkspaceManager API (wm_server). This client wraps the REST endpoints exposed by the server and provides convenience helpers for common workflows, including Splunk-related operations.

This package is intended to be installed as a standalone dependency by applications and tests that need to manage or interact with WorkspaceManager workspaces.

## Features

- API key authentication via configurable header (defaults to `X-API-Key`)
- Workspace lifecycle: create, list, get, delete
- Remote command execution inside workspaces
- Filesystem operations: mkdir, read, write, copy to/from, list, exists, delete
- Discovery helpers: emulate find/tree
- Logs access
- Application status endpoint (`/app/status`)
- Splunk convenience helpers: start, status, and REST calls (via `curl` inside the container)

## Installation

From the wm_client directory:

    # Editable install (recommended for local development)
    pip install -e .

    # Or as a regular package install
    pip install .

If you’re working from the monorepo root and want tests to import the client package, install it first:

    cd workspace_manager/wm_client
    pip install -e .

Then run tests from the root (or `workspace_manager`) normally.

## Usage

Basic example:

    from wm_client import WorkspaceManagerClient

    client = WorkspaceManagerClient(
        base_url="http://127.0.0.1:8081",
        api_key="your-api-key",                    # optional; omit if server auth is disabled
        api_key_header_name="X-API-Key"            # optional; defaults to X-API-Key
    )

    # Create a new workspace (wait until the application is ready)
    ws = client.create_workspace(
        application_params={"splunk_password": "use-a-strong-password"},
        wait_ready=True,
        require_application_params=True,
    )
    wsid = ws.workspace_id  # or ws["workspace_id"] depending on model shape

    # Execute a command inside the workspace (as the default user)
    rc, out, err = client.exec(wsid, "echo hello")
    print(rc, out, err)

    # Filesystem operations
    client.mkdir(wsid, "/tmp/workspace/myapp", parents=True)
    client.write_file(wsid, "/tmp/workspace/myapp/README.txt", "hello world")
    content = client.read_file(wsid, "/tmp/workspace/myapp/README.txt")

    # Application status
    status = client.get_app_status(wsid)
    print(status)

    # Cleanup
    client.delete_workspace(wsid)

### Splunk helpers

    from wm_client import SplunkHelpers

    sh = SplunkHelpers(client)

    # Ensure Splunk started (idempotent)
    sh.splunk_start(wsid, timeout=600)

    # Check status text
    status_text = sh.splunk_status(wsid)
    print(status_text)

    # Call Splunk REST via curl inside the container
    http_status, body_text = sh.splunk_rest(
        wsid=wsid,
        method="GET",
        path="services/server/info",   # relative to https://127.0.0.1:8089/
        params={"output_mode": "json"},
        timeout=30,
    )
    print(http_status, body_text)

### Direct upload handoff (secure, streaming)

This client supports a secure handoff flow for direct uploads to a workspace without sharing the main API key with end clients. The flow:

1) Request short-lived credentials from the server:
    creds = client.get_direct_upload_credentials(
        workspace_id=wsid,
        destination_path="/tmp/workspace/uploads/package.tgz",  # must be absolute inside container
        ttl_seconds=900,  # optional; defaults to server setting
    )
    # Example structure:
    # {
    #   "upload_url": "http://127.0.0.1:8081/workspaces/<wsid>/files/copy-to",
    #   "header": "Authorization",
    #   "token": "Bearer <signed-token>",
    #   "expires_in": 900,
    #   "workspace_id": "<wsid>",
    #   "destination_path": "/tmp/workspace/uploads/package.tgz",
    # }

2) Perform the upload using either the SDK helper or a raw HTTP client.

- Using the SDK helper:
    ok = client.upload_file(
        workspace_id=wsid,
        destination_path="/tmp/workspace/uploads/package.tgz",
        local_path="./dist/package.tgz",
        auth_header_name=creds["header"],
        auth_header_value=creds["token"],    # e.g., "Bearer <signed-token>"
    )

- Using requests directly (example):
    import requests

    files = {"file": ("package.tgz", open("./dist/package.tgz", "rb"), "application/octet-stream")}
    r = requests.post(
        creds["upload_url"],
        params={"destination_path": "/tmp/workspace/uploads/package.tgz"},  # required
        headers={creds["header"]: creds["token"]},  # e.g., {"Authorization": "Bearer <signed-token>"}
        files=files,
        timeout=1200,
    )
    r.raise_for_status()

Notes:
- The token is short-lived and scoped to a specific workspace_id and destination_path.
- The server validates the token signature, expiry, and that the request matches the authorized path.
- Uploads are streamed efficiently to the container (no large server-side buffering).
- Even if the credential response contains a `query_param` hint, prefer headers; the SDK disallows placing tokens in URLs.

### Direct download handoff (secure, streaming)

This client also supports a secure handoff flow for direct downloads from a workspace without sharing the main API key with end clients.

1) Request short-lived credentials from the server:
    creds = client.get_direct_download_credentials(
        workspace_id=wsid,
        source_path="/tmp/workspace/uploads/package.tgz",  # must be absolute inside container
        ttl_seconds=900,  # optional; defaults to server setting
    )
    # Example structure:
    # {
    #   "download_url": "http://127.0.0.1:8081/workspaces/<wsid>/files/copy-from",
    #   "header": "Authorization",
    #   "token": "Bearer <signed-token>",
    #   "expires_in": 900,
    #   "workspace_id": "<wsid>",
    #   "source_path": "/tmp/workspace/uploads/package.tgz",
    # }

2) Perform the download using either the SDK helper or a raw HTTP client.

- Using the SDK helper:
    client.download_file(
        workspace_id=wsid,
        source_path="/tmp/workspace/uploads/package.tgz",
        local_path="./downloaded.tgz",
        auth_header_name=creds["header"],
        auth_header_value=creds["token"],    # e.g., "Bearer <signed-token>"
    )

- Using requests directly (example):
    import requests

    r = requests.get(
        creds["download_url"],
        params={"source_path": "/tmp/workspace/uploads/package.tgz"},  # required
        headers={creds["header"]: creds["token"]},  # e.g., {"Authorization": "Bearer <signed-token>"}
        stream=True,
        timeout=1200,
    )
    r.raise_for_status()
    with open("./downloaded.tgz", "wb") as f:
        for chunk in r.iter_content(chunk_size=128 * 1024):
            if not chunk:
                continue
            f.write(chunk)

Notes:
- The token is short-lived and scoped to a specific workspace_id and source_path.
- The server validates the token signature, expiration, and that the request matches the authorized path.
- Downloads are streamed efficiently from the container (no large server-side buffering).
- Even if the credential response contains a `query_param` hint, prefer headers; the SDK disallows placing tokens in URLs.

## API Overview

The public surface of the client is designed around high-level methods that map to server routes:

- Authentication/config:
  - Constructor accepts `base_url`, `api_key` (optional), and `api_key_header_name` (defaults to `X-API-Key`).

- Workspace lifecycle:
  - `create_workspace(application_params: dict | None = None, env_vars: dict | None = None, ports: dict | None = None, labels: dict | None = None, image: str | None = None, application_kind: str | None = None, wait_ready: bool = True, *, require_application_params: bool = False) -> WorkspaceCreateResponse`
    - `application_params` carries secrets/config (e.g., `{"splunk_password": "..."}`); set `require_application_params=True` when they are mandatory.
    - `image` and `application_kind` let callers override the server defaults (e.g., request the Aire workspace image).
  - `delete_workspace(workspace_id: str) -> WorkspaceDeleteResponse`
  - `list_workspaces(owner: str | None = None) -> WorkspaceListResponse`
  - `get_workspace(workspace_id: str) -> WorkspaceStatus`

- Exec:
  - `exec(workspace_id: str, command: str, user: str = "splunk", cwd: str | None = None, env_vars: dict | None = None, timeout: int = 300) -> tuple[int, str, str]`

- Filesystem:
  - `mkdir(workspace_id: str, path: str, parents: bool = True, mode: str | None = None) -> MkdirResult`
  - `write_file(workspace_id: str, path: str, content: str) -> FileWriteResult`
  - `read_file(workspace_id: str, path: str) -> FileReadResult`
  - `copy_to(workspace_id: str, local_path: str, dest_path: str) -> CopyToResponse`
  - `copy_from(workspace_id: str, source_path: str, local_path: str) -> None`
  - `list_dir(workspace_id: str, path: str) -> ListDirResult`
  - `exists(workspace_id: str, path: str) -> ExistsResult`
  - `delete_path(workspace_id: str, path: str) -> ExistsResult`
  - `fs_find(workspace_id: str, base_path: str, max_depth: int = 50, limit: int = 500) -> list[str]`
  - `fs_tree(workspace_id: str, base_path: str, limit: int = 2000) -> list[dict]`

- Logs:
  - `get_logs(workspace_id: str, tail: int = 100) -> LogsResponse`

- App status:
  - `get_app_status(workspace_id: str) -> ApplicationStatus`

- Splunk convenience:
  - `splunk_start(workspace_id: str, timeout: int = 600) -> None`
  - `splunk_status(workspace_id: str, timeout: int = 120) -> str`
  - `splunk_rest(workspace_id: str, method: str, path: str, params: dict | None = None, data: dict | None = None, timeout: int = 60) -> tuple[int, str]`

Return types (e.g., WorkspaceCreateResponse) may be dataclasses or Pydantic models, or raw dicts depending on the implementation. The intent is to provide ergonomic Python types while preserving raw fields returned by the server.

## Configuration

The client itself does not read environment variables directly, but you can pass equivalents to its constructor. Typically, the server is configured via its own environment (.env):

- Server expects (common keys):
  - WORKSPACE_API_KEY
  - WORKSPACE_API_KEY_HEADER (default: X-API-Key)

- For Splunk:
  - CONTAINER_WORKSPACE_DIR (default: /tmp/workspace)
  - WORKSPACE_DEFAULT_IMAGE (default: splunk/splunk:latest)
  - DOCKER_CLIENT_TIMEOUT, WORKSPACE_JANITOR_INTERVAL_SECONDS, etc.

In tests or apps, configure the client with:

- base_url: e.g., http://127.0.0.1:8081
- api_key: should match the server’s WORKSPACE_API_KEY if auth is enabled
- api_key_header_name: should match WORKSPACE_API_KEY_HEADER (defaults to X-API-Key)

## Compatibility

- Python >= 3.10
- Uses `requests` for HTTP calls
- Compatible with the WorkspaceManager server API described under `wm_server`.

## Contributing

- Keep the client surface area aligned with the server routes.
- Aim for synchronous methods returning user-friendly types while exposing enough server detail for diagnostics.
- Add small integration tests that spin up a local server where feasible.
- Avoid pulling in heavy dependencies.

## License

Apache-2.0 (or the license used by the parent project)
