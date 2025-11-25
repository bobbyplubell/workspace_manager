# WorkspaceManager API Reference

This document captures the HTTP surface exposed by `wm_server` and the convenience methods shipped with the Python SDK (`WorkspaceManagerClient`). Every path listed below is rooted at the WorkspaceManager base URL (for example `https://127.0.0.1:8081`).

## Authentication

- Requests are authenticated with an API key supplied in the header named by `WORKSPACE_API_KEY_HEADER` (defaults to `X-API-Key`).
- Configure valid keys via `WORKSPACE_API_KEY` (single key) or `WORKSPACE_API_KEYS` (comma-separated list). Leave them unset to run the service without auth for local testing.

All client helpers accept either explicit credentials or default to environment variables loaded through `wm_client.config`.

```python
from wm_client import WorkspaceManagerClient

client = WorkspaceManagerClient(
    base_url="https://wm.example.test",
    api_key="super-secret",        # optional when the server doesn't enforce auth
    verify_tls=True,               # opt-out via env vars when testing self-signed certs
)
```

## Core REST endpoints

The client mirrors the server endpoints one-to-one. Timeout values shown below are defaults that can be overridden per call.

### Health

- **Endpoint:** `GET /health`
- **SDK:** `WorkspaceManagerClient.health(timeout=5)`
- **Response:** `{ "status": "ok", "service": "...", "version": "..." }`
- **Notes:** Unauthenticated; useful for readiness probes.

### Create workspace

- **Endpoint:** `POST /workspaces?wait_ready=true|false`
- **SDK:** `create_workspace(application_params=None, env_vars=None, ports=None, labels=None, image=None, application_kind=None, wait_ready=True, timeout=1200, require_application_params=False)`
- **Request body:** JSON with optional keys:
  - `application_params` – Arbitrary string map forwarded to the selected plugin; set `require_application_params=True` to enforce they are provided.
  - `env_vars` – Additional environment variables injected into the container.
  - `ports` – Mapping like `{ "8000/tcp": 8000 }`; the server validates ranges and reserved ports.
  - `labels` – Free-form metadata labels stored on the Docker container.
  - `image` – Override Docker image (defaults to `WORKSPACE_DEFAULT_IMAGE` server-side).
  - `application_kind` – Optional hint for plugin selection.
- **Response:** `{ "workspace_id": "...", "status": "running", "created_at": "...", "application_plugin": {...} }`
- **Notes:** When `wait_ready=true` (SDK default), the server waits until the target plugin reports readiness or fails. Non-success status codes propagate as `HTTPError`.

### List workspaces

- **Endpoint:** `GET /workspaces?owner=<api-key-suffix>`
- **SDK:** `list_workspaces(owner=None, timeout=60)`
- **Response:** `{ "workspaces": [ { "workspace_id": "...", "status": "...", "image": "...", ... } ] }`
- **Notes:** Pass `owner=<suffix>` to scope results to workspaces created via the same API key (the suffix is the last eight characters of the key, which the server attaches automatically).

### Retrieve workspace details

- **Endpoint:** `GET /workspaces/{workspace_id}`
- **SDK:** `get_workspace(workspace_id, timeout=30)`
- **Response:** `WorkspaceStatus` payload describing lifecycle timestamps, image, owner, and plugin metadata.

### Delete workspace

- **Endpoint:** `DELETE /workspaces/{workspace_id}`
- **SDK:** `delete_workspace(workspace_id, timeout=30)`
- **Response:** HTTP 200 with `{ "workspace_id": "...", "status": "deleted" }` when the container was removed, or `False` from the SDK when a 404 occurs (workspace already gone).

### Execute a command

- **Endpoint:** `POST /workspaces/{workspace_id}/exec`
- **SDK:** `exec(workspace_id, command, user="splunk", cwd=None, env_vars=None, timeout=300)`
- **Request body:** `{ "command": "sh -lc '...'", "user": "splunk", "cwd": "/tmp/workspace", "env_vars": { ... }, "timeout": 300 }`
- **Response:** `{ "stdout": "...", "stderr": "...", "exit_code": 0, "success": true }`
- **SDK return value:** `(exit_code, stdout, stderr)`
- **Notes:** The SDK automatically prepends a PATH bootstrapper so Splunk tools and helper binaries are available without the caller managing `PATH`.

## File management

### Create directories

- **Endpoint:** `POST /workspaces/{workspace_id}/files/mkdir`
- **SDK:** `mkdir(workspace_id, path, parents=True, mode=None, timeout=60)`
- **Request body:** `{ "path": "/abs/path", "parents": true, "mode": "755" }`
- **Response:** `{ "path": "/abs/path", "created": true }`

### Write a file

- **Endpoint:** `POST /workspaces/{workspace_id}/files/write`
- **SDK:** `write_file(workspace_id, path, content, timeout=60)`
- **Request body:** `{ "path": "/abs/path", "content": "text" }`
- **Response:** `{ "path": "/abs/path", "bytes_written": <int> }`

### Read a file

- **Endpoint:** `GET /workspaces/{workspace_id}/files/read?path=/abs/path`
- **SDK:** `read_file(workspace_id, path, timeout=60)`
- **Response:** `{ "content": "..." }` (SDK returns the string directly).
- **Validation:** Paths must be absolute; the SDK enforces this before calling the server.

## Direct transfer endpoints

Large transfers avoid proxying through FastAPI by using short-lived credentials. The SDK exposes a complete flow:

1. Call `get_direct_upload_credentials(workspace_id, destination_path, ttl_seconds=None, timeout=30)` which maps to `POST /workspaces/{workspace_id}/generate-upload-token`. The response includes `upload_url`, `header`, `query_param`, `token`, `expires_in`, and the target path.
2. Use `upload_file(...)` or `upload_bytes(...)` with the returned header/token to stream data directly. Both helpers enforce the `WM_MAX_FILE_TRANSFER_BYTES` limit (overridable per call).
3. For downloads, call `get_direct_download_credentials(...)` (`POST /workspaces/{workspace_id}/generate-download-token`) and then `download_file(...)` which streams the bytes to a local path while enforcing the same size limits.

Tokens are bearer-style strings that must be supplied via the provided header name. Query parameters are explicitly rejected by the SDK to prevent accidental credential leakage; use headers instead.

## Application status endpoint

- **Endpoint:** `GET /workspaces/{workspace_id}/app/status`
- **SDK:** `get_app_status(workspace_id, timeout=30)`
- **Response:** `{ "app_name": "...", "running": true, "rest_ready": false, "provisioning": true, "provisioning_message": "..." }`
- **Notes:** Each plugin decides how to populate these fields; clients can poll to drive dashboards without parsing CLI output.

## WorkspaceManagerClient convenience methods

| Method | Description |
| --- | --- |
| `base_url_normalized` | Property that strips trailing slashes to avoid duplicate separators. |
| `auth_headers()` | Returns `{header_name: api_key}` when credentials are configured. |
| `upload_file(...)` | Streams a local file to `/workspaces/{id}/files/copy-to`, enforcing file-size limits and optional bearer auth. |
| `upload_bytes(...)` | Same as `upload_file` but accepts in-memory bytes or file-like objects. |
| `download_file(...)` | Streams `/workspaces/{id}/files/copy-from` to a local path with the configured limits. |

All helper methods raise `requests.HTTPError` for non-success status codes (unless otherwise documented, e.g., `delete_workspace` returning `False` on 404). The SDK never mutates process environment variables; call `wm_client.config.get_settings().cache_clear()` if you need to re-read env vars mid-process.

## SplunkWorkspace helpers

The `wm_client.applications.splunk_workspace.SplunkWorkspace` helper wraps common Splunk workflows:

- **Initialization:** `SplunkWorkspace(client, splunk_username=None, splunk_password=None, verify_tls=None, run_as_user="splunk")`. Missing credentials fall back to `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`.
- **`splunk_status(workspace_id, timeout=120)`** – Runs `splunk status` and returns combined stdout/stderr.
- **`splunk_start(workspace_id, timeout=600)`** – Idempotently starts Splunk, waiting until the CLI reports `running`. Raises `RuntimeError` on failure or timeout.
- **`splunk_rest(workspace_id, method, path, params=None, data=None, timeout=60)`** – Executes a REST call via `curl` inside the container using a temporary netrc file. Returns `(status_code, body)`.

Use these helpers when managing Splunk-based workspaces so your tests do not have to recreate the boilerplate `exec` calls.
