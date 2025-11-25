# workspace_manager

Lightweight container orchestration service used. Provides:
- FastAPI server (`wm_server`) to create/delete/list workspaces backed by Docker containers.
- Client library (`wm_client`)

## Installation via pip

Both components ship with their own `pyproject.toml`. To install either directly from
this git repository use pip's `subdirectory` support:

```bash
# Install the FastAPI server code
pip install "git+https://github.com/your-org/workspace_manager.git#subdirectory=wm_server"

# Install the Python client SDK
pip install "git+https://github.com/your-org/workspace_manager.git#subdirectory=wm_client"
```

For editable installs while developing locally you can similarly run
`pip install -e ./wm_server` or `pip install -e ./wm_client` from the repo root.

## Environment Variables

Both components prefer configuration through environment variables so they can run the same way in local development, CI, or production. The tables below list every variable understood by the repo along with its default.

### Client SDK (`wm_client`)

| Name | Default | Purpose |
| --- | --- | --- |
| `WORKSPACE_API_URL` | `https://127.0.0.1:8081` | Primary WorkspaceManager base URL. |
| `WM_BASE_URL` | _unset_ | Legacy alias for the base URL (used only when `WORKSPACE_API_URL` is missing). |
| `WORKSPACE_API_KEY` | _unset_ | API key sent with each request when the server enforces authentication. |
| `WORKSPACE_API_KEY_HEADER` | `X-API-Key` | Header name that carries the API key. |
| `WM_REQUEST_TIMEOUT` | `60` | Default HTTP timeout (seconds) for short requests such as `GET /health`. |
| `WM_EXEC_TIMEOUT` | `300` | Default timeout (seconds) when running `exec` commands. |
| `WM_CREATE_TIMEOUT` | `1200` | Default timeout (seconds) for `create_workspace(wait_ready=True)`. |
| `WM_FILE_TIMEOUT` | `120` | Default timeout (seconds) for file helpers (`read_file`, `write_file`, etc.). |
| `WM_VERIFY_TLS` | `true` | When `false`, TLS verification is disabled (requires `WM_ALLOW_INSECURE_TLS=true`). |
| `WM_ALLOW_INSECURE_HTTP` | `false` | Explicit opt-in to allow `http://` base URLs. |
| `WM_ALLOW_INSECURE_TLS` | `false` | Explicit opt-in to skip TLS verification. |
| `WM_MAX_FILE_TRANSFER_BYTES` | `1073741824` (1 GiB) | Hard cap applied to uploads/downloads initiated by the SDK. |
| `WORKSPACE_PUBLIC_BASE_URL` | _unset_ | Optional public URL you may hand to third parties instead of `base_url`. |
| `CONTAINER_WORKSPACE_DIR` | `/tmp/workspace` | Informational default working directory inside containers. |
| `SPLUNK_USERNAME` | _unset_ | Username consumed by `SplunkWorkspace`; must be provided for Splunk helpers. |
| `SPLUNK_PASSWORD` | _unset_ | Password consumed by `SplunkWorkspace`; required for Splunk helpers. |

### Server (`wm_server`)

#### Bootstrap & authentication

| Name | Default | Purpose |
| --- | --- | --- |
| `WM_SERVER_ENV_FILE` | `.env.server` | Optional dotenv file automatically loaded by `wm_server.app.main`. |
| `WORKSPACE_API_KEY` | _unset_ | Single API key accepted by the service (disables auth when empty). |
| `WORKSPACE_API_KEYS` | _unset_ | Comma-separated list of valid API keys (merged with `WORKSPACE_API_KEY`). |
| `WORKSPACE_API_KEY_HEADER` | `X-API-Key` | Header name used to read API keys from requests. |

#### Workspace defaults & metadata

| Name | Default | Purpose |
| --- | --- | --- |
| `WORKSPACE_DEFAULT_IMAGE` | `ubuntu:22.04` | Base Docker image when callers do not request one explicitly. |
| `WORKSPACE_DEFAULT_CPU` | `1c` | Default CPU limit; converted to Docker `nano_cpus`. |
| `WORKSPACE_DEFAULT_MEM` | `2g` | Default memory limit; converted to Docker `mem_limit`. |
| `WORKSPACE_NETWORK_MODE` | `none` | Docker network mode for newly created workspaces. |
| `CONTAINER_WORKSPACE_DIR` | `/tmp/workspace` | Directory inside each container treated as the working tree. |
| `WORKSPACE_APPLICATION_KIND` | _unset_ | Hint passed to the plugin resolver when requests omit `application_kind`. |
| `WORKSPACE_MANAGER_VERSION` | `0.1.0` | Version string exposed via the FastAPI metadata and `/health`. |
| `WORKSPACE_CONTAINER_PREFIX` | `wm_ws_` | Prefix applied to Docker container names created by the service. |
| `WORKSPACE_ENABLE_CHECKPOINTS` | `true` | Enables the checkpoint routes if the Docker daemon supports them. |
| `WORKSPACE_STOP_TIMEOUT_SECONDS` | `5` | Grace period before SIGKILL when stopping containers. |
| `WORKSPACE_IDLE_TTL_SECONDS` | `7200` | Maximum idle time (seconds) before the janitor removes a workspace. |
| `WORKSPACE_JANITOR_INTERVAL_SECONDS` | `3600` | Background janitor wakeup interval (minimum enforced: 10 seconds). |
| `WORKSPACE_TOOLS_VOLUME` | `wm_tools_cache` | Named Docker volume mounted by plugins that need shared tooling. |
| `WORKSPACE_PORT_PROXY_HOST` | auto-detected | Overrides the host/IP included in port-forwarding hints. |
| `CORS_ALLOW_ORIGINS` | `*` | Comma-separated list of allowed origins for the FastAPI CORS middleware. |

#### Docker & runtime

| Name | Default | Purpose |
| --- | --- | --- |
| `DOCKER_CLIENT_TIMEOUT` | `180` | Timeout (seconds) applied to Docker client operations at startup and runtime. |
| `DOCKER_PLATFORM` | _unset_ | Optional Docker platform override (for example `linux/amd64`). |
| `DOCKER_HOST` | Docker default | Standard Docker socket/URL; also used to infer the proxy host when applicable. |

#### Direct upload/download credentials

| Name | Default | Purpose |
| --- | --- | --- |
| `WORKSPACE_UPLOAD_TOKEN_SECRET` | `dev-upload-token-secret` | Symmetric secret used to mint short-lived upload/download tokens (override in production). |
| `WORKSPACE_UPLOAD_TOKEN_HEADER` | `Authorization` | Header name clients must use when presenting a generated token. |
| `WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM` | `token` | Alternate query parameter accepted when header delivery is not possible. |
| `WORKSPACE_UPLOAD_TOKEN_TTL_SECONDS` | `900` | Token lifetime (seconds) for generated upload/download credentials. |

#### Plugin system

| Name | Default | Purpose |
| --- | --- | --- |
| `WM_PLUGINS_ENABLED` | `true` | Master switch for the plugin-based application resolver. |
| `WM_PLUGINS_ENTRYPOINT_GROUPS` | `wm_server.app_plugins` | Entry-point groups inspected for plugins. |
| `WM_PLUGINS_MODULES` | _unset_ | Comma-separated list of Python modules to import for plugin registration. |
| `WM_PLUGINS_ALLOWLIST` | _unset_ | Limit plugin selection to the listed names. |
| `WM_PLUGINS_DENYLIST` | _unset_ | Exclude the listed plugin names. |
| `WM_PLUGINS_FAIL_FAST` | `false` | When `true`, fail server startup if plugin loading raises. |

#### Logging & diagnostics

| Name | Default | Purpose |
| --- | --- | --- |
| `LOG_LEVEL` | `INFO` | Baseline log level; used when `WM_LOG_LEVEL` is not provided. |
| `WM_LOG_LEVEL` | `INFO` | Preferred base log level for WorkspaceManager loggers. |
| `WM_LOG_FILE` | _unset_ | Absolute log-file path; highest precedence target for the rotating handler. |
| `WM_LOG_DIR` | _unset_ | Directory used when `WM_LOG_FILE` is unset (combined with `WM_LOG_NAME`). |
| `WM_LOG_NAME` | `<service_name>.log` | File name if the handler needs to pick/create a log file. |
| `WM_LOG_MAX_BYTES` | `10485760` (10 MB) | Max size of each log file before rotation. |
| `WM_LOG_BACKUP_COUNT` | `10` | Number of rotated files to keep. |
| `WM_CONSOLE` | `false` | `"1"`/`"true"` adds a console handler in addition to the file logger. |

## API Reference

See [API_REFERENCE.md](API_REFERENCE.md) for request/response details covering both the FastAPI surface and the Python client helpers.
