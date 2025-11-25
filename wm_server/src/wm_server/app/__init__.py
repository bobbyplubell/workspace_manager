"""
WorkspaceManager (FastAPI) — README-lite

Overview
- This package provides a stateless, multi-tenant microservice that manages isolated
  workspaces for arbitrary applications via a plugin system, each backed by its own Docker container.
- It exposes a resource-oriented REST API that replaces direct Python calls to a Docker client.
- The service waits for application readiness (driven by the selected plugin) before returning from POST /workspaces.

Key Design Points
- Multi-tenant: every workspace_id maps to a unique container (no singletons).
- Stateless: no persistent session state is stored in the service; Docker is the source of truth.
- Resource limits: CPU/memory limits are defined by the application/service defaults (not client-provided).
- Security: API key authentication via a configurable HTTP header.
- Auto-cleanup: a background janitor loop removes idle workspaces after a configurable TTL.

Quickstart (local)
- Use a virtual environment in ./venv as per project conventions:
  1) From the workspace_manager directory:
     $ python -m venv ./venv
     $ source ./venv/bin/activate
     $ pip install -U pip
     $ pip install .
  2) Start the service (adjust host/port as needed):
     $ workspace-manager app.main:app --host 127.0.0.1 --port 8081
- Health check (unauthenticated):
  GET http://127.0.0.1:8081/health

Authentication
- Provide an API key in a header (defaults below):
  - Header name: X-API-Key (configurable via WORKSPACE_API_KEY_HEADER)
  - Header value: the token configured in WORKSPACE_API_KEY
- If WORKSPACE_API_KEY is unset, authentication is effectively disabled (accepts all requests).

Core Endpoints (summary)
- Workspace lifecycle:
  - POST /workspaces
    Request: { application_params?, env_vars?, ports?, labels? }
    Response: { workspace_id, status, created_at }
  - DELETE /workspaces/{workspace_id}
    Response: { workspace_id, status }
  - GET /workspaces
    Response: { workspaces: [ { workspace_id, status, created_at, last_used_at, container_id, image } ] }
  - GET /workspaces/{workspace_id}
    Response: { workspace_id, status, created_at, last_used_at, container_id, image }

- Command execution:
  - POST /workspaces/{workspace_id}/exec
    Request: { command, user?, cwd?, env_vars?, timeout? }
    Response: { stdout, stderr, exit_code, success }

- File operations:
  - POST /workspaces/{workspace_id}/files/write
    Request: { path, content }
    Response: { path, bytes_written }
  - GET /workspaces/{workspace_id}/files/read?path=/abs/path
    Response: { content }
  - POST /workspaces/{workspace_id}/files/copy-to (multipart/form-data)
    Auth: short-lived direct upload token via header (default: Authorization: Bearer <token>) or query param (default: token). Obtain via POST /workspaces/{workspace_id}/generate-upload-token.
    Form: file=<UploadFile>, destination_path=/abs/path
    Response: { destination_path, status:"copied" }
  - POST /workspaces/{workspace_id}/generate-upload-token
    Params: destination_path=/abs/path, ttl_seconds=<optional>
    Response: { upload_url, header, query_param, token, expires_in, workspace_id, destination_path }
    Env: WORKSPACE_UPLOAD_TOKEN_SECRET (required), WORKSPACE_UPLOAD_TOKEN_HEADER (default: Authorization), WORKSPACE_UPLOAD_TOKEN_QUERY_PARAM (default: token), WORKSPACE_UPLOAD_TOKEN_TTL_SECONDS (default: 900)
  - POST /workspaces/{workspace_id}/generate-download-token
    Params: source_path=/abs/path, ttl_seconds=<optional>
    Response: { download_url, header, query_param, token, expires_in, workspace_id, source_path }
  - GET /workspaces/{workspace_id}/files/copy-from?source_path=/abs/path
    Auth: short-lived direct download token via header (default: Authorization: Bearer <token>) or query param (default: token). Obtain via POST /workspaces/{workspace_id}/generate-download-token.
    Response: file bytes (application/octet-stream) or tar stream for directories
  - API key authentication
    - Header: WORKSPACE_API_KEY_HEADER (default: X-API-Key)
    - Keys: WORKSPACE_API_KEY (single) or WORKSPACE_API_KEYS (comma-separated) are accepted
    - Generate keys using a cryptographically secure source (e.g., Python: secrets.token_urlsafe(32))
  - GET /workspaces/{workspace_id}/files/list?path=/abs/dir
    Response: { items: [ { path, is_directory, size, permissions, owner, group } ] }
  - GET /workspaces/{workspace_id}/files/exists?path=/abs/path
    Response: { exists: bool }
  - DELETE /workspaces/{workspace_id}/files?path=/abs/path
    Response: { exists: bool }  # exists=false indicates successful deletion

- Discovery helpers (no external tools required):
  - GET /workspaces/{workspace_id}/fs/find?base_path=/abs/path&limit=500
    Response: [ "relative/subpath", ... ]
  - GET /workspaces/{workspace_id}/fs/tree?base_path=/abs/path&limit=2000
    Response: [ { type:"directory", name, path, children:[...] } ]

- Checkpoints (best-effort; depends on Docker daemon capabilities):
  - POST /workspaces/{workspace_id}/checkpoints
    Request: { name, exit?, checkpoint_dir? }
    Response: { ok: bool }
  - GET /workspaces/{workspace_id}/checkpoints
    Response: { checkpoints: [name, ...] }
  - DELETE /workspaces/{workspace_id}/checkpoints/{name}
    Response: { ok: bool }
  - POST /workspaces/{workspace_id}/start-from-checkpoint?name=checkpoint_name
    Response: { ok: bool }

- Logs:
  - GET /workspaces/{workspace_id}/logs?tail=100
    Response: { logs: "..." }

Environment Configuration (.env support)
- The service loads environment variables from workspace_manager/.env at startup (does not override existing process env). Only the following keys are consumed:
- WORKSPACE_API_KEY                # API key required to authenticate requests
- WORKSPACE_API_KEY_HEADER         # Header name, default "X-API-Key"
- WORKSPACE_DEFAULT_IMAGE          # Default Docker image for generic workspaces (default: "ubuntu:22.04")
- WORKSPACE_DEFAULT_CPU            # Default CPU limit (e.g., "1", "1.5", "2c")
- WORKSPACE_DEFAULT_MEM            # Default memory limit (e.g., "2g", "512m")
- CONTAINER_WORKSPACE_DIR          # Default working directory inside container (default: "/tmp/workspace")
- DOCKER_CLIENT_TIMEOUT            # Docker client timeout in seconds (default: 180)
- WORKSPACE_IDLE_TTL_SECONDS       # Idle TTL for auto-cleanup (default: 7200)
- WORKSPACE_CONTAINER_PREFIX       # Container name prefix (default: "wm_ws_")
- WORKSPACE_JANITOR_INTERVAL_SECONDS # Janitor sweep interval (default: 3600)
- CORS_ALLOW_ORIGINS               # Comma-separated list of allowed origins for CORS (default: "*")
- DOCKER_PLATFORM                  # Platform hint (default: "linux/amd64")
- WORKSPACE_MANAGER_VERSION        # Service version string for metadata
- LOG_LEVEL                        # Logging level (default: "INFO")
- WORKSPACE_ENABLE_CHECKPOINTS     # Enable Docker checkpoints endpoints (default: "true")
- WORKSPACE_TOOLS_VOLUME           # Named volume some plugins mount at /opt/tools (default: "wm_tools_cache")

Runtime Notes
- Readiness: The service waits for the selected plugin’s readiness criteria before returning from POST /workspaces.
- Docker access: The process must have permission to talk to the Docker daemon.
  On Linux, ensure the user is in the "docker" group or run with appropriate privileges.
- Checkpoints: Docker checkpoint features require CRIU support and daemon configuration.
  If not supported, checkpoint endpoints will simply return ok=false.
- Resource limits: The service applies application/service default CPU and memory limits, translating them to nano_cpus and mem_limit bytes for Docker.
- Multi-tenant isolation: Each workspace is a separate container. The service uses labels
  to identify and manage containers under its control.
- Cleanup: Idle containers are stopped/removed by a background janitor task based on last activity time.
- Compatibility: Endpoints cover functionality previously provided by the internal Docker client:
  command execution, file operations (read/write/copy), directory listing, file existence, checkpoints, and logs.

Development Workflow
- Activate ./venv for all local development and testing.
- Keep tests under tests/ (as per project rules).
- Avoid reading massive data files without limiting size (project guidance applies to data/).
- Follow the project’s import policy: do not lazy-load imports and do not wrap imports in try/except.

Version
- Matches pyproject: 0.1.0
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
