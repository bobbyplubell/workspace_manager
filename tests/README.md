# Workspace Manager Integration Tests

This package contains black-box, real-integration tests for the WorkspaceManager service that spin up:
- A local FastAPI server (uvicorn) in a background thread
- Real Docker containers (Splunk Enterprise image) managed by the service API
- Real API calls only (no mocks)

The tests exercise common workflows:
- Create a "workspace" (a Splunk container) via the WorkspaceManager API
- Run Splunk CLI commands and REST calls (e.g., service status, oneshot searches with `| makeresults`)
- Copy files to/from the container workspace via the API
- Build a minimal Splunk app in the container, package it, and install via the Splunk CLI
- Verify via REST that the app is installed

These tests are intentionally end-to-end and require Docker to be available on the host.

---

## Prerequisites

- Python 3.10+
- A working Docker environment (Docker Desktop or dockerd) with access to the Docker socket from your user
- Internet access to pull the Splunk container image for the first run, unless already cached locally
- Sufficient memory allocated to Docker (the default test config requests ~2GiB per workspace)

Recommended one-time setup:
- Pre-pull the Splunk image to avoid long first-run delays:
  - `docker pull splunk/splunk:latest`
  - or set `SPLUNK_BASE_IMAGE` / `WORKSPACE_DEFAULT_IMAGE` to your preferred tag and pull that

---

## Running the tests

Run from the repository root to ensure pytest discovers all test packages and configuration:

- Run the entire integration suite for the workspace:
  - `pytest -m "integration and docker" workspace_manager/tests/integration -vv -s`

- Run a single test by keyword:
  - `pytest -m "integration and docker" -k app_package_and_install workspace_manager/tests/integration -vv -s`

These tests:
- Will be automatically skipped if Docker is not reachable
- Start an ephemeral WorkspaceManager service bound to a random free local port
- Use a temporary API key and set the service URL in process environment for the duration of the test
- Clean up the spawned container(s) at the end of the test best-effort

Pytest configuration highlights (see repo `pytest.ini`):
- Generous test timeouts are configured for slower image pulls and first-run Splunk initialization
- Registered markers include: `integration`, `docker`, `docker_env`, `e2e`, etc.

---

## Useful environment variables

Most are optional. The tests will set sensible defaults when needed.

- Docker / performance
  - `DOCKER_CLIENT_TIMEOUT` (default set by tests to 1200) – increase for slower registries or machines
  - `PYTEST_DOCKER_START_TIMEOUT` – optional, if using external pytest-docker setups
  - `WORKSPACE_JANITOR_INTERVAL_SECONDS` (default set very high by tests) – keep the janitor from tearing down active workspaces

- WorkspaceManager defaults (the service reads these)
  - `WORKSPACE_DEFAULT_IMAGE` or `SPLUNK_BASE_IMAGE` (default: `splunk/splunk:latest`)
  - `WORKSPACE_DEFAULT_CPU` (e.g., `1`, `2`) and `WORKSPACE_DEFAULT_MEM` (e.g., `2g`, `4g`)
  - `CONTAINER_WORKSPACE_DIR` (default: `/tmp/workspace`)
  - `DOCKER_PLATFORM` (optional; e.g., `linux/amd64` on Apple Silicon to force x86 images)

- Splunk
  - `SPLUNK_PASSWORD` (tests auto-populate a strong random value if unset; set explicitly when coordinating with other systems)

You generally do not need to set the service API variables yourself; the tests manage:
- `WORKSPACE_API_KEY`
- `WORKSPACE_API_KEY_HEADER`
- `WORKSPACE_API_URL`

---

## What these tests do not do

- They do not mock the API or Docker; everything uses the real Docker daemon and the live API surface.
- They do not require any external Splunk Cloud or remote services. All calls are local to the container.

Network note:
- The only external network access is pulling the Splunk image if it is not already cached locally.
- All other HTTP requests are to the local WorkspaceManager server (127.0.0.1).

---

## Troubleshooting

- Tests are skipped with a message like “Docker not available or not reachable”:
  - Ensure Docker is running and your user can access the Docker socket.
  - Try `docker info` and `docker pull splunk/splunk:latest` from the shell.

- Timeout waiting for Splunk readiness:
  - First-run of a fresh Splunk image can take several minutes.
  - Pre-pull the image and rerun the tests.
  - Increase `DOCKER_CLIENT_TIMEOUT` or `PYTEST_DOCKER_START_TIMEOUT`.

- Apple Silicon (M1/M2) issues:
  - Some Splunk images may run under emulation. Consider setting `DOCKER_PLATFORM=linux/amd64` before running tests.
  - Ensure Docker Desktop has adequate CPU/memory configured.

- Residual containers:
  - Tests clean up best-effort. If a test crashes, you can remove leftovers manually:
    - `docker ps -a --filter "label=splk.ws.managed=true"`
    - `docker rm -f <container_id>`

---

## CI considerations

These tests require:
- A Docker-enabled runner with enough memory/CPU
- Ability to pull container images (unless pre-cached)
- Extended timeouts for first-run image initialization

If you need to disable these tests in CI, filter out markers:
- `pytest -m "not (integration and docker)"`

---

## Contact

If you run into persistent issues with these tests:
- Verify Docker access and resource allocation
- Share the exact pytest invocation and the tail of the Splunk container logs if readiness fails
