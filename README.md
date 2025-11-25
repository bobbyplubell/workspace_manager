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
