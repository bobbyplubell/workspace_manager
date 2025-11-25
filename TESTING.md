# Testing `workspace_manager`

Unit/integration tests live under `workspace_manager/tests`. They require Docker.

Typical runs:
```bash
# from repo root
pytest workspace_manager/tests
```

Notes:
- Tests spin up temporary containers; ensure Docker is available and you have permission to run it.
- Aire-specific tests expect `AIRE_WORKSPACE_IMAGE` to point to a built `aire-workspace` image:
  ```bash
  docker build --platform linux/amd64 -t aire-workspace -f workspace_manager/containers/aire/Dockerfile .
  AIRE_WORKSPACE_IMAGE=aire-workspace pytest workspace_manager/tests
  ```
