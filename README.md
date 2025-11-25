# workspace_manager

Lightweight container orchestration service used. Provides:
- FastAPI server (`wm_server`) to create/delete/list workspaces backed by Docker containers.
- Client library (`wm_client`)

For Aire usage you typically:
1. Build the `aire-workspace` image.
2. Start `wm_server`.
3. Use `wm_client` (via `aire/workspace_tools`) to create a workspace and execute commands/files inside it.
