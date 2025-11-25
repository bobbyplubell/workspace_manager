from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from wm_server.app.applications.base import ApplicationCommand, ContainerApplication
from wm_server.app.deps import ServiceConfig
from wm_server.app.models import WorkspaceConfig
from wm_server.app.plugins.base import ApplicationPlugin, PLUGIN_API_VERSION


class TestHTTPApplication(ContainerApplication):
    """
    Simple HTTP container used for integration tests.
    """

    HTTP_PORT = 8080

    @property
    def name(self) -> str:
        return "test-http"

    def default_image(self, settings: ServiceConfig) -> str:
        return os.getenv("TEST_HTTP_IMAGE", "python:3.11-alpine")

    def build_environment(self, cfg: WorkspaceConfig, settings: ServiceConfig) -> Dict[str, str]:
        env = dict(cfg.env_vars or {})
        env.setdefault("TEST_HTTP_PORT", str(self.HTTP_PORT))
        env.setdefault("TEST_HTTP_HOST", "0.0.0.0")
        env.setdefault("WORKSPACE_DIR", settings.container_workspace_dir)
        return env

    def post_create_setup(self, container, settings: ServiceConfig) -> None:
        workdir = settings.container_workspace_dir
        container.exec_run(["sh", "-lc", f"mkdir -p '{workdir}'"], user="root", demux=True)
        # Write a small index.html served by the HTTP server.
        index_path = Path(workdir) / "index.html"
        body = "<html><body><h1>workspace-manager</h1></body></html>"
        container.exec_run(
            [
                "sh",
                "-lc",
                f"cat <<'EOF' > '{index_path}'\n{body}\nEOF\nchmod 644 '{index_path}'",
            ],
            user="root",
            demux=True,
        )

    def readiness_probe(self, settings: ServiceConfig) -> ApplicationCommand:
        # Use python to avoid curl dependency.
        script = (
            "python3 - <<'PY'\n"
            "import urllib.request\n"
            f"urllib.request.urlopen('http://127.0.0.1:{self.HTTP_PORT}/').read()\n"
            "PY"
        )
        return ApplicationCommand(command=script, user="root")

    def startup_commands(self, settings: ServiceConfig) -> List[ApplicationCommand]:
        return []

    def exposed_ports(self, settings: ServiceConfig) -> Dict[str, int]:
        return {"http": self.HTTP_PORT}

    def docker_run_overrides(self, settings: ServiceConfig) -> Dict[str, object]:
        workdir = settings.container_workspace_dir
        # keep container alive and run httpd in background
        script = (
            f"mkdir -p '{workdir}' && "
            f"python3 -u -m http.server {self.HTTP_PORT} --bind 0.0.0.0 --directory '{workdir}' & "
            "while true; do sleep 3600; done"
        )
        return {"command": ["/bin/sh", "-c", script]}


class TestHTTPPlugin(ApplicationPlugin):
    """
    Test-only plugin exporting the TestHTTPApplication.
    """

    def plugin_name(self) -> str:
        return "test_http_plugin"

    def plugin_version(self) -> str:
        return "0.0.test"

    def api_version(self) -> str:
        return PLUGIN_API_VERSION

    def description(self) -> str:
        return "Test HTTP application used by integration tests."

    def provides(self) -> List[str]:
        return ["test-http"]

    def match_score(
        self,
        image: Optional[str],
        kind: Optional[str],
        cfg: WorkspaceConfig,
        settings: ServiceConfig,
    ) -> int:
        hint = (kind or cfg.application_kind or "").strip().lower()
        if hint == "test-http":
            return 500
        img = (image or cfg.image or settings.default_image or "").lower()
        if "python" in img:
            return 300
        return 0

    def get_application(self, settings: ServiceConfig) -> TestHTTPApplication:
        return TestHTTPApplication()
