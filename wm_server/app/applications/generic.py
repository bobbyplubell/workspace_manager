from __future__ import annotations

"""
Generic application implementation.

This module defines a conservative default ContainerApplication implementation
for non-Splunk images. It provides:
- No-op startup commands
- An always-ready readiness probe
- Root as the default exec user
- Environment passthrough from the WorkspaceConfig
"""

from typing import Dict, Sequence

from wm_server.app.applications.base import ApplicationCommand, ContainerApplication
from wm_server.app.deps import ServiceConfig
from wm_server.app.models import WorkspaceConfig


class GenericContainerApplication(ContainerApplication):
    """
    Conservative default for non-Splunk images.
    """

    @property
    def name(self) -> str:
        return "generic"

    def default_image(self, settings: ServiceConfig) -> str:
        # Fallback to whatever the service considers default
        return settings.default_image

    def build_environment(self, cfg: WorkspaceConfig, settings: ServiceConfig) -> Dict[str, str]:
        env: Dict[str, str] = {}
        env.update(cfg.env_vars or {})
        return env

    def startup_commands(self, settings: ServiceConfig) -> Sequence[ApplicationCommand]:
        # No-op startup by default
        return [ApplicationCommand(command="true")]

    def readiness_probe(self, settings: ServiceConfig) -> ApplicationCommand:
        # Always ready
        return ApplicationCommand(command="true", user="root")

    def default_exec_user(self) -> str:
        return "root"
    
    # post_create_setup inherited from base (mkdir -p on workspace dir)


__all__ = ["GenericContainerApplication"]