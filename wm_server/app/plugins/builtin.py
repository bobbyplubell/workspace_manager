from __future__ import annotations

"""
Builtin application plugins shipped with WorkspaceManager.

These wrap the in-repo ContainerApplication implementations so they can
participate in the new plugin selection pipeline.
"""

from typing import List

from wm_server.app import __version__ as wm_version
from wm_server.app.applications.generic import GenericContainerApplication
from wm_server.app.deps import ServiceConfig
from wm_server.app.models import WorkspaceConfig
from wm_server.app.plugins.base import ApplicationPlugin, PLUGIN_API_VERSION


class GenericBuiltinPlugin(ApplicationPlugin):
    """
    Minimal builtin plugin to ensure WorkspaceManager always has a fallback.
    """

    def plugin_name(self) -> str:
        return "generic_builtin"

    def plugin_version(self) -> str:
        return wm_version

    def api_version(self) -> str:
        return PLUGIN_API_VERSION

    def description(self) -> str:
        return "Fallback generic container support."

    def provides(self) -> List[str]:
        return ["generic"]

    def match_score(
        self,
        image: str | None,
        kind: str | None,
        cfg: WorkspaceConfig,
        settings: ServiceConfig,
    ) -> int:
        return 1

    def get_application(self, settings: ServiceConfig) -> GenericContainerApplication:
        return GenericContainerApplication()


def builtin_plugins() -> List[ApplicationPlugin]:
    return [GenericBuiltinPlugin()]


__all__ = ["builtin_plugins"]
