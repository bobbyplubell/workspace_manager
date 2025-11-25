from __future__ import annotations

"""
Plugin base interfaces and metadata helpers for WorkspaceManager.

The plugin model centers on ApplicationPlugin implementations that can
instantiate application-specific ContainerApplication subclasses.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Sequence, TYPE_CHECKING

from wm_server.app.applications.base import ContainerApplication

if TYPE_CHECKING:
    from wm_server.app.deps import ServiceConfig
    from wm_server.app.models import WorkspaceConfig


PLUGIN_API_VERSION = "1.0"


class ApplicationPlugin(ABC):
    """
    Contract for installable application plugins.

    Implementations should be import-safe (no lazy imports) and deterministic.
    """

    @abstractmethod
    def plugin_name(self) -> str:
        """
        Unique plugin identifier (stable across releases).
        """

    @abstractmethod
    def plugin_version(self) -> str:
        """
        Plugin package version string (semantic versioning recommended).
        """

    @abstractmethod
    def api_version(self) -> str:
        """
        Plugin API version supported by this plugin.
        """

    def description(self) -> Optional[str]:
        """
        Optional human-friendly description of capabilities.
        """
        return None

    def provides(self) -> Sequence[str]:
        """
        Application kinds serviced by this plugin (e.g., ["aire"]).
        """
        return []

    @abstractmethod
    def match_score(
        self,
        image: Optional[str],
        kind: Optional[str],
        cfg: "WorkspaceConfig",
        settings: "ServiceConfig",
    ) -> int:
        """
        Deterministic, non-negative suitability score for a request.
        0 indicates the plugin should not handle the request.
        """

    @abstractmethod
    def get_application(self, settings: "ServiceConfig") -> ContainerApplication:
        """
        Return a configured ContainerApplication implementation.
        """

    def config_schema(self) -> Optional[Dict[str, object]]:
        """
        Optional JSON schema (dict) describing supported application_params.
        """
        return None

    def exposed_ports(self, settings: "ServiceConfig") -> Dict[str, int]:
        """
        Optional helper for plugin-defined port exposure metadata.
        """
        try:
            app = self.get_application(settings)
            ports = app.exposed_ports(settings)
            return ports if isinstance(ports, dict) else {}
        except Exception:
            return {}


@dataclass(frozen=True)
class PluginMetadata:
    name: str
    version: str
    api_version: str
    provides: Sequence[str]
    description: Optional[str] = None
    origin: Optional[str] = None
    config_schema: Optional[Dict[str, object]] = None


@dataclass(frozen=True)
class PluginLoadError:
    name: str
    origin: str
    error_type: str
    message: str


@dataclass(frozen=True)
class PluginSelection:
    metadata: PluginMetadata
    application: ContainerApplication
    score: int


__all__ = [
    "ApplicationPlugin",
    "PLUGIN_API_VERSION",
    "PluginMetadata",
    "PluginLoadError",
    "PluginSelection",
]
