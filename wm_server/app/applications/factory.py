from __future__ import annotations

"""
Application resolution helpers backed by the plugin system.

Legacy behavior (heuristic selection by image/kind) is preserved as a
fallback when plugins are disabled or unavailable.
"""

import os
from dataclasses import dataclass
from typing import Optional

from wm_server.app.applications.base import ContainerApplication
from wm_server.app.applications.generic import GenericContainerApplication
from wm_server.app.deps import ServiceConfig, get_settings
from wm_server.app.models import WorkspaceConfig
from wm_server.app.plugins.manager import get_plugin_manager


@dataclass(frozen=True)
class ApplicationResolution:
    application: ContainerApplication
    plugin_name: Optional[str] = None
    plugin_version: Optional[str] = None


def _legacy_resolve(image: Optional[str], kind: Optional[str]) -> ContainerApplication:
    """
    Legacy fallback when no plugins are available.
    """
    return GenericContainerApplication()


def resolve_application_with_metadata(
    image: Optional[str],
    kind: Optional[str] = None,
    cfg: Optional[WorkspaceConfig] = None,
    *,
    plugin_name: Optional[str] = None,
    settings: Optional[ServiceConfig] = None,
) -> ApplicationResolution:
    """
    Resolve a ContainerApplication and include the plugin metadata used.
    """
    settings = settings or get_settings()
    manager = get_plugin_manager(settings)
    cfg_obj = cfg or WorkspaceConfig()
    kind_hint = kind or cfg_obj.application_kind or os.getenv("WORKSPACE_APPLICATION_KIND") or None

    # Honor explicit plugin name labels when provided (e.g., existing workspaces).
    selected = manager.selection_by_name(plugin_name, settings) if plugin_name else None
    if selected:
        meta = selected.metadata
        return ApplicationResolution(selected.application, meta.name, meta.version)

    effective_image = image or cfg_obj.image or settings.default_image

    if settings.plugins_enabled:
        selection = manager.select_plugin(
            cfg=cfg_obj,
            image=effective_image,
            kind=kind_hint,
            settings=settings,
        )
        if selection:
            meta = selection.metadata
            return ApplicationResolution(selection.application, meta.name, meta.version)

    legacy_app = _legacy_resolve(effective_image, kind_hint)
    return ApplicationResolution(legacy_app, plugin_name="legacy_generic", plugin_version="0")


def resolve_application(image: Optional[str], kind: Optional[str] = None) -> ContainerApplication:
    """
    Backwards-compatible helper returning only the application implementation.
    """
    return resolve_application_with_metadata(image=image, kind=kind).application


__all__ = [
    "ApplicationResolution",
    "resolve_application",
    "resolve_application_with_metadata",
]
