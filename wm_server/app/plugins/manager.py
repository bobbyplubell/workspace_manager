from __future__ import annotations

"""
Plugin discovery and selection utilities.
"""

import importlib
import logging
from dataclasses import dataclass
from importlib import metadata
from typing import Dict, List, Optional, Sequence, Tuple

from wm_server.app.applications.generic import GenericContainerApplication
from wm_server.app.deps import ServiceConfig, get_settings
from wm_server.app.models import WorkspaceConfig
from wm_server.app.plugins import builtin
from wm_server.app.plugins.base import (
    ApplicationPlugin,
    PLUGIN_API_VERSION,
    PluginLoadError,
    PluginMetadata,
    PluginSelection,
)

_LOGGER = logging.getLogger("workspace_manager")
_PLUGIN_CACHE: Dict[Tuple[object, ...], "PluginManager"] = {}


@dataclass
class _LoadedPlugin:
    plugin: ApplicationPlugin
    metadata: PluginMetadata
    origin: str


def _lowered(items: Sequence[str]) -> List[str]:
    return [itm.strip().lower() for itm in items if isinstance(itm, str) and itm.strip()]


class PluginManager:
    """
    Discovers and manages ApplicationPlugin implementations.
    """

    def __init__(self, settings: ServiceConfig):
        self._settings = settings
        self._plugins: Dict[str, _LoadedPlugin] = {}
        self._load_errors: List[PluginLoadError] = []
        self._allow = set(_lowered(settings.plugin_allowlist))
        self._deny = set(_lowered(settings.plugin_denylist))
        self._load_plugins()

    # --------------------
    # Discovery / loading
    # --------------------

    def _load_plugins(self) -> None:
        # Builtins are always available.
        for plugin in builtin.builtin_plugins():
            self._register_plugin(plugin, origin="builtin")

        if not self._settings.plugins_enabled:
            return

        for group in self._settings.plugin_entrypoint_groups or []:
            self._load_entrypoint_group(group)

        for module_path in self._settings.plugin_modules or []:
            self._load_explicit_module(module_path)

    def _load_entrypoint_group(self, group: str) -> None:
        try:
            eps = metadata.entry_points()
            selected = eps.select(group=group) if hasattr(eps, "select") else []
        except Exception as exc:
            self._record_error(
                name=f"<group:{group}>",
                origin="entry_point",
                error=exc,
            )
            if self._settings.plugin_fail_fast:
                raise
            return

        for ep in selected:
            try:
                loaded = ep.load()
                plugin = self._coerce_plugin_instance(loaded)
                self._register_plugin(plugin, origin=f"entry_point:{group}")
            except Exception as exc:
                self._record_error(
                    name=getattr(ep, "name", "<unknown>"),
                    origin=f"entry_point:{group}",
                    error=exc,
                )
                if self._settings.plugin_fail_fast:
                    raise

    def _load_explicit_module(self, spec: str) -> None:
        spec = (spec or "").strip()
        if not spec:
            return
        if ":" not in spec:
            self._record_error(name=spec, origin="module", error=ValueError("Module spec must be module:ClassName"))
            if self._settings.plugin_fail_fast:
                raise ValueError("Invalid plugin module spec")
            return
        module_name, _, attr = spec.partition(":")
        try:
            module = importlib.import_module(module_name)
            target = getattr(module, attr)
            plugin = self._coerce_plugin_instance(target)
            self._register_plugin(plugin, origin=f"module:{module_name}")
        except Exception as exc:
            self._record_error(name=spec, origin="module", error=exc)
            if self._settings.plugin_fail_fast:
                raise

    @staticmethod
    def _coerce_plugin_instance(obj: object) -> ApplicationPlugin:
        if isinstance(obj, ApplicationPlugin):
            return obj
        if isinstance(obj, type) and issubclass(obj, ApplicationPlugin):
            return obj()
        if callable(obj):
            candidate = obj()
            if isinstance(candidate, ApplicationPlugin):
                return candidate
        raise TypeError(f"Object {obj} is not an ApplicationPlugin or factory.")

    def _register_plugin(self, plugin: ApplicationPlugin, origin: str) -> None:
        try:
            name = plugin.plugin_name().strip()
            if not name:
                raise ValueError("Plugin name cannot be empty")
            lowered = name.lower()
            if self._allow and lowered not in self._allow:
                return
            if lowered in self._deny:
                return
            if lowered in self._plugins:
                raise ValueError(f"Duplicate plugin name '{name}'")
            api_version = plugin.api_version().strip()
            if not api_version:
                raise ValueError("Plugin must declare api_version")
            if not self._is_api_compatible(api_version):
                raise ValueError(
                    f"Plugin {name} api_version {api_version} incompatible with WM {PLUGIN_API_VERSION}"
                )
            metadata = PluginMetadata(
                name=name,
                version=plugin.plugin_version(),
                api_version=api_version,
                provides=list(plugin.provides() or []),
                description=plugin.description(),
                origin=origin,
                config_schema=plugin.config_schema(),
            )
            self._plugins[lowered] = _LoadedPlugin(plugin=plugin, metadata=metadata, origin=origin)
        except Exception as exc:
            self._record_error(name=getattr(plugin, "plugin_name", lambda: "<unknown>")(), origin=origin, error=exc)
            if self._settings.plugin_fail_fast:
                raise

    @staticmethod
    def _is_api_compatible(plugin_version: str) -> bool:
        try:
            plugin_major = plugin_version.split(".", 1)[0]
            wm_major = PLUGIN_API_VERSION.split(".", 1)[0]
            return plugin_major == wm_major
        except Exception:
            return False

    def _record_error(self, name: str, origin: str, error: Exception) -> None:
        self._load_errors.append(
            PluginLoadError(
                name=name or "<unknown>",
                origin=origin,
                error_type=error.__class__.__name__,
                message=str(error),
            )
        )

    # --------------------
    # Public introspection
    # --------------------

    def list_plugins(self) -> List[PluginMetadata]:
        return [entry.metadata for entry in self._plugins.values()]

    def list_errors(self) -> List[PluginLoadError]:
        return list(self._load_errors)

    # --------------------
    # Selection
    # --------------------

    def select_plugin(
        self,
        cfg: WorkspaceConfig,
        *,
        image: Optional[str],
        kind: Optional[str],
        settings: ServiceConfig,
    ) -> PluginSelection:
        candidates: List[Tuple[int, _LoadedPlugin]] = []
        for entry in self._plugins.values():
            try:
                score = entry.plugin.match_score(image, kind, cfg, settings)
                if not isinstance(score, int) or score < 0:
                    score = 0
            except Exception as exc:
                self._record_error(entry.metadata.name, entry.origin, exc)
                score = 0
            candidates.append((score, entry))

        if candidates:
            candidates.sort(key=lambda item: (item[0], item[1].metadata.name))
            best_score, best = candidates[-1]
            if best_score > 0:
                app = best.plugin.get_application(settings)
                return PluginSelection(metadata=best.metadata, application=app, score=best_score)

        return self._legacy_fallback()

    def selection_by_name(
        self,
        name: Optional[str],
        settings: ServiceConfig,
    ) -> Optional[PluginSelection]:
        if not name:
            return None
        entry = self._plugins.get(name.strip().lower())
        if not entry:
            return None
        try:
            app = entry.plugin.get_application(settings)
        except Exception as exc:
            self._record_error(entry.metadata.name, entry.origin, exc)
            return None
        return PluginSelection(metadata=entry.metadata, application=app, score=0)

    @staticmethod
    def _legacy_fallback() -> PluginSelection:
        app = GenericContainerApplication()
        metadata = PluginMetadata(
            name="legacy_generic",
            version="0",
            api_version=PLUGIN_API_VERSION,
            provides=["generic"],
            description="Legacy heuristic fallback.",
            origin="legacy",
        )
        return PluginSelection(metadata=metadata, application=app, score=0)


def _manager_signature(settings: ServiceConfig) -> Tuple[object, ...]:
    return (
        settings.plugins_enabled,
        tuple(settings.plugin_entrypoint_groups or []),
        tuple(settings.plugin_modules or []),
        tuple(sorted(_lowered(settings.plugin_allowlist))),
        tuple(sorted(_lowered(settings.plugin_denylist))),
        settings.plugin_fail_fast,
    )


def get_plugin_manager(settings: Optional[ServiceConfig] = None) -> PluginManager:
    cfg = settings or get_settings()
    sig = _manager_signature(cfg)
    manager = _PLUGIN_CACHE.get(sig)
    if manager is None:
        manager = PluginManager(cfg)
        _PLUGIN_CACHE.clear()
        _PLUGIN_CACHE[sig] = manager
    return manager


__all__ = ["PluginManager", "get_plugin_manager"]
