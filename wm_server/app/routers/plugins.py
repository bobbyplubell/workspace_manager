from __future__ import annotations

"""
Administrative endpoints for inspecting WorkspaceManager plugins.
"""

from fastapi import APIRouter, Depends

from wm_server.app import models as m
from wm_server.app.deps import ServiceConfig, get_settings
from wm_server.app.plugins.manager import get_plugin_manager

router = APIRouter(prefix="/plugins", tags=["plugins"])


@router.get("", response_model=m.PluginListResponse)
async def list_plugins(settings: ServiceConfig = Depends(get_settings)) -> m.PluginListResponse:
    manager = get_plugin_manager(settings)
    plugins = [
        m.PluginSummary(
            name=meta.name,
            version=meta.version,
            api_version=meta.api_version,
            provides=list(meta.provides),
            description=meta.description,
            origin=meta.origin,
            config_schema=meta.config_schema,
        )
        for meta in manager.list_plugins()
    ]
    return m.PluginListResponse(plugins=plugins)


@router.get("/errors", response_model=m.PluginErrorsResponse)
async def list_plugin_errors(settings: ServiceConfig = Depends(get_settings)) -> m.PluginErrorsResponse:
    manager = get_plugin_manager(settings)
    errors = [
        m.PluginErrorInfo(
            name=err.name,
            origin=err.origin,
            error_type=err.error_type,
            message=err.message,
        )
        for err in manager.list_errors()
    ]
    return m.PluginErrorsResponse(errors=errors)
