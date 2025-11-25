from __future__ import annotations

"""
Applications package initializer.

This package re-exports the core application abstractions and implementations
from its submodules for convenient importing:

from wm_server.app.applications import (
    ApplicationCommand,
    ContainerApplication,
    GenericContainerApplication,
    SplunkContainerApplication,
)
"""

from wm_server.app.applications.base import ApplicationCommand, ContainerApplication
from wm_server.app.applications.generic import GenericContainerApplication

__all__ = [
    "ApplicationCommand",
    "ContainerApplication",
    "GenericContainerApplication",
]
