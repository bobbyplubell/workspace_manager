"""
Application-specific helpers for wm_client.

Currently exported:
- SplunkWorkspace: helpers to interact with Splunk inside a WorkspaceManager workspace.

Usage:
    from wm_client.applications import SplunkWorkspace
"""

from .splunk_workspace import SplunkWorkspace

__all__ = ["SplunkWorkspace"]