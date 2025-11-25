"""
Centralized constants for wm_client.

These constants provide shared defaults and well-known values used by the
WorkspaceManager Python client and its application helpers.
"""

from __future__ import annotations

# HTTP/API defaults
DEFAULT_API_KEY_HEADER = "X-API-Key"

# Splunk defaults
ENV_SPLUNK_USERNAME = "SPLUNK_USERNAME"
ENV_SPLUNK_PASSWORD = "SPLUNK_PASSWORD"
# No insecure fallback credentials are provided. Callers must explicitly supply them.
DEFAULT_SPLUNK_USERNAME = None
DEFAULT_SPLUNK_PASSWORD = None

# Splunk locations and paths inside the container
SPLUNK_DEFAULT_HOME = "/opt/splunk"
SPLUNK_TOOLS_BIN = "/opt/splunk-tools/bin"

# Common command environment prefix to ensure PATH is set up consistently
# for Splunk CLI and tools. Intended to be prepended to commands executed
# within a workspace container.
COMMAND_ENV_PREFIX = (
    f"SPLUNK_HOME=${{SPLUNK_HOME:-{SPLUNK_DEFAULT_HOME}}}; export SPLUNK_HOME; "
    f'export PATH="$SPLUNK_HOME/bin:/usr/local/bin:{SPLUNK_TOOLS_BIN}:$PATH"; '
)

# Splunk management (splunkd) and web defaults
SPLUNKD_SCHEME = "https"
SPLUNKD_HOST = "127.0.0.1"
SPLUNKD_PORT = 8089
SPLUNK_WEB_PORT = 8000

__all__ = [
    "DEFAULT_API_KEY_HEADER",
    "ENV_SPLUNK_USERNAME",
    "ENV_SPLUNK_PASSWORD",
    "DEFAULT_SPLUNK_USERNAME",
    "DEFAULT_SPLUNK_PASSWORD",
    "SPLUNK_DEFAULT_HOME",
    "SPLUNK_TOOLS_BIN",
    "COMMAND_ENV_PREFIX",
    "SPLUNKD_SCHEME",
    "SPLUNKD_HOST",
    "SPLUNKD_PORT",
    "SPLUNK_WEB_PORT",
]
