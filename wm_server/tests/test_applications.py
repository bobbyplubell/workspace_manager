from __future__ import annotations

import os

import pytest

from wm_server.app.applications.factory import resolve_application, resolve_application_with_metadata


@pytest.mark.unit
def test_resolve_application_defaults_to_generic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WORKSPACE_APPLICATION_KIND", raising=False)
    app = resolve_application("docker.io/library/ubuntu:latest")
    assert app.name == "generic"


@pytest.mark.unit
def test_resolve_application_with_metadata_reports_generic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WORKSPACE_APPLICATION_KIND", raising=False)
    res = resolve_application_with_metadata("docker.io/library/ubuntu:22.04")
    assert res.plugin_name in {"generic_builtin", "legacy_generic"}
    assert res.application.name == "generic"
