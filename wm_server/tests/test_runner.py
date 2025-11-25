from __future__ import annotations

import threading
import time

import pytest

from wm_server.app import runner


class _DummyConfig:
    def __init__(self, app, host, port, log_level):
        self.app = app
        self.host = host
        self.port = port
        self.log_level = log_level


def test_start_uvicorn_in_thread_reports_failure(monkeypatch):
    """
    If the uvicorn Server terminates before setting started=True (for example,
    due to a bind/permission error) the helper should raise so callers can abort.
    """

    class _CrashedServer:
        def __init__(self, config):
            self.config = config
            self.started = False
            self.should_exit = False

        def run(self):
            raise SystemExit(1)

    class _ThreadMock:
        def __init__(self, target=None, daemon=True):
            self._target = target
            self._alive = False
            self.daemon = daemon

        def start(self):
            self._alive = True
            try:
                if self._target:
                    self._target()
            except SystemExit:
                pass
            finally:
                self._alive = False

        def is_alive(self):
            return self._alive

        def join(self, timeout=None):
            return

    monkeypatch.setattr(runner.uvicorn, "Config", lambda *a, **kw: _DummyConfig(*a, **kw))
    monkeypatch.setattr(runner.uvicorn, "Server", lambda config: _CrashedServer(config))
    monkeypatch.setattr(runner, "threading", type("T", (), {"Thread": _ThreadMock}))

    with pytest.raises(RuntimeError):
        runner.start_uvicorn_in_thread(object(), host="127.0.0.1", port=9999, startup_timeout=0.3)


def test_start_uvicorn_in_thread_returns_running_server(monkeypatch):
    """
    Happy path: server reports started and remains alive long enough for the helper to return.
    """

    stop_event = threading.Event()

    class _HealthyServer:
        def __init__(self, config):
            self.config = config
            self.started = False
            self.should_exit = False

        def run(self):
            self.started = True
            while not stop_event.is_set():
                time.sleep(0.01)

    monkeypatch.setattr(runner.uvicorn, "Config", lambda *a, **kw: _DummyConfig(*a, **kw))
    monkeypatch.setattr(runner.uvicorn, "Server", lambda config: _HealthyServer(config))

    server, thread = runner.start_uvicorn_in_thread(
        object(),
        host="127.0.0.1",
        port=10000,
        startup_timeout=1.0,
    )

    assert server.started is True
    assert thread.is_alive()
    stop_event.set()
    thread.join(timeout=1)
    assert not thread.is_alive()
