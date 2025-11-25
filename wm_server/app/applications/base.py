from __future__ import annotations

"""
Base abstractions for the applications package.

This module provides:
- ApplicationCommand: a dataclass representing shell commands to be executed inside containers.
- ContainerApplication (ABC): an interface for application-specific container behavior.

Responsibilities:
- Define the contract for building environment variables, startup commands, readiness probes.
- Provide default hooks for container lifecycle customization (post-create, post-copy).
- Avoid framework coupling to keep logic portable and testable.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import asyncio
import logging
import time
from typing import Dict, List, Optional, Sequence

from docker import DockerClient
from docker.models.containers import Container

from wm_server.app.deps import ServiceConfig
from wm_server.app.models import WorkspaceConfig, ApplicationStatus


@dataclass(frozen=True)
class ApplicationCommand:
    """
    Represents a shell command to run inside the container.

    The expectation is that callers will wrap this with `sh -lc` to leverage shell
    semantics (env expansion, pipes, &&, etc.). This struct carries the desired
    user, working directory, and additional environment values to apply for that
    specific command invocation.
    """
    command: str
    user: Optional[str] = None
    workdir: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)

    def as_exec_argv(self) -> List[str]:
        """
        Return the command wrapped for POSIX shell execution.
        """
        return ["sh", "-lc", self.command]


class ContainerApplication(ABC):
    """
    Abstract interface for application-specific container behavior.
    Implementations should be idempotent and safe to re-run.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Human-friendly application name.
        """
        raise NotImplementedError

    @abstractmethod
    def default_image(self, settings: ServiceConfig) -> str:
        """
        Provide a default image for this application, used when the caller does not specify one.
        """
        raise NotImplementedError

    def default_cpu_limit(self, settings: ServiceConfig) -> str:
        """
        Provide a default CPU limit string for this application.
        Default: defer to service-level default_cpu_limit.
        """
        return settings.default_cpu_limit

    def default_mem_limit(self, settings: ServiceConfig) -> str:
        """
        Provide a default memory limit string for this application.
        Default: defer to service-level default_mem_limit.
        """
        return settings.default_mem_limit

    @abstractmethod
    def build_environment(self, cfg: WorkspaceConfig, settings: ServiceConfig) -> Dict[str, str]:
        """
        Construct environment variables for container creation. The result is merged with caller-provided env_vars.
        """
        raise NotImplementedError

    def validate_config(self, cfg: WorkspaceConfig, settings: ServiceConfig) -> None:
        """
        Application-specific validation hook. Implementations may raise ValueError when required parameters
        are missing from cfg.application_params or when other invariants are not met.
        """
        return

    def hostname(self, workspace_id: str) -> str:
        """
        Provide a hostname for the container. Subclasses can override for custom naming.
        """
        return f"ws-{workspace_id}"

    @abstractmethod
    def startup_commands(self, settings: ServiceConfig) -> Sequence[ApplicationCommand]:
        """
        Commands to run to initialize or (re)start the application process.
        These are intended to be idempotent and safe to re-run.
        """
        raise NotImplementedError

    @abstractmethod
    def readiness_probe(self, settings: ServiceConfig) -> ApplicationCommand:
        """
        Return a probe command that exits 0 when the application is ready to accept requests.
        Should be fast and side-effect free.
        """
        raise NotImplementedError

    def exposed_ports(self, settings: ServiceConfig) -> Dict[str, int]:
        """
        Declare application-specific container ports that should be exposed on the host.

        Return a mapping of logical names to container ports (e.g., {"web": 8000, "mgmt": 8089}).
        The router may assign dynamic host ports for these container ports and reflect them
        back in the WorkspaceStatus/ApplicationStatus response.

        Default: no explicit ports.
        """
        return {}

    def default_exec_user(self) -> str:
        """
        Return the default user to use when executing commands inside the container.
        Subclasses can override to provide application-specific defaults.
        """
        return "root"

    def post_create_setup(self, container: Container, settings: ServiceConfig) -> None:
        """
        Optional hook invoked right after container creation.
        Typical uses:
        - Create and chown workspace directory
        - Seed config files
        """
        # Default: ensure the workspace directory exists
        workdir = settings.container_workspace_dir
        container.exec_run(["sh", "-lc", f"mkdir -p '{workdir}'"], user="root", demux=True)

    def post_copy_adjust(self, container: Container, path: str, settings: ServiceConfig) -> None:
        """
        Optional hook invoked after copying files into the container.
        Default: no-op.
        """
        return

    def prepare_run(self, client: DockerClient, settings: ServiceConfig) -> None:
        """
        Optional hook executed before container creation to provision prerequisites (e.g., volumes).
        """
        return

    def docker_run_overrides(self, settings: ServiceConfig) -> Dict[str, object]:
        """
        Allow applications to override docker run kwargs (e.g., command/entrypoint).
        Default: no overrides.
        """
        return {}

    def get_status(self, container: Container, settings: ServiceConfig) -> ApplicationStatus:
        """
        Return a standardized application status for this workspace.

        Default implementation (generic):
        - running: True if Docker container status is 'running'
        - rest_ready: False (unknown)
        - provisioning: False (unknown)
        - status_text: 'running' or 'stopped'
        Implementations (e.g., Splunk) should override to provide richer, app-aware details.
        """
        try:
            container.reload()
            running = (container.status == "running")
        except Exception:
            running = False
        return ApplicationStatus(
            app_name=self.name,
            running=running,
            rest_ready=False,
            provisioning=False,
            provisioning_message=None,
            version=None,
            build=None,
            web_port=None,
            mgmt_port=None,
            status_text=("running" if running else "stopped"),
        )

    async def wait_for_ready(
        self,
        container: Container,
        settings: ServiceConfig,
        timeout_s: int,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Default readiness loop that relies on Docker healthchecks and the readiness_probe hook.
        """
        log = logger or logging.getLogger("workspace_manager")
        deadline = time.time() + max(1, timeout_s)
        next_log = time.time() + 5

        while time.time() < deadline:
            try:
                container.reload()
                if container.status not in ("created", "restarting", "running"):
                    raise RuntimeError(f"Container status is {container.status}")

                try:
                    health = (getattr(container, "attrs", {}) or {}).get("State", {}).get("Health", {}) or {}
                    if isinstance(health, dict) and health.get("Status") == "healthy":
                        return
                except Exception as exc:
                    log.debug("Readiness: healthcheck probe failed: %s", exc)

                probe = self.readiness_probe(settings)
                res = container.exec_run(
                    probe.as_exec_argv(),
                    user=probe.user or "root",
                    workdir=probe.workdir,
                    environment=probe.environment,
                    demux=True,
                )
                exit_code = int(getattr(res, "exit_code", 1))
                if exit_code == 0:
                    return
            except Exception as exc:
                log.debug("Readiness loop error: %s", exc)

            if time.time() >= next_log:
                try:
                    logs = container.logs(tail=200)
                    log.debug("[WorkspaceManager] container logs tail:\n%s", logs.decode("utf-8", errors="replace"))
                except Exception as exc:
                    log.debug("[WorkspaceManager] failed to tail container logs: %s", exc)
                next_log = time.time() + 10

            await asyncio.sleep(1)

        probe = self.readiness_probe(settings)
        res = container.exec_run(
            probe.as_exec_argv(),
            user=probe.user or "root",
            workdir=probe.workdir,
            environment=probe.environment,
            demux=True,
        )
        stdout_b, stderr_b = (res.output if res and hasattr(res, "output") else (b"", b"")) if res else (b"", b"")
        detail = (stderr_b or stdout_b).decode("utf-8", errors="replace")
        raise RuntimeError(f"Application did not become ready in {timeout_s}s: {detail}")


__all__ = [
    "ApplicationCommand",
    "ContainerApplication",
]
