"""Disposable, network-isolated Docker lab runner."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import re
import shutil
import subprocess
from typing import TypeVar
import uuid

from .authorization import AuthorizationReport, ObjectAuthorizationAssessment
from .local_assessment import AssessmentReport, LocalAssessmentAgent
from .local_assessment import LocalHttpInventory
from .tool_broker import DockerExecAuthorizationProbe, DockerExecHttpToolBroker


class LabRunnerError(RuntimeError):
    pass


T = TypeVar("T")


class DockerLabRunner:
    IMAGE = "agentic-security-local-lab:0.1"

    def __init__(
        self,
        project_root: Path | None = None,
        docker_executable: str = "docker",
        command_timeout_seconds: float = 120.0,
    ) -> None:
        self.project_root = project_root or Path(__file__).resolve().parents[2]
        self.lab_directory = self.project_root / "lab"
        self.docker_executable = docker_executable
        self.command_timeout_seconds = command_timeout_seconds

    def run_assessment(
        self,
        agent: LocalAssessmentAgent,
        cors_profile: str = "safe",
        model_plan=None,
        model_analysis=None,
        model_summary=None,
    ) -> AssessmentReport:
        if cors_profile not in ("safe", "reflected-credentials"):
            raise LabRunnerError("Unsupported local CORS fixture profile")
        def assess(container_id: str) -> AssessmentReport:
            inventory = LocalHttpInventory()
            inventory.use_broker(
                DockerExecHttpToolBroker(
                    container_id,
                    ("/", "/robots.txt", "/openapi.json", "/health", "/cors-policy"),
                    docker_executable=self.docker_executable,
                    max_calls=5,
                )
            )
            return agent.run(
                target="http://127.0.0.1:8080",
                confirmed_local_lab=True,
                model_plan=model_plan,
                model_analysis=model_analysis,
                model_summary=model_summary,
                inventory=inventory,
            )

        return self._run_disposable_lab("LAB_CORS_PROFILE", cors_profile, assess)

    def run_authorization_assessment(
        self, authz_profile: str
    ) -> AuthorizationReport:
        if authz_profile not in ("safe", "broken-owner-check"):
            raise LabRunnerError("Unsupported local authorization fixture profile")

        def assess(container_id: str) -> AuthorizationReport:
            probe = DockerExecAuthorizationProbe(
                container_id,
                docker_executable=self.docker_executable,
            )
            return ObjectAuthorizationAssessment().run(probe)

        return self._run_disposable_lab(
            "LAB_AUTHZ_PROFILE",
            authz_profile,
            assess,
        )

    def _run_disposable_lab(
        self,
        environment_variable: str,
        profile: str,
        operation: Callable[[str], T],
    ) -> T:
        if shutil.which(self.docker_executable) is None:
            raise LabRunnerError("Docker executable is not available")
        if not (self.lab_directory / "Dockerfile").is_file():
            raise LabRunnerError(f"Local lab Dockerfile is missing from {self.lab_directory}")

        suffix = uuid.uuid4().hex[:12]
        network_name = f"agentic-lab-net-{suffix}"
        container_id: str | None = None
        try:
            self._docker("build", "--tag", self.IMAGE, str(self.lab_directory))
            self._docker("network", "create", "--internal", network_name)
            result = self._docker(
                "run",
                "--detach",
                "--rm",
                "--network",
                network_name,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=1m",
                "--label",
                "agentic-security.local-lab=true",
                "--label",
                f"agentic-security.run-id={suffix}",
                "--env",
                f"{environment_variable}={profile}",
                self.IMAGE,
            )
            container_id = result.stdout.strip()
            if not re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id):
                raise LabRunnerError("Docker returned an invalid container identifier")
            return operation(container_id)
        finally:
            cleanup_errors: list[str] = []
            if container_id is not None:
                error = self._docker_cleanup("stop", "--time", "2", container_id)
                if error is not None:
                    cleanup_errors.append(error)
            error = self._docker_cleanup("network", "rm", network_name)
            if error is not None:
                cleanup_errors.append(error)
            if cleanup_errors:
                raise LabRunnerError(
                    "Lab cleanup was incomplete: " + "; ".join(cleanup_errors)
                )

    def _docker(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                [self.docker_executable, *arguments],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.command_timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raise LabRunnerError(f"Docker command timed out: {arguments[0]}") from error
        except OSError as error:
            raise LabRunnerError(f"Could not run Docker: {type(error).__name__}") from error
        if result.returncode != 0:
            detail = result.stderr.strip()[:500] or f"exit code {result.returncode}"
            raise LabRunnerError(f"Docker {arguments[0]} failed: {detail}")
        return result

    def _docker_cleanup(self, *arguments: str) -> str | None:
        try:
            result = subprocess.run(
                [self.docker_executable, *arguments],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return f"Docker {arguments[0]} cleanup timed out"
        except OSError as error:
            return f"Docker {arguments[0]} cleanup failed ({type(error).__name__})"
        if result.returncode != 0:
            detail = result.stderr.strip()[:300] or f"exit code {result.returncode}"
            return f"Docker {arguments[0]} cleanup failed: {detail}"
        return None
