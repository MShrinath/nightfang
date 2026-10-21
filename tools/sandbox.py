#!/usr/bin/env python3
"""
NIGHTFANG Containerized Sandbox Runner (Executable Implementation)
Modeled after PentAGI's Docker Worker Sandbox (backend/pkg/docker/sandbox.go)
Reference Specification: integration/execution-policy-gateway.md §3 (Stage 6)

Provides isolated, containerized execution of security tools with strict resource
bounds (CPU, RAM, PIDs), read-only root filesystems, network isolation options,
and graceful fallback to a restricted subprocess sandbox when Docker is unavailable.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SandboxMode(str, Enum):
    DOCKER = "DOCKER"
    SUBPROCESS_FALLBACK = "SUBPROCESS_FALLBACK"


@dataclass
class SandboxConfig:
    image: str = "alpine:latest"
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    pids_limit: int = 100
    network_mode: str = "bridge"  # "bridge", "none", or custom network
    read_only_root: bool = True
    timeout_seconds: int = 60
    workdir: str = "/workspace"
    enable_fallback: bool = True


@dataclass
class SandboxProbeReport:
    daemon_reachable: bool
    mode: SandboxMode
    daemon_info: str = ""
    container_runtime: str = ""
    isolation_level: str = "HIGH"
    details: Dict[str, Any] = field(default_factory=dict)


class SandboxRunner:
    """
    Containerized tool dispatcher modeled after PentAGI's Docker runner.
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.mode = self._detect_mode()

    def _detect_mode(self) -> SandboxMode:
        """Probe Docker availability; fallback to subprocess if unavailable."""
        if shutil.which("docker") is not None:
            try:
                proc = subprocess.run(
                    ["docker", "info", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.returncode == 0:
                    return SandboxMode.DOCKER
            except Exception:
                pass

        if self.config.enable_fallback:
            return SandboxMode.SUBPROCESS_FALLBACK
        raise RuntimeError("Docker daemon is unreachable and fallback mode is disabled.")

    def probe(self) -> SandboxProbeReport:
        """Run diagnostic probe similar to PentAGI's sandbox_probe.sh."""
        if self.mode == SandboxMode.DOCKER:
            try:
                proc = subprocess.run(
                    ["docker", "version", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return SandboxProbeReport(
                    daemon_reachable=True,
                    mode=SandboxMode.DOCKER,
                    container_runtime="docker",
                    isolation_level="CONTAINER_ISOLATED",
                    daemon_info="Docker Engine (Daemon Active)",
                    details={"version_json": proc.stdout.strip()},
                )
            except Exception as e:
                return SandboxProbeReport(
                    daemon_reachable=False,
                    mode=SandboxMode.SUBPROCESS_FALLBACK,
                    isolation_level="LOCAL_PROCESS_RESTRICTED",
                    daemon_info=f"Docker probe failed: {e}",
                )

        return SandboxProbeReport(
            daemon_reachable=False,
            mode=SandboxMode.SUBPROCESS_FALLBACK,
            isolation_level="LOCAL_PROCESS_RESTRICTED",
            daemon_info="Docker CLI not found or daemon down; running in restricted subprocess sandbox",
        )

    def run(
        self,
        command: str,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        host_mount_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute command inside the sandbox container (or fallback isolated subprocess).
        Returns a dict matching the tool_result schema:
        {
            "status": "SUCCESS" | "FAILED" | "TIMEOUT",
            "exit_code": int,
            "stdout": str,
            "stderr": str,
            "duration_ms": int,
            "mode": str
        }
        """
        effective_timeout = timeout or self.config.timeout_seconds

        if self.mode == SandboxMode.DOCKER:
            return self._run_docker(command, effective_timeout, env, host_mount_dir)
        else:
            return self._run_subprocess(command, effective_timeout, env, host_mount_dir)

    def _run_docker(
        self,
        command: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
        host_mount_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        t0 = time.time()
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", self.config.network_mode,
            "--memory", self.config.memory_limit,
            f"--cpus={self.config.cpu_limit}",
            f"--pids-limit={self.config.pids_limit}",
            "--security-opt", "no-new-privileges:true",
        ]

        if self.config.read_only_root:
            docker_cmd.extend(["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        if host_mount_dir and os.path.exists(host_mount_dir):
            abs_mount = os.path.abspath(host_mount_dir).replace("\\", "/")
            docker_cmd.extend(["-v", f"{abs_mount}:{self.config.workdir}:rw"])
            docker_cmd.extend(["-w", self.config.workdir])

        if env:
            for k, v in env.items():
                docker_cmd.extend(["-e", f"{k}={v}"])

        docker_cmd.extend([self.config.image, "sh", "-c", command])

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration_ms = int((time.time() - t0) * 1000)
            status = "SUCCESS" if proc.returncode == 0 else "FAILED"
            return {
                "status": status,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "duration_ms": duration_ms,
                "mode": SandboxMode.DOCKER.value,
            }
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "TIMEOUT",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Sandbox container execution timed out after {timeout} seconds.",
                "duration_ms": duration_ms,
                "mode": SandboxMode.DOCKER.value,
            }
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "FAILED",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Docker runner execution error: {e}",
                "duration_ms": duration_ms,
                "mode": SandboxMode.DOCKER.value,
            }

    def _run_subprocess(
        self,
        command: str,
        timeout: int,
        env: Optional[Dict[str, str]] = None,
        host_mount_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Subprocess fallback running in an isolated temp directory with sanitized environment."""
        t0 = time.time()
        temp_dir = tempfile.mkdtemp(prefix="nf_sandbox_")
        work_dir = host_mount_dir if (host_mount_dir and os.path.exists(host_mount_dir)) else temp_dir

        # Sanitize environment: only permit essential system variables
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "SYSTEMDRIVE": os.environ.get("SYSTEMDRIVE", "C:"),
            "COMSPEC": os.environ.get("COMSPEC", ""),
            "PATHEXT": os.environ.get("PATHEXT", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "TEMP": temp_dir,
            "TMP": temp_dir,
        }
        if os.name != "nt":
            safe_env["HOME"] = temp_dir
            safe_env["USER"] = "sandbox"
        if env:
            safe_env.update(env)

        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=work_dir,
                env=safe_env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration_ms = int((time.time() - t0) * 1000)
            status = "SUCCESS" if proc.returncode == 0 else "FAILED"
            return {
                "status": status,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "duration_ms": duration_ms,
                "mode": SandboxMode.SUBPROCESS_FALLBACK.value,
            }
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "TIMEOUT",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Subprocess execution timed out after {timeout} seconds.",
                "duration_ms": duration_ms,
                "mode": SandboxMode.SUBPROCESS_FALLBACK.value,
            }
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            return {
                "status": "FAILED",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Subprocess runner error: {e}",
                "duration_ms": duration_ms,
                "mode": SandboxMode.SUBPROCESS_FALLBACK.value,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


def run_self_tests() -> bool:
    print("Running NIGHTFANG Sandbox Runner Self-Tests...")
    sandbox = SandboxRunner()
    probe = sandbox.probe()
    print(f"  [INFO] Detected mode: {probe.mode.value} | Isolation: {probe.isolation_level}")

    # Test basic command execution
    res = sandbox.run("echo 'NIGHTFANG_SANDBOX_OK'", timeout=10)
    assert res["status"] == "SUCCESS", f"Execution failed: {res}"
    assert "NIGHTFANG_SANDBOX_OK" in res["stdout"], f"Output missing: {res}"
    print("  [PASS] Test 1: Command dispatch and output capture verified.")

    # Test timeout enforcement
    t_start = time.time()
    # Cross-platform sleep command test
    sleep_cmd = "ping -n 3 127.0.0.1 >nul" if os.name == "nt" else "sleep 3"
    res_timeout = sandbox.run(sleep_cmd, timeout=1)
    duration = time.time() - t_start
    assert res_timeout["status"] == "TIMEOUT", f"Expected TIMEOUT, got: {res_timeout}"
    assert duration < 2.5, f"Timeout took too long: {duration}s"
    print("  [PASS] Test 2: Timeout guardrail properly terminated execution.")

    print("\nAll Sandbox Runner self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    run_self_tests()
