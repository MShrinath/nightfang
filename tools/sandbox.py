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
from typing import Any, Dict, List, Optional, Set, Tuple


class SandboxMode(str, Enum):
    DOCKER = "DOCKER"
    SUBPROCESS_FALLBACK = "SUBPROCESS_FALLBACK"


# ---------------------------------------------------------------------------
# Command Allowlist
# ---------------------------------------------------------------------------

# Categories of commands permitted in the sandbox.
# Each entry maps a category name to a list of allowed command prefixes.
# A command is allowed if its executable name matches any entry in the
# category that is enabled via SandboxConfig.allow_categories.
COMMAND_ALLOWLIST: Dict[str, List[str]] = {
    "read_only": [
        "echo", "cat", "head", "tail", "wc", "sort", "uniq", "grep", "egrep", "fgrep",
        "find", "ls", "pwd", "stat", "file", "xxd", "hexdump", "strings", "od",
        "whoami", "id", "uname", "hostname", "ip", "ifconfig", "netstat",
        "env", "printenv", "date", "uptime", "df", "du", "ps", "top",
        "sha256sum", "sha1sum", "md5sum", "cksum",
        "nmap", "nslookup", "dig", "host", "traceroute", "ping",
        "curl", "wget", "httpx", "nikto",
        "sublist3r", "theHarvester", "amass", "dnsenum",
        "whois", "shodan", "censys",
        "git", "gh",
        "jq", "yq",
    ],
    "write_safe": [
        "mkdir", "touch", "cp", "mv", "chmod", "chown",
        "tee", "dd",
    ],
    "restricted": [
        "rm", "rmdir", "kill", "pkill",
        "iptables", "ufw",
    ],
}


def _command_name(command: str) -> str:
    """Extract the base command name from a shell command string using shlex parsing."""
    import shlex
    try:
        tokens = shlex.split(command)
    except ValueError:
        # Fallback: simple split on whitespace
        tokens = command.strip().split()
    if not tokens:
        return ""
    # Strip leading env assignments and shell builtins
    cmd = tokens[0]
    for prefix in ("sh", "bash", "/bin/sh", "/bin/bash"):
        if cmd == prefix and len(tokens) > 1:
            cmd = tokens[1]
            break
    return cmd


def check_command_allowlist(command: str, allowed_categories: Set[str]) -> Tuple[bool, str]:
    """Check whether a command is permitted by the allowlist.

    Returns (allowed, reason).
    """
    cmd_name = _command_name(command)
    if not cmd_name:
        return False, "Empty command"

    # Check basename (strip path)
    basename = os.path.basename(cmd_name)

    for category in allowed_categories:
        allowed_cmds = COMMAND_ALLOWLIST.get(category, [])
        if basename in allowed_cmds:
            return True, f"Allowed via category '{category}'"

    return False, f"Command '{basename}' not found in any allowed category: {allowed_categories}"


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
    # Command allowlist: set of category names to permit.
    # Default: read_only + write_safe (no destructive commands).
    allow_categories: Set[str] = field(
        default_factory=lambda: {"read_only", "write_safe"}
    )
    # When True, enforce the allowlist before execution.
    enforce_allowlist: bool = True
    # When True, verify artifact cleanup after each run.
    verify_cleanup: bool = True


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
        allow_categories: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Execute command inside the sandbox container (or fallback isolated subprocess).

        Returns a dict matching the tool_result schema:
        {
            "status": "SUCCESS" | "FAILED" | "TIMEOUT" | "ALLOWLIST_BLOCKED",
            "exit_code": int,
            "stdout": str,
            "stderr": str,
            "duration_ms": int,
            "mode": str,
            "allowlist_reason": str (only when blocked),
            "cleanup_verified": bool (only when verify_cleanup is enabled),
        }
        """
        effective_timeout = timeout or self.config.timeout_seconds

        # 1. Command Allowlist Check
        if self.config.enforce_allowlist:
            categories = allow_categories or self.config.allow_categories
            allowed, reason = check_command_allowlist(command, categories)
            if not allowed:
                return {
                    "status": "ALLOWLIST_BLOCKED",
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": reason,
                    "duration_ms": 0,
                    "mode": self.mode.value,
                    "allowlist_reason": reason,
                }

        # 2. Execute
        if self.mode == SandboxMode.DOCKER:
            result = self._run_docker(command, effective_timeout, env, host_mount_dir)
        else:
            result = self._run_subprocess(command, effective_timeout, env, host_mount_dir)

        # 3. Artifact Cleanup Verification
        if self.config.verify_cleanup:
            result["cleanup_verified"] = self._verify_cleanup(host_mount_dir)

        return result

    def _verify_cleanup(self, host_mount_dir: Optional[str]) -> bool:
        """Verify that temporary artifacts from the last run were cleaned up."""
        import glob
        if host_mount_dir and os.path.exists(host_mount_dir):
            leftovers = glob.glob(os.path.join(host_mount_dir, "nf_sandbox_*"))
            return len(leftovers) == 0
        leftovers = glob.glob(os.path.join(tempfile.gettempdir(), "nf_sandbox_*"))
        return len(leftovers) == 0

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
            # Parse command into tokens and execute with shell=False to prevent injection
            import shlex as _shlex
            try:
                cmd_tokens = _shlex.split(command)
            except ValueError:
                cmd_tokens = command.strip().split()
            if not cmd_tokens:
                raise ValueError("Empty command")

            # Windows shell builtins need cmd.exe /c wrapper when shell=False
            exec_tokens = list(cmd_tokens)
            if os.name == "nt" and cmd_tokens and cmd_tokens[0].lower() in (
                "echo", "dir", "type", "cls", "ver", "cd", "ren", "move", "copy", "del",
            ):
                exec_tokens = ["cmd.exe", "/c"] + exec_tokens

            proc = subprocess.run(
                exec_tokens,
                shell=False,
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

    # Test 1: Basic command execution
    res = sandbox.run("echo 'NIGHTFANG_SANDBOX_OK'", timeout=10)
    assert res["status"] == "SUCCESS", f"Execution failed: {res}"
    assert "NIGHTFANG_SANDBOX_OK" in res["stdout"], f"Output missing: {res}"
    print("  [PASS] Test 1: Command dispatch and output capture verified.")

    # Test 2: Timeout enforcement
    t_start = time.time()
    # Use a command that will run long enough to timeout
    # ping is in read_only allowlist; use it without shell redirects
    if os.name == "nt":
        sleep_cmd = "ping -n 5 127.0.0.1"
    else:
        sleep_cmd = "sleep 3"
    res_timeout = sandbox.run(sleep_cmd, timeout=1)
    duration = time.time() - t_start
    assert res_timeout["status"] == "TIMEOUT", f"Expected TIMEOUT, got: {res_timeout}"
    assert duration < 2.5, f"Timeout took too long: {duration}s"
    print("  [PASS] Test 2: Timeout guardrail properly terminated execution.")

    # Test 3: Command allowlist enforcement
    res_block = sandbox.run("rm -rf /", timeout=5)
    assert res_block["status"] == "ALLOWLIST_BLOCKED", f"Expected ALLOWLIST_BLOCKED, got: {res_block}"
    assert "rm" in res_block.get("allowlist_reason", ""), f"Expected rm in reason: {res_block}"
    print("  [PASS] Test 3: Command allowlist blocked destructive command (rm).")

    # Test 4: Allowed write command
    res_write = sandbox.run("mkdir nf_test_dir", timeout=10)
    assert res_write["status"] == "SUCCESS", f"Write command failed: {res_write}"
    print("  [PASS] Test 4: Allowed write command (mkdir) executed successfully.")

    # Test 5: Cleanup verification
    assert "cleanup_verified" in res, f"Expected cleanup_verified in result: {res}"
    print("  [PASS] Test 5: Artifact cleanup verification present.")

    print("\nAll Sandbox Runner self-tests PASSED successfully!")
    return True


if __name__ == "__main__":
    run_self_tests()
