"""Tool runner and backend selection."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Literal

from least_privilege_agent_sandbox import bpf_loader, landlock
from least_privilege_agent_sandbox.audit_guard import AuditGuard
from least_privilege_agent_sandbox.policy import Policy, PolicyDeny

Backend = Literal["bpf-lsm", "landlock", "audit"]


@dataclass(frozen=True, slots=True)
class RunResult:
    backend: Backend
    returncode: int
    stdout: str
    stderr: str


def select_backend(*, require_kernel: bool = False) -> Backend:
    if bpf_loader.status().available:
        return "bpf-lsm"
    if landlock.status().available:
        return "landlock"
    if require_kernel:
        raise RuntimeError(
            "policy requires a kernel backend, but BPF LSM and Landlock are unavailable"
        )
    return "audit"


def run_tool(
    spiffe_id: str,
    tool: str,
    argv: list[str],
    *,
    policy: Policy,
    cwd: str | None = None,
    backend: Backend | None = None,
    timeout: float | None = 10.0,
) -> RunResult:
    subject = policy.require_subject(spiffe_id)
    decision = subject.first_denial_for_tool_call(tool, argv)
    if not decision.allowed:
        raise PolicyDeny(decision.reason)
    if not argv:
        raise ValueError("argv cannot be empty")
    exe_decision = subject.check_executable(argv[0])
    if not exe_decision.allowed:
        raise PolicyDeny(exe_decision.reason)
    selected = backend or select_backend(require_kernel=subject.require_kernel)
    if selected == "bpf-lsm":
        selected = "landlock" if landlock.status().available else "audit"
    if selected == "landlock":
        completed = landlock.run_restricted(subject, argv, cwd=cwd, timeout=timeout)
        return RunResult("landlock", completed.returncode, completed.stdout, completed.stderr)
    with AuditGuard(policy, spiffe_id):
        completed = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    return RunResult("audit", completed.returncode, completed.stdout, completed.stderr)


def executable_from_argv(argv: list[str]) -> str:
    if not argv:
        raise ValueError("argv cannot be empty")
    return os.fspath(argv[0])
