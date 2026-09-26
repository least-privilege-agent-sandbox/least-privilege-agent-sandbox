from __future__ import annotations

import sys
from pathlib import Path

import pytest

from least_privilege_agent_sandbox.policy import Policy, PolicyDeny
from least_privilege_agent_sandbox.runner import executable_from_argv, run_tool, select_backend
from tests.conftest import SPIFFE


def test_runner_allows_simple_audit_command(policy: object) -> None:
    result = run_tool(
        SPIFFE,
        "exec",
        [sys.executable, "-c", "print('hello')"],
        policy=policy,  # type: ignore[arg-type]
        backend="audit",
    )
    assert result.backend == "audit"
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_runner_fails_closed_on_disallowed_tool(policy: object) -> None:
    with pytest.raises(PolicyDeny):
        run_tool(
            SPIFFE,
            "shell",
            [sys.executable, "-c", "print('hello')"],
            policy=policy,  # type: ignore[arg-type]
            backend="audit",
        )


def test_runner_helpers_and_denied_executable(policy: Policy, workdir: Path) -> None:
    selected = select_backend()
    assert selected in {"audit", "landlock", "bpf-lsm"}
    if selected == "audit":
        with pytest.raises(RuntimeError):
            select_backend(require_kernel=True)
    else:
        assert select_backend(require_kernel=True) in {"landlock", "bpf-lsm"}
    with pytest.raises(ValueError):
        executable_from_argv([])
    assert executable_from_argv(["python"]) == "python"
    bad = workdir / "bad.exe"
    bad.write_text("", encoding="utf-8")
    with pytest.raises(PolicyDeny):
        run_tool(SPIFFE, "exec", [str(bad)], policy=policy, backend="audit")
