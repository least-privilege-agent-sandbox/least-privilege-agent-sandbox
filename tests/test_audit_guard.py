from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from least_privilege_agent_sandbox.audit_guard import AuditGuard, guarded_connect
from least_privilege_agent_sandbox.policy import PolicyDeny
from tests.conftest import SPIFFE, write_policy_file


def _run_child(code: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    src = str(Path.cwd() / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_audit_guard_denies_file_and_exec(workdir: Path) -> None:
    workspace = workdir / "workspace"
    workspace.mkdir()
    (workspace / "ok.txt").write_text("ok", encoding="utf-8")
    outside = workdir / "fake-home" / "credentials.txt"
    outside.parent.mkdir()
    outside.write_text("secret", encoding="utf-8")
    policy_path = write_policy_file(workdir, workspace)
    code = f"""
from least_privilege_agent_sandbox.audit_guard import AuditGuard
from least_privilege_agent_sandbox.policy import Policy, PolicyDeny
p = Policy.from_file({str(policy_path)!r})
with AuditGuard(p, {SPIFFE!r}):
    assert open({str(workspace / "ok.txt")!r}, encoding='utf-8').read() == 'ok'
    try:
        open({str(outside)!r}, encoding='utf-8').read()
        raise SystemExit('outside read allowed')
    except PolicyDeny:
        pass
    try:
        open({str(workdir / "bad.txt")!r}, 'w', encoding='utf-8').write('bad')
        raise SystemExit('outside write allowed')
    except PolicyDeny:
        pass
print('ok')
"""
    result = _run_child(code, workdir)
    assert result.returncode == 0, result.stderr + result.stdout
    assert result.stdout.strip() == "ok"


def test_audit_guard_denies_socket(workdir: Path) -> None:
    workspace = workdir / "workspace"
    workspace.mkdir()
    policy_path = write_policy_file(workdir, workspace, network=[])
    code = f"""
from least_privilege_agent_sandbox.audit_guard import AuditGuard, guarded_connect
from least_privilege_agent_sandbox.policy import Policy, PolicyDeny
p = Policy.from_file({str(policy_path)!r})
with AuditGuard(p, {SPIFFE!r}):
    try:
        guarded_connect('127.0.0.1', 9, timeout=0.05)
        raise SystemExit('connect allowed')
    except PolicyDeny:
        pass
print('ok')
"""
    result = _run_child(code, workdir)
    assert result.returncode == 0, result.stderr + result.stdout


def test_audit_guard_direct_coverage(policy: object, workdir: Path) -> None:
    workspace = workdir / "workspace"
    ok = workspace / "ok.txt"
    ok.write_text("ok", encoding="utf-8")
    outside = workdir / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    with AuditGuard(policy, SPIFFE):  # type: ignore[arg-type]
        assert ok.read_text(encoding="utf-8") == "ok"
        with pytest.raises(PolicyDeny):
            outside.read_text(encoding="utf-8")
        with pytest.raises(PolicyDeny):
            (workdir / "bad.txt").write_text("bad", encoding="utf-8")
        with pytest.raises(PolicyDeny):
            guarded_connect("127.0.0.1", 9, timeout=0.01)
