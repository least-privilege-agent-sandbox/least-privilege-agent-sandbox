from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from least_privilege_agent_sandbox.policy import Policy, PolicyDeny
from tests.conftest import SPIFFE


def test_policy_denies_by_default(policy: Policy) -> None:
    assert policy.subject_for("spiffe://example.org/agent/nope") is None
    with pytest.raises(PolicyDeny):
        policy.require_subject("spiffe://example.org/agent/nope")


def test_policy_allows_and_denies_core_operations(policy: Policy, workdir: Path) -> None:
    subject = policy.require_subject(SPIFFE)
    workspace = workdir / "workspace"
    allowed = workspace / "ok.txt"
    allowed.write_text("ok", encoding="utf-8")
    outside = workdir / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    assert subject.check_tool("exec").allowed
    assert not subject.check_tool("shell").allowed
    assert subject.check_path(allowed, "read").allowed
    assert subject.check_path(workspace / "sub" / ".." / "ok.txt", "read").allowed
    assert not subject.check_path(outside, "read").allowed
    assert subject.check_executable(sys.executable).allowed
    assert not subject.check_executable(os.fspath(outside)).allowed
    assert subject.check_network("example.com", 443).allowed
    assert not subject.check_network("evil.example", 443).allowed
    assert not subject.check_args_size(["x" * 3000]).allowed


def test_symlink_escape_resolves_to_target(policy: Policy, workdir: Path) -> None:
    subject = policy.require_subject(SPIFFE)
    workspace = workdir / "workspace"
    outside = workdir / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = workspace / "link"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert not subject.check_path(link, "read").allowed
