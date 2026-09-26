from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from least_privilege_agent_sandbox import bpf_loader, landlock
from least_privilege_agent_sandbox.cli import main
from least_privilege_agent_sandbox.policy import Policy
from least_privilege_agent_sandbox.runner import select_backend
from tests.conftest import SPIFFE


@dataclass(frozen=True)
class _Status:
    available: bool
    abi: int = 0
    reason: str = "test"


def test_backend_selection_prefers_bpf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bpf_loader, "status", lambda: _Status(True))
    monkeypatch.setattr(landlock, "status", lambda: _Status(True, abi=3))
    assert select_backend() == "bpf-lsm"


def test_backend_selection_uses_landlock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bpf_loader, "status", lambda: _Status(False))
    monkeypatch.setattr(landlock, "status", lambda: _Status(True, abi=3))
    assert select_backend() == "landlock"


def test_backend_selection_fails_closed_when_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bpf_loader, "status", lambda: _Status(False))
    monkeypatch.setattr(landlock, "status", lambda: _Status(False))
    with pytest.raises(RuntimeError):
        select_backend(require_kernel=True)


def test_cli_requires_command() -> None:
    assert main(["run", "--policy", "p.yaml", "--svid", "s.pem", "--trust-bundle", "ca.pem"]) == 2


def test_cli_denies_bad_svid_path(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        'subjects:\n  "spiffe://ztap.test/agent/agent-7":\n    allowed_tools: []\n',
        encoding="utf-8",
    )
    assert (
        main(
            [
                "run",
                "--policy",
                str(policy),
                "--svid",
                str(tmp_path / "missing.pem"),
                "--trust-bundle",
                str(tmp_path / "missing-ca.pem"),
                "--",
                sys.executable,
            ]
        )
        != 0
    )


@pytest.mark.parametrize("require_kernel", [False, True])
def test_policy_require_kernel_flag_is_compiled(tmp_path: Path, require_kernel: bool) -> None:
    policy = Policy.from_dict(
        {
            "subjects": {
                SPIFFE: {
                    "allowed_tools": ["exec"],
                    "fs": {"read": [str(tmp_path)], "write": [str(tmp_path)]},
                    "executables": [sys.executable],
                    "network": [],
                    "require_kernel": require_kernel,
                }
            }
        }
    )
    assert policy.require_subject(SPIFFE).require_kernel is require_kernel
