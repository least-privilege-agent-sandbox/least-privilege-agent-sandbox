from __future__ import annotations

import shutil
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from least_privilege_agent_sandbox.policy import Policy

SPIFFE = "spiffe://ztap.test/agent/agent-7"


@pytest.fixture()
def workdir() -> Iterator[Path]:
    root = Path.cwd() / ".test-runs" / uuid.uuid4().hex
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def policy(workdir: Path) -> Policy:
    workspace = workdir / "workspace"
    workspace.mkdir()
    return Policy.from_dict(
        {
            "subjects": {
                SPIFFE: {
                    "allowed_tools": ["exec", "file.read", "http.get"],
                    "fs": {"read": [str(workspace)], "write": [str(workspace)]},
                    "executables": [sys.executable],
                    "network": ["127.0.0.1:18601", "example.com:443"],
                    "max_arg_bytes": 2048,
                }
            }
        }
    )


def write_policy_file(path: Path, workspace: Path, *, network: list[str] | None = None) -> Path:
    import yaml

    p = path / "policy.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "subjects": {
                    SPIFFE: {
                        "allowed_tools": ["exec", "file.read", "http.get"],
                        "fs": {"read": [str(workspace)], "write": [str(workspace)]},
                        "executables": [sys.executable],
                        "network": network or ["127.0.0.1:18601"],
                        "max_arg_bytes": 2048,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return p
