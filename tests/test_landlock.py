from __future__ import annotations

import shutil
import socket
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from least_privilege_agent_sandbox import landlock
from least_privilege_agent_sandbox.policy import Policy
from tests.conftest import SPIFFE

pytestmark = pytest.mark.integration


@pytest.fixture()
def landlock_workdir() -> Iterator[Path]:
    root = Path("/root/least-privilege-agent-sandbox-test-runs") / uuid.uuid4().hex
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _subject(workdir: Path, *, network: list[str] | None = None) -> object:
    workspace = workdir / "workspace"
    workspace.mkdir(exist_ok=True)
    policy = Policy.from_dict(
        {
            "subjects": {
                SPIFFE: {
                    "allowed_tools": ["exec"],
                    "fs": {"read": [str(workspace)], "write": [str(workspace)]},
                    "executables": [sys.executable],
                    "network": network or [],
                    "max_arg_bytes": 4096,
                    "require_kernel": True,
                }
            }
        }
    )
    return policy.require_subject(SPIFFE)


def test_landlock_filesystem_denials(landlock_workdir: Path) -> None:
    st = landlock.status()
    if not st.available:
        pytest.skip(st.reason)
    workdir = landlock_workdir
    workspace = workdir / "workspace"
    workspace.mkdir()
    ok = workspace / "ok.txt"
    ok.write_text("ok", encoding="utf-8")
    fake_home = workdir / "fake-home"
    fake_home.mkdir()
    creds = fake_home / "credentials.txt"
    creds.write_text("secret", encoding="utf-8")
    subject = _subject(workdir)

    allowed = landlock.run_restricted(
        subject, [sys.executable, "-c", f"print(open({str(ok)!r}).read())"]
    )
    assert allowed.returncode == 0, allowed.stderr

    denied = landlock.run_restricted(
        subject, [sys.executable, "-c", f"open({str(creds)!r}).read()"]
    )
    assert denied.returncode != 0

    write_denied = landlock.run_restricted(
        subject, [sys.executable, "-c", f"open({str(fake_home / 'new.txt')!r}, 'w').write('x')"]
    )
    assert write_denied.returncode != 0

    link = workspace / "link"
    try:
        link.symlink_to(creds)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    symlink_denied = landlock.run_restricted(
        subject, [sys.executable, "-c", f"open({str(link)!r}).read()"]
    )
    assert symlink_denied.returncode != 0


def test_landlock_network_denial(landlock_workdir: Path) -> None:
    st = landlock.status()
    if not st.available:
        pytest.skip(st.reason)
    if not landlock.network_supported():
        pytest.skip("Landlock network rules require ABI >= 4")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        subject = _subject(landlock_workdir, network=[])
        denied = landlock.run_restricted(
            subject,
            [
                sys.executable,
                "-c",
                "import socket,sys\ns=socket.socket();s.settimeout(1);s.connect(('127.0.0.1',"
                + str(port)
                + "))",
            ],
        )
        assert denied.returncode != 0
