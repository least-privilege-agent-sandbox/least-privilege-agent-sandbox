"""Cooperative in-process guard built on Python audit hooks.

Python audit hooks are documented by the Python project as process-local event hooks. They are
useful for observing and cooperatively denying operations raised by CPython, but they run in the
guarded process and are not a security boundary against malicious native code.
"""

from __future__ import annotations

import contextvars
import os
import socket
import sys
from types import TracebackType
from typing import Any

from least_privilege_agent_sandbox.policy import Policy, PolicyDeny, SubjectPolicy

_CURRENT: contextvars.ContextVar[SubjectPolicy | None] = contextvars.ContextVar(
    "sandbox_subject", default=None
)
_INSTALLED = False


def install_audit_hook() -> None:
    global _INSTALLED
    if not _INSTALLED:
        sys.addaudithook(_audit_hook)
        _INSTALLED = True


class AuditGuard:
    def __init__(self, policy: Policy, spiffe_id: str) -> None:
        self._subject = policy.require_subject(spiffe_id)
        self._token: contextvars.Token[SubjectPolicy | None] | None = None

    def __enter__(self) -> AuditGuard:
        install_audit_hook()
        self._token = _CURRENT.set(self._subject)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._token is not None:
            _CURRENT.reset(self._token)


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    subject = _CURRENT.get()
    if subject is None:
        return
    if event == "open":
        _check_open(subject, args)
    elif event in {"os.remove", "os.unlink", "os.rmdir", "os.mkdir", "os.rename"}:
        for value in args[:2]:
            if isinstance(value, (str, bytes, os.PathLike)):
                _raise_if_denied(subject.check_path(os.fsdecode(value), "write"))
    elif event == "subprocess.Popen":
        executable = args[0]
        if isinstance(executable, (str, bytes, os.PathLike)):
            _raise_if_denied(subject.check_executable(os.fsdecode(executable)))
    elif event == "socket.connect" and len(args) >= 2:
        address = args[1]
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = address[0], address[1]
            if isinstance(host, str) and isinstance(port, int):
                _raise_if_denied(subject.check_network(host, port))


def _check_open(subject: SubjectPolicy, args: tuple[Any, ...]) -> None:
    if not args:
        return
    raw_path = args[0]
    if not isinstance(raw_path, (str, bytes, os.PathLike)):
        return
    path = os.fsdecode(raw_path)
    mode = args[1] if len(args) > 1 and isinstance(args[1], str) else "r"
    flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
    writing = any(ch in mode for ch in "wax+") or bool(
        flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    )
    _raise_if_denied(subject.check_path(path, "write" if writing else "read"))


def _raise_if_denied(decision: Any) -> None:
    if not decision.allowed:
        raise PolicyDeny(decision.reason)


def guarded_connect(host: str, port: int, timeout: float = 1.0) -> None:
    """Tiny helper used by tests and examples to trigger socket.connect audit events."""
    with socket.create_connection((host, port), timeout=timeout):
        return
