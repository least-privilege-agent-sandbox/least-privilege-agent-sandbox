"""Linux Landlock backend using ctypes syscalls."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import subprocess  # nosec B404 - argv is policy-checked and run without a shell.
import sys
from ctypes import c_int, c_uint64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from least_privilege_agent_sandbox.policy import PolicyDeny, SubjectPolicy

SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
PR_SET_NO_NEW_PRIVS = 38
O_PATH = getattr(os, "O_PATH", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

READ_FS = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
WRITE_FS = (
    READ_FS
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)
EXEC_FS = LANDLOCK_ACCESS_FS_EXECUTE | READ_FS
HANDLED_FS = WRITE_FS | LANDLOCK_ACCESS_FS_EXECUTE
HANDLED_NET = LANDLOCK_ACCESS_NET_CONNECT_TCP

libc: Any = ctypes.CDLL(None, use_errno=True) if sys.platform == "linux" else None
if libc is not None:
    libc.prctl.restype = c_int
    libc.prctl.argtypes = [c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


class RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", c_uint64),
        ("handled_access_net", c_uint64),
        ("scoped", c_uint64),
    ]


class PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", c_uint64), ("parent_fd", c_int)]


class NetPortAttr(ctypes.Structure):
    _fields_ = [("allowed_access", c_uint64), ("port", c_uint64)]


@dataclass(frozen=True, slots=True)
class LandlockStatus:
    available: bool
    abi: int
    reason: str


def abi_version() -> int:
    if sys.platform != "linux":
        return 0
    if libc is None:
        return 0
    ret = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    if ret < 0:
        return 0
    return int(ret)


def status() -> LandlockStatus:
    if sys.platform != "linux":
        return LandlockStatus(False, 0, "Landlock is Linux-only")
    abi = abi_version()
    if abi <= 0:
        err = ctypes.get_errno()
        return LandlockStatus(False, 0, os.strerror(err or errno.ENOSYS))
    return LandlockStatus(True, abi, f"Landlock ABI {abi}")


def run_restricted(
    subject: SubjectPolicy,
    argv: list[str],
    *,
    cwd: str | None = None,
    timeout: float | None = 10.0,
) -> subprocess.CompletedProcess[str]:
    if not argv:
        raise ValueError("argv cannot be empty")
    decision = subject.check_executable(argv[0])
    if not decision.allowed:
        raise PolicyDeny(decision.reason)
    st = status()
    if not st.available:
        raise RuntimeError(st.reason)
    return subprocess.run(  # nosec B603 - argv is validated against the subject policy first.
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        preexec_fn=lambda: apply_subject(subject),
    )


def apply_subject(subject: SubjectPolicy) -> None:
    st = status()
    if not st.available:
        raise OSError(st.reason)
    handled_net = HANDLED_NET if st.abi >= 4 else 0
    attr = RulesetAttr(HANDLED_FS, handled_net, 0)
    if st.abi >= 6:
        size = ctypes.sizeof(attr)
    elif st.abi >= 4:
        size = ctypes.sizeof(c_uint64) * 2
    else:
        size = ctypes.sizeof(c_uint64)
    fd = _syscall_fd(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        size,
        0,
    )
    try:
        _add_runtime_rules(fd)
        for prefix in subject.read_paths.prefixes:
            _add_ancestor_dir_rules(fd, prefix)
            _add_path_rule(fd, prefix, READ_FS)
        for prefix in subject.write_paths.prefixes:
            _add_ancestor_dir_rules(fd, prefix)
            _add_path_rule(fd, prefix, WRITE_FS)
        for exe in subject.executables:
            _add_path_rule(fd, exe, EXEC_FS)
        if handled_net:
            for matcher in subject.network:
                _add_net_rule(fd, matcher.port)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            _raise_errno("prctl(PR_SET_NO_NEW_PRIVS)")
        ret = libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0)
        if ret != 0:
            _raise_errno("landlock_restrict_self")
    finally:
        os.close(fd)


def network_supported() -> bool:
    return abi_version() >= 4


def _add_runtime_rules(ruleset_fd: int) -> None:
    candidates = [
        Path(sys.executable),
        Path("/usr"),
        Path("/lib"),
        Path("/lib64"),
        Path("/bin"),
        Path("/etc"),
    ]
    if platform.machine().lower() in {"aarch64", "arm64"}:
        candidates.extend([Path("/lib/aarch64-linux-gnu"), Path("/usr/lib/aarch64-linux-gnu")])
    else:
        candidates.extend([Path("/lib/x86_64-linux-gnu"), Path("/usr/lib/x86_64-linux-gnu")])
    for path in candidates:
        if path.exists():
            _add_path_rule(ruleset_fd, os.fspath(path), EXEC_FS)


def _add_ancestor_dir_rules(ruleset_fd: int, path: str) -> None:
    current = Path(path).resolve(strict=False)
    if current.is_file():
        current = current.parent
    for parent in reversed(current.parents):
        if os.fspath(parent) == os.sep:
            continue
        if parent.exists():
            _add_path_rule(ruleset_fd, os.fspath(parent), LANDLOCK_ACCESS_FS_READ_DIR)


def _add_path_rule(ruleset_fd: int, path: str, allowed: int) -> None:
    flags = O_PATH | O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return
    try:
        if not os.path.isdir(path):
            allowed &= ~(
                LANDLOCK_ACCESS_FS_READ_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_CHAR
                | LANDLOCK_ACCESS_FS_MAKE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_REG
                | LANDLOCK_ACCESS_FS_MAKE_SOCK
                | LANDLOCK_ACCESS_FS_MAKE_FIFO
                | LANDLOCK_ACCESS_FS_MAKE_BLOCK
                | LANDLOCK_ACCESS_FS_MAKE_SYM
            )
        attr = PathBeneathAttr(allowed, fd)
        ret = libc.syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(attr),
            0,
        )
        if ret != 0:
            _raise_errno(f"landlock_add_rule({path})")
    finally:
        os.close(fd)


def _add_net_rule(ruleset_fd: int, port: int) -> None:
    attr = NetPortAttr(LANDLOCK_ACCESS_NET_CONNECT_TCP, port)
    ret = libc.syscall(
        SYS_LANDLOCK_ADD_RULE,
        ruleset_fd,
        LANDLOCK_RULE_NET_PORT,
        ctypes.byref(attr),
        0,
    )
    if ret != 0:
        _raise_errno(f"landlock_add_net_rule({port})")


def _syscall_fd(number: int, arg1: Any, arg2: int, arg3: int) -> int:
    if libc is None:
        raise OSError("libc unavailable")
    ret = libc.syscall(number, arg1, arg2, arg3)
    if ret < 0:
        _raise_errno(f"syscall({number})")
    return int(ret)


def _raise_errno(op: str) -> None:
    err = ctypes.get_errno()
    raise OSError(err, f"{op}: {os.strerror(err)}")
