"""Declarative policy model and fast in-memory compiler."""

from __future__ import annotations

import fnmatch
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Self

import yaml

Access = Literal["read", "write"]


class PolicyDeny(PermissionError):
    """Raised when a policy denies an operation."""


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    component: str
    latency_us: float


@dataclass(frozen=True, slots=True)
class HostMatcher:
    pattern: str
    port: int
    regex: re.Pattern[str]

    @classmethod
    def compile(cls, spec: str) -> HostMatcher:
        if ":" not in spec:
            raise ValueError(f"network destination must be host:port: {spec!r}")
        host, port_s = spec.rsplit(":", 1)
        port = int(port_s)
        if not 0 < port < 65536:
            raise ValueError(f"invalid port in {spec!r}")
        return cls(host, port, re.compile(fnmatch.translate(host)))

    def matches(self, host: str, port: int) -> bool:
        return self.port == port and self.regex.fullmatch(host) is not None


@dataclass(frozen=True, slots=True)
class PathPrefixTrie:
    """Small normalized prefix matcher; interface leaves room for trie growth."""

    prefixes: tuple[str, ...]

    @classmethod
    def compile(cls, paths: list[str], base_dir: Path | None = None) -> PathPrefixTrie:
        normalized = {_realpath(p, base_dir=base_dir) for p in paths}
        return cls(tuple(sorted(normalized, key=len, reverse=True)))

    def contains(self, path: str | os.PathLike[str]) -> bool:
        target = _realpath(path)
        for prefix in self.prefixes:
            if target == prefix or target.startswith(prefix + os.sep):
                return True
        return False


def _realpath(path: str | os.PathLike[str], *, base_dir: Path | None = None) -> str:
    p = Path(path)
    if not p.is_absolute() and base_dir is not None:
        p = base_dir / p
    try:
        resolved = p.resolve(strict=False)
    except RuntimeError:
        resolved = Path(os.path.realpath(os.fspath(p)))
    return os.path.normcase(os.path.normpath(os.fspath(resolved)))


@dataclass(frozen=True, slots=True)
class SubjectPolicy:
    spiffe_glob: str
    allowed_tools: frozenset[str]
    read_paths: PathPrefixTrie
    write_paths: PathPrefixTrie
    executables: frozenset[str]
    network: tuple[HostMatcher, ...]
    max_arg_bytes: int
    require_kernel: bool = False

    def check_tool(self, tool: str) -> Decision:
        start = time.perf_counter_ns()
        allowed = tool in self.allowed_tools
        return Decision(
            allowed,
            "tool allowed" if allowed else f"tool {tool!r} not allowed",
            "policy.tool",
            _elapsed_us(start),
        )

    def check_args_size(self, argv: list[str] | tuple[str, ...]) -> Decision:
        start = time.perf_counter_ns()
        total = sum(len(a.encode("utf-8", errors="surrogateescape")) for a in argv)
        allowed = total <= self.max_arg_bytes
        return Decision(
            allowed,
            "argument size allowed" if allowed else f"argument bytes {total} exceed limit",
            "policy.args",
            _elapsed_us(start),
        )

    def check_path(self, path: str | os.PathLike[str], access: Access) -> Decision:
        start = time.perf_counter_ns()
        trie = self.write_paths if access == "write" else self.read_paths
        allowed = trie.contains(path)
        return Decision(
            allowed,
            f"{access} path allowed" if allowed else f"{access} path denied: {path}",
            f"policy.fs.{access}",
            _elapsed_us(start),
        )

    def check_executable(self, executable: str | os.PathLike[str]) -> Decision:
        start = time.perf_counter_ns()
        raw = os.fspath(executable)
        exe = _realpath(raw)
        allowed = exe in self.executables or Path(raw).name in self.executables
        return Decision(
            allowed,
            "executable allowed" if allowed else f"executable denied: {executable}",
            "policy.exec",
            _elapsed_us(start),
        )

    def check_network(self, host: str, port: int) -> Decision:
        start = time.perf_counter_ns()
        allowed = any(m.matches(host, port) for m in self.network)
        reason = (
            "network destination allowed"
            if allowed
            else f"network destination denied: {host}:{port}"
        )
        return Decision(
            allowed,
            reason,
            "policy.net",
            _elapsed_us(start),
        )

    def first_denial_for_tool_call(self, tool: str, argv: list[str]) -> Decision:
        for decision in (self.check_tool(tool), self.check_args_size(argv)):
            if not decision.allowed:
                return decision
        return Decision(True, "tool call allowed", "policy", 0.0)


def _elapsed_us(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1000.0


class Policy:
    """Compiled deny-by-default policy keyed by SPIFFE ID glob."""

    def __init__(self, subjects: tuple[SubjectPolicy, ...]) -> None:
        self._subjects = subjects

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Self:
        policy_path = Path(path)
        data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        return cls.from_dict(data, base_dir=policy_path.parent)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, base_dir: Path | None = None) -> Self:
        raw_subjects = data.get("subjects", {})
        if not isinstance(raw_subjects, dict):
            raise ValueError("policy subjects must be a mapping")
        subjects: list[SubjectPolicy] = []
        for spiffe_glob, raw in raw_subjects.items():
            if not isinstance(raw, dict):
                raise ValueError(f"subject {spiffe_glob!r} must map to an object")
            fs = raw.get("fs", {}) or {}
            read_paths = list(fs.get("read", []) or [])
            write_paths = list(fs.get("write", []) or [])
            executable_specs = [str(x) for x in raw.get("executables", []) or []]
            subjects.append(
                SubjectPolicy(
                    spiffe_glob=str(spiffe_glob),
                    allowed_tools=frozenset(str(x) for x in raw.get("allowed_tools", []) or []),
                    read_paths=PathPrefixTrie.compile(read_paths + write_paths, base_dir=base_dir),
                    write_paths=PathPrefixTrie.compile(write_paths, base_dir=base_dir),
                    executables=frozenset(
                        item
                        for x in executable_specs
                        for item in (x, _realpath(x, base_dir=base_dir))
                    ),
                    network=tuple(
                        HostMatcher.compile(str(x)) for x in raw.get("network", []) or []
                    ),
                    max_arg_bytes=int(raw.get("max_arg_bytes", 4096)),
                    require_kernel=bool(raw.get("require_kernel", False)),
                )
            )
        return cls(tuple(subjects))

    def subject_for(self, spiffe_id: str) -> SubjectPolicy | None:
        for subject in self._subjects:
            if fnmatch.fnmatchcase(spiffe_id, subject.spiffe_glob):
                return subject
        return None

    def require_subject(self, spiffe_id: str) -> SubjectPolicy:
        subject = self.subject_for(spiffe_id)
        if subject is None:
            raise PolicyDeny(f"no policy matched SPIFFE ID {spiffe_id!r}")
        return subject

    @property
    def subjects(self) -> tuple[SubjectPolicy, ...]:
        return self._subjects
