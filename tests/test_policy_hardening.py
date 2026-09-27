from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from least_privilege_agent_sandbox.policy import HostMatcher, Policy

SPIFFE = "spiffe://example.org/agent/hardened"
PATH_PARTS = st.lists(st.from_regex(r"[A-Za-z0-9_-]{1,8}", fullmatch=True), min_size=1, max_size=6)


def _policy(workspace: Path, **overrides: object) -> Policy:
    body: dict[str, object] = {
        "allowed_tools": ["exec", "file.read"],
        "fs": {"read": [str(workspace)], "write": [str(workspace / "out")]},
        "executables": [sys.executable],
        "network": ["*.example.com:443", "127.0.0.1:18601"],
        "max_arg_bytes": 128,
    }
    body.update(overrides)
    return Policy.from_dict({"subjects": {SPIFFE: body}})


@pytest.mark.parametrize(
    ("relative", "access", "allowed"),
    [
        ("file.txt", "read", True),
        ("./file.txt", "read", True),
        ("nested/../file.txt", "read", True),
        ("nested/deeper/../../file.txt", "read", True),
        ("out/new.txt", "write", True),
        ("out/../file.txt", "write", False),
        ("../outside.txt", "read", False),
        ("nested/../../../outside.txt", "read", False),
        ("out/../../outside.txt", "write", False),
        ("unicode-π.txt", "read", True),
        ("space dir/file.txt", "read", True),
        ("trail/file.txt", "read", True),
        ("trail/../trail/file.txt", "read", True),
        ("case/File.txt", "read", True),
        ("out/子.txt", "write", True),
        ("子/../../evil.txt", "read", False),
    ],
)
def test_path_normalisation_matrix(
    tmp_path: Path, relative: str, access: str, allowed: bool
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "out").mkdir(parents=True)
    (workspace / "trail").mkdir()
    (workspace / "case").mkdir()
    (workspace / "space dir").mkdir()
    (workspace / "子").mkdir()
    policy = _policy(workspace)
    path = workspace / relative
    assert policy.require_subject(SPIFFE).check_path(path, access).allowed is allowed


def test_trailing_slash_prefix_does_not_allow_sibling(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    allowed = workspace / "allowed"
    sibling = workspace / "allowed-sibling"
    allowed.mkdir(parents=True)
    sibling.mkdir()
    policy = _policy(allowed)
    subject = policy.require_subject(SPIFFE)
    assert subject.check_path(allowed / "x", "read").allowed
    assert not subject.check_path(sibling / "x", "read").allowed


def test_symlink_chain_escape_denied(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    link1 = workspace / "link1"
    link2 = workspace / "link2"
    try:
        link1.symlink_to(link2)
        link2.symlink_to(secret)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    assert not _policy(workspace).require_subject(SPIFFE).check_path(link1, "read").allowed


@pytest.mark.parametrize(
    ("pattern", "host", "port", "allowed"),
    [
        ("*.example.com:443", "api.example.com", 443, True),
        ("*.example.com:443", "example.com", 443, False),
        ("*.example.com:443", "api.example.com", 80, False),
        ("127.0.0.1:18601", "127.0.0.1", 18601, True),
        ("data.*.test:8443", "data.us.test", 8443, True),
        ("data.*.test:8443", "data.us.test", 443, False),
    ],
)
def test_host_matchers(pattern: str, host: str, port: int, allowed: bool) -> None:
    assert HostMatcher.compile(pattern).matches(host, port) is allowed


@pytest.mark.parametrize("tool", ["exec", "file.read"])
def test_allowed_tools_are_exact(tmp_path: Path, tool: str) -> None:
    subject = _policy(tmp_path / "workspace").require_subject(SPIFFE)
    assert subject.check_tool(tool).allowed
    assert not subject.check_tool(tool + ".extra").allowed


@pytest.mark.parametrize("argv", [["x" * 128], ["x" * 129], ["π" * 64], ["π" * 65]])
def test_argument_size_is_measured_in_utf8_bytes(tmp_path: Path, argv: list[str]) -> None:
    subject = _policy(tmp_path / "workspace").require_subject(SPIFFE)
    expected = sum(len(a.encode("utf-8")) for a in argv) <= 128
    assert subject.check_args_size(argv).allowed is expected


@given(PATH_PARTS)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
def test_decisions_are_deterministic(tmp_path: Path, parts: list[str]) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    subject = _policy(workspace).require_subject(SPIFFE)
    path = workspace.joinpath(*[p.replace(os.sep, "_") for p in parts])
    first = subject.check_path(path, "read")
    second = subject.check_path(path, "read")
    assert first.allowed == second.allowed
    assert first.component == second.component


@given(PATH_PARTS)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
def test_paths_under_real_allowed_prefix_are_allowed(tmp_path: Path, parts: list[str]) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    path = workspace.joinpath(*[p.replace(os.sep, "_") for p in parts])
    assert _policy(workspace).require_subject(SPIFFE).check_path(path, "read").allowed


@given(PATH_PARTS)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
def test_paths_outside_real_allowed_prefix_are_denied(tmp_path: Path, parts: list[str]) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir(exist_ok=True)
    outside.mkdir(exist_ok=True)
    path = outside.joinpath(*[p.replace(os.sep, "_") for p in parts])
    assert not _policy(workspace).require_subject(SPIFFE).check_path(path, "read").allowed


def test_yaml_compile_monotone_when_adding_allow_rules(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    extra = tmp_path / "extra"
    workspace.mkdir()
    extra.mkdir()
    base_doc = {
        "subjects": {
            SPIFFE: {
                "allowed_tools": ["file.read"],
                "fs": {"read": [str(workspace)], "write": []},
                "executables": [],
                "network": [],
            }
        }
    }
    expanded_doc = yaml.safe_load(yaml.safe_dump(base_doc))
    expanded_doc["subjects"][SPIFFE]["fs"]["read"].append(str(extra))
    base = Policy.from_dict(base_doc).require_subject(SPIFFE)
    expanded = Policy.from_dict(expanded_doc).require_subject(SPIFFE)
    assert base.check_path(workspace / "x", "read").allowed
    assert expanded.check_path(workspace / "x", "read").allowed
    assert not base.check_path(extra / "x", "read").allowed
    assert expanded.check_path(extra / "x", "read").allowed


@pytest.mark.parametrize(
    "bad_policy",
    [
        {},
        {"subjects": []},
        {"subjects": {SPIFFE: []}},
        {"subjects": {SPIFFE: {"network": ["missing-port"]}}},
        {"subjects": {SPIFFE: {"network": ["host:99999"]}}},
    ],
)
def test_bad_policy_documents_fail_closed(bad_policy: dict[str, object]) -> None:
    if bad_policy == {}:
        assert Policy.from_dict(bad_policy).subject_for(SPIFFE) is None
    else:
        with pytest.raises((ValueError, TypeError)):
            Policy.from_dict(bad_policy)


@pytest.mark.parametrize(
    ("glob", "spiffe_id", "matched"),
    [
        ("spiffe://example.org/agent/*", "spiffe://example.org/agent/a", True),
        ("spiffe://example.org/agent/?", "spiffe://example.org/agent/ab", False),
        ("spiffe://example.org/ns/*/agent/*", "spiffe://example.org/ns/prod/agent/a", True),
        ("spiffe://example.org/ns/prod/*", "spiffe://example.org/ns/dev/agent/a", False),
        ("spiffe://*/agent/a", "spiffe://example.org/agent/a", True),
        ("spiffe://example.org/agent/[ab]", "spiffe://example.org/agent/a", True),
        ("spiffe://example.org/agent/[ab]", "spiffe://example.org/agent/c", False),
        ("spiffe://example.org/agent/*", "spiffe://other.test/agent/a", False),
    ],
)
def test_spiffe_glob_matching(tmp_path: Path, glob: str, spiffe_id: str, matched: bool) -> None:
    workspace = tmp_path / "workspace"
    policy = Policy.from_dict(
        {
            "subjects": {
                glob: {
                    "allowed_tools": [],
                    "fs": {"read": [str(workspace)], "write": []},
                    "executables": [],
                    "network": [],
                }
            }
        }
    )
    assert (policy.subject_for(spiffe_id) is not None) is matched


@pytest.mark.parametrize(
    ("base", "candidate", "allowed"),
    [
        ("a/b", "a/b/c", True),
        ("a/b", "a/b", True),
        ("a/b", "a/bad", False),
        ("a/b", "a/b/../bad", False),
        ("a/b/c", "a/b/c/d/e", True),
        ("a/b/c", "a/b/c/../../x", False),
        ("子/犬", "子/犬/鳥", True),
        ("子/犬", "子/犬2/鳥", False),
        ("with space", "with space/file", True),
        ("with space", "with  space/file", False),
        ("dots.dir", "dots.dir/file", True),
        ("dots.dir", "dots.dir2/file", False),
    ],
)
def test_prefix_boundary_matrix(tmp_path: Path, base: str, candidate: str, allowed: bool) -> None:
    root = tmp_path / "root"
    prefix = root / base
    prefix.mkdir(parents=True)
    policy = _policy(prefix)
    assert policy.require_subject(SPIFFE).check_path(root / candidate, "read").allowed is allowed
