from __future__ import annotations

import ast
from pathlib import Path

import pytest


def _string_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.add(node.value.lower())
    return values


@pytest.mark.parametrize("source", sorted(Path("src/least_privilege_agent_sandbox").glob("*.py")))
def test_benchmark_generator_literals_are_not_embedded_in_source(source: Path) -> None:
    generator = pytest.importorskip("zero_trust_agent_benchmark.generator")
    literal_tokens = getattr(generator, "literal_tokens", None)
    if literal_tokens is None:
        pytest.skip("Zero Trust Agent Benchmark does not expose literal_tokens()")

    profile = pytest.importorskip("zero_trust_agent_benchmark.profile").profile()
    profile_terms = set(profile.get("tools", {}))
    profile_terms.update(profile.get("egress_allowlist", []))
    profile_terms.update(profile.get("email_allowed_domains", []))
    profile_terms.update(
        scope for meta in profile.get("tools", {}).values() for scope in meta.get("scopes", [])
    )
    schema_terms = {
        "agent",
        "args",
        "attestation",
        "cmd",
        "command",
        "content",
        "context",
        "decision",
        "destination",
        "executable",
        "file",
        "input",
        "output",
        "path",
        "policy",
        "audit",
        "network",
        "read",
        "source",
        "svid",
        "tool",
        "tools",
        "url",
        "user",
        "valid",
        "write",
    }
    forbidden = {str(token).lower() for token in literal_tokens()} - profile_terms - schema_terms
    copied = _string_literals(source) & forbidden
    assert copied == set()
