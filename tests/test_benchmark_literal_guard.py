from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

SOURCE_ROOT = Path("src/least_privilege_agent_sandbox")


def _string_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.add(node.value.lower())
    return values


def _benchmark_literals() -> set[str]:
    generator = pytest.importorskip("zero_trust_agent_benchmark.generator")
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
        "audit",
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
        "read",
        "network",
        "source",
        "svid",
        "tool",
        "tools",
        "url",
        "user",
        "valid",
        "write",
    }
    return (
        {str(token).lower() for token in generator.literal_tokens()} - profile_terms - schema_terms
    )


@pytest.mark.parametrize("source", sorted(SOURCE_ROOT.glob("*.py")))
def test_benchmark_generator_literals_are_not_shortcuts(source: Path) -> None:
    assert _string_literals(source).isdisjoint(_benchmark_literals())


def test_trace_identifiers_and_exact_benchmark_domain_are_not_embedded() -> None:
    benchmark = pytest.importorskip("zero_trust_agent_benchmark")
    trace_dir = Path("..") / "zero-trust-agent-benchmark" / "traces"
    traces = (
        benchmark.load_traces(split=None, path=trace_dir)
        if trace_dir.exists()
        else benchmark.load_traces(split=None)
    )
    forbidden = {trace.trace_id.lower() for trace in traces}
    forbidden.add(".".join(("acme", "test")))
    copied: dict[str, list[str]] = {}
    for source in sorted(SOURCE_ROOT.glob("*.py")):
        hits = sorted(_string_literals(source) & forbidden)
        if hits:
            copied[str(source)] = hits
    assert copied == {}


def test_shortcut_audit_files_are_reviewed() -> None:
    audit_dir = Path("..") / "zero-trust-agent-benchmark" / "results"
    if not audit_dir.exists():
        pytest.skip("benchmark audit result files are not available in the installed package")
    shortcut = json.loads((audit_dir / "shortcut_audit.json").read_text(encoding="utf-8"))
    overfit = json.loads((audit_dir / "overfit_check.json").read_text(encoding="utf-8"))
    assert shortcut["counts"]["benign"] > 0
    assert shortcut["counts"]["in_policy_attack"] > 0
    assert "top_attack_tokens" in overfit
