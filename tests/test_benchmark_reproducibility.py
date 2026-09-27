from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from least_privilege_agent_sandbox.benchmark_adapter import SandboxDefense
from least_privilege_agent_sandbox.policy import Policy

PINNED_TEST_SHA256 = "d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b"


def _load_test_traces() -> list[Any]:
    benchmark = pytest.importorskip("zero_trust_agent_benchmark")
    local_path = Path("..") / "zero-trust-agent-benchmark" / "traces"
    if local_path.exists():
        digest = hashlib.sha256((local_path / "test.jsonl").read_bytes()).hexdigest()
        assert digest == PINNED_TEST_SHA256
        return list(benchmark.load_traces(split="test", path=local_path))
    return list(benchmark.load_traces(split="test"))


def _defense() -> SandboxDefense:
    profile_mod = pytest.importorskip("zero_trust_agent_benchmark.profile")
    defense = SandboxDefense(Policy.from_file("examples/benchmark_policy.yaml"))
    defense.setup(profile_mod.profile())
    return defense


@pytest.mark.parametrize(
    ("provide_issued_secrets", "summary_path"),
    [
        (True, Path("results/benchmark-test/summary.json")),
        (False, Path("results/benchmark-test/summary-no-issued-secrets.json")),
    ],
)
def test_committed_benchmark_test_counts_reproduce(
    provide_issued_secrets: bool, summary_path: Path
) -> None:
    evaluator = pytest.importorskip("zero_trust_agent_benchmark.evaluate")
    expected = json.loads(summary_path.read_text(encoding="utf-8"))["counts"]
    report = evaluator.evaluate(
        _defense(), _load_test_traces(), provide_issued_secrets=provide_issued_secrets
    )
    assert report.counts == expected
