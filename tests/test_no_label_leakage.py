from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from least_privilege_agent_sandbox.benchmark_adapter import SandboxDefense
from least_privilege_agent_sandbox.policy import Policy


def _defense() -> SandboxDefense:
    profile_mod = pytest.importorskip("zero_trust_agent_benchmark.profile")
    defense = SandboxDefense(Policy.from_file("examples/benchmark_policy.yaml"))
    defense.setup(profile_mod.profile())
    return defense


def _decisions(trace: Any, *, trace_id: str | None = None) -> list[str]:
    defense = _defense()
    defense.on_trace_start(
        {"trace_id": trace_id or trace.trace_id, "issued_secrets": trace.secrets}
    )
    history: list[dict[str, Any]] = []
    out: list[str] = []
    for step in trace.steps:
        decision = defense.decide(
            {
                "trace_id": trace_id or trace.trace_id,
                "step": step.step,
                "agent": asdict(trace.agent),
                "tool": step.tool,
                "args": step.args,
                "context": step.context,
                "history": list(history),
            }
        )
        out.append(json.dumps(decision, sort_keys=True))
        history.append({"step": step.step, "tool": step.tool, "decision": decision["decision"]})
    return out


def test_decisions_do_not_depend_on_forbidden_benchmark_fields() -> None:
    benchmark = pytest.importorskip("zero_trust_agent_benchmark")
    trace_dir = Path("..") / "zero-trust-agent-benchmark" / "traces"
    traces = (
        benchmark.load_traces(split="dev", path=trace_dir)
        if trace_dir.exists()
        else benchmark.load_traces(split="dev")
    )
    for trace in traces[:40]:
        mutated = trace.to_dict()
        mutated["trace_id"] = "randomized-trace"
        mutated["split"] = "test" if mutated["split"] == "dev" else "dev"
        mutated["label"] = "benign" if mutated["label"] == "attack" else "attack"
        mutated["family"] = "benign_randomized"
        mutated["description"] = "randomized"
        mutated["template_id"] = "randomized-template"
        mutated["metadata"] = {"in_policy": not bool(mutated.get("metadata", {}).get("in_policy"))}
        for step in mutated["steps"]:
            step["malicious"] = not bool(step.get("malicious"))
        randomized = pytest.importorskip("zero_trust_agent_benchmark.schema").Trace.from_dict(
            mutated
        )
        assert _decisions(trace, trace_id="original-trace") == _decisions(
            randomized, trace_id="randomized-trace"
        )
