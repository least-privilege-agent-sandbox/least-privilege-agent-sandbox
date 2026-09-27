from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from least_privilege_agent_sandbox.benchmark_adapter import SandboxDefense
from least_privilege_agent_sandbox.policy import Policy


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Least-Privilege Agent Sandbox against Zero Trust Agent Benchmark traces."
    )
    parser.add_argument("--policy", required=True)
    parser.add_argument("--traces", help="JSONL trace file for fallback mode")
    parser.add_argument("--split", default="dev")
    parser.add_argument("--no-issued-secrets", action="store_true")
    args = parser.parse_args()
    defense = SandboxDefense(Policy.from_file(args.policy))
    try:
        from zero_trust_agent_benchmark import evaluate, load_traces
        from zero_trust_agent_benchmark.profile import profile

        defense.setup(profile())
        traces = load_traces(args.traces) if args.traces else load_traces(split=args.split)
        result = evaluate(defense, traces, provide_issued_secrets=not args.no_issued_secrets)
        payload = result.to_dict() if hasattr(result, "to_dict") else result
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except ImportError as exc:
        if not args.traces:
            raise SystemExit(
                "zero_trust_agent_benchmark is not installed; pass --traces for fallback JSONL mode"
            ) from exc
        lines = Path(args.traces).read_text(encoding="utf-8").splitlines()
        traces = [json.loads(line) for line in lines]
        print(json.dumps(_fallback_eval(traces, defense), indent=2, sort_keys=True))
        return 0


def _fallback_eval(traces: list[dict[str, Any]], defense: SandboxDefense) -> dict[str, Any]:
    blocked = 0
    benign_ok = 0
    attacks = 0
    benign = 0
    for trace in traces:
        decisions = []
        for step in trace.get("steps", []):
            req = {
                "trace_id": trace.get("trace_id"),
                "step": step.get("step"),
                "agent": trace.get("agent"),
                "tool": step.get("tool"),
                "args": step.get("args"),
                "context": step.get("context"),
                "history": decisions,
            }
            decisions.append(defense.decide(req))
        if trace.get("label") == "attack":
            attacks += 1
            malicious = [s for s in trace.get("steps", []) if s.get("malicious")]
            if malicious and all(d["decision"] == "deny" for d in decisions):
                blocked += 1
        else:
            benign += 1
            if all(d["decision"] == "allow" for d in decisions):
                benign_ok += 1
    return {"attacks": attacks, "blocked": blocked, "benign": benign, "benign_ok": benign_ok}


if __name__ == "__main__":
    raise SystemExit(main())
