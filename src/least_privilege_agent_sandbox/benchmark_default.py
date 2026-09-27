"""Environment-configured Zero Trust Agent Benchmark defense object."""

from __future__ import annotations

import os

from least_privilege_agent_sandbox.benchmark_adapter import SandboxDefense
from least_privilege_agent_sandbox.policy import Policy

_policy_path = os.environ.get("SANDBOX_POLICY", "examples/benchmark_policy.yaml")
defense = SandboxDefense(Policy.from_file(_policy_path))
