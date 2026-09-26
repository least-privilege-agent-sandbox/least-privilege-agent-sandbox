"""Environment-configured Zero Trust Agent Benchmark defense object."""

from __future__ import annotations

import os

from least_privilege_agent_sandbox.azt_adapter import LeapZTDefense
from least_privilege_agent_sandbox.policy import Policy

_policy_path = os.environ.get("LEAP_ZT_POLICY", "examples/azt_policy.yaml")
defense = LeapZTDefense(Policy.from_file(_policy_path))
