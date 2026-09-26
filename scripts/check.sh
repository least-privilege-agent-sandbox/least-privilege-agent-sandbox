#!/usr/bin/env bash
set -euo pipefail
mkdir -p .tmp .test-runs
if [[ -d /root && -w /root ]]; then
  mkdir -p /root/least-privilege-agent-sandbox-tmp
  export TMPDIR="/root/least-privilege-agent-sandbox-tmp"
else
  export TMPDIR="$PWD/.tmp"
fi
python -m pip install -q -e ".[dev]"
ruff check .
ruff format --check .
mypy src
if [[ "${ZTAP_INTEGRATION:-0}" == "1" ]]; then
  pytest -q --cov=least_privilege_agent_sandbox --cov-report=term-missing --cov-fail-under=90
else
  pytest -q -m "not integration" --cov=least_privilege_agent_sandbox --cov-report=term-missing --cov-fail-under=90
fi
bash scripts/tlc.sh
