#!/usr/bin/env bash
set -euo pipefail
mkdir -p .tmp .test-runs
export TMPDIR="$PWD/.tmp"
python -m pip install -q -e ".[dev]"
ruff check .
ruff format --check .
mypy src
if [[ "${RUN_INTEGRATION_TESTS:-0}" == "1" ]]; then
  pytest -q --cov=least_privilege_agent_sandbox --cov-report=term-missing --cov-fail-under=90
else
  pytest -q -m "not integration" --cov=least_privilege_agent_sandbox --cov-report=term-missing --cov-fail-under=90
fi
bash scripts/tlc.sh
