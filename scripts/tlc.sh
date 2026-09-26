#!/usr/bin/env bash
set -euo pipefail
JAR="${TLA_JAR:-tools/tla2tools.jar}"
if ! command -v java >/dev/null 2>&1; then
  echo "SKIP TLC: java not found"
  exit 0
fi
if [[ ! -f "$JAR" ]]; then
  echo "SKIP TLC: tla2tools.jar not found"
  exit 0
fi
rm -f specs/*_TTrace_*
java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -config specs/LayeredEnforcement.cfg specs/LayeredEnforcement.tla
rm -f specs/*_TTrace_*
set +e
coop_out=$(java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -config specs/LayeredEnforcementCoopOnly.cfg specs/LayeredEnforcement.tla 2>&1)
coop_rc=$?
set -e
echo "$coop_out"
rm -f specs/*_TTrace_*
if [[ "$coop_rc" -eq 0 ]]; then
  echo "Expected cooperative-only TLC config to produce a counterexample" >&2
  exit 1
fi
if ! grep -q "Invariant NoDeniedEffect is violated" <<<"$coop_out"; then
  echo "Expected invariant violation was not observed" >&2
  exit 1
fi
echo "Cooperative-only counterexample observed as expected."
