# Changelog

## Unreleased - 2026-09-25

- Added task-derived requester-authority checks, untrusted-content delegation controls, tool-output taint checks, destructive-query checks, control-token handling, and URL/path canonicalisation to the benchmark defense.
- Added no-label-leakage regression coverage, benchmark literal guards, Hypothesis adversarial tests, and result reproducibility tests for the new controls.
- Updated Zero Trust Agent Benchmark v4.1 dev/test artifacts, ablation results, README metrics, and hypotheses documentation.
- Renamed benchmark-facing files, identifiers, domains, environment variables, and Berkeley Packet Filter Linux Security Module symbols to descriptive names.
- Renamed labels in result files; measured values unchanged.

## 0.1.0 - 2026-09-25

* Initial local implementation with policy compiler, SPIFFE Verifiable Identity Document cache, audit hook backend, Landlock
  backend, Berkeley Packet Filter Linux Security Module prototype, Zero Trust Agent Benchmark adapter, benchmarks, docs, and Temporal Logic of Actions Plus spec.
