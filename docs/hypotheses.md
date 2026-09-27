# What we measured

Reference microbenchmark run: `results/20260925T211429Z-a01d479f` on Docker `python:3.12-slim` (100 trials). Landlock corpus artifact: `results/landlock-corpus` (490 operations). Zero Trust Agent Benchmark v4.1 artifacts are `results/benchmark-dev` and `results/benchmark-test`; `test.jsonl` sha256 is `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b` from `zero-trust-agent-benchmark` commit `e234839`. Rates use Wilson intervals over distinct traces or denied operations.

| Claim | Hypothesis | Procedure | Result |
|---|---|---|---|
| Claim 1: decision latency | Decision median < 3 ms | 100 policy checks across policy sizes 1/10/100 | PASS: median 60.25 µs, 95th percentile 107.68 µs |
| Claim 2: Landlock open overhead | Landlock per-open 95th percentile overhead < 5 µs | Child process loop with and without Landlock; the 95th percentile is the verdict statistic because tail cost matters for tool execution, not only steady-state median | FAIL: median 0.68 µs [−0.05, 4.20], 95th percentile 194.67 µs [67.29, 226.16], 99th percentile 261.75 µs [194.69, 306.88], mean 6.42 µs [−9.94, 22.78] |
| Claim 3: Landlock filesystem denial | Landlock denies 100% forbidden filesystem operations | Seeded Landlock corpus: outside read/write, symlink chains, `..`, mkdir/unlink/rename/truncate, non-allowlisted exec, and permitted read/write/mkdir/unlink/rename/hardlink/symlink | PASS: denial 335/335 = 1.000 [0.989, 1.000]; permitted success 155/155 = 1.000 [0.976, 1.000] |
| Claim 4: Berkeley Packet Filter Linux Security Module overhead | Berkeley Packet Filter Linux Security Module overhead | Runtime Berkeley Packet Filter Linux Security Module benchmark | INCONCLUSIVE locally; Docker kernel lacks the Berkeley Packet Filter Linux Security Module. The C program compiles with `clang -target bpf` after installing `clang libbpf-dev`. |

Temporal Logic of Actions Plus main config: PASS, 472,637 states generated, 113,442 distinct states, depth 17. Cooperative-only config: expected counterexample, 1,171 states generated, 673 distinct states, depth 5.

## Benchmark defense changes

The benchmark adapter now adds generic controls for requester authority and untrusted delegation before operating-system policy checks: per-task tool authority from the user task, suspicious delegated instruction detection for untrusted retrieved content and tool output, model-control token rejection unless the request is a user-originated quotation or lesson, destructive query checks, issued-secret data loss prevention, and URL/path canonicalisation before policy evaluation. The controls do not read trace labels, families, template identifiers, descriptions, split names, metadata verdicts, or per-step malicious flags.

Miss analysis was performed only on the dev split. Dev misses before the change were concentrated in in-policy prompt-injection egress, tool-output hijacks, and user-originated privilege escalation. Final dev results with issued secrets are 250/250 attacks blocked, 2/250 false positives, and 0/500 leaking traces.

The benchmark shortcut audit and overfit report were reviewed. The source guard blocks trace identifiers and the benchmark's exact generated domain from source literals, the no-label regression randomises forbidden fields while requiring byte-identical decisions, and the reproducibility test recomputes the official test-split counts from the committed code and policy for both issued-secret settings.

## Zero Trust Agent Benchmark v4.1 results

Official evaluator invocation: `zero_trust_agent_benchmark.evaluate.evaluate(defense, traces, provide_issued_secrets=...)` after loading the operator profile into the defense. The pinned test trace hash was checked before writing the result artifacts.

| Split and secret setting | Overall block rate | In-policy block rate | Out-of-policy block rate | False positive rate | Leak rate | Leaking traces |
|---|---:|---:|---:|---:|---:|---:|
| Dev, issued secrets provided | 250/250 = 1.000 [0.985, 1.000] | 141/141 = 1.000 [0.973, 1.000] | 109/109 = 1.000 [0.966, 1.000] | 2/250 = 0.008 [0.002, 0.029] | 0/500 = 0.000 [0.000, 0.008] | 0 |
| Dev, issued secrets withheld | 234/250 = 0.936 [0.899, 0.960] | 125/141 = 0.887 [0.824, 0.929] | 109/109 = 1.000 [0.966, 1.000] | 2/250 = 0.008 [0.002, 0.029] | 16/500 = 0.032 [0.020, 0.051] | 16 |
| Test, issued secrets provided | 500/500 = 1.000 [0.992, 1.000] | 250/250 = 1.000 [0.985, 1.000] | 250/250 = 1.000 [0.985, 1.000] | 4/500 = 0.008 [0.003, 0.020] | 0/1000 = 0.000 [0.000, 0.004] | 0 |
| Test, issued secrets withheld | 468/500 = 0.936 [0.911, 0.954] | 218/250 = 0.872 [0.825, 0.908] | 250/250 = 1.000 [0.985, 1.000] | 4/500 = 0.008 [0.003, 0.020] | 32/1000 = 0.032 [0.023, 0.045] | 32 |

Test split policy-slice table with issued secrets provided:

| Slice | Block rate | False positive rate | Leak rate |
|---|---:|---:|---:|
| Overall | 500/500 = 1.000 [0.992, 1.000] | 4/500 = 0.008 [0.003, 0.020] | 0/1000 = 0.000 [0.000, 0.004] |
| In-policy attacks | 250/250 = 1.000 [0.985, 1.000] | Not applicable | 0/250 = 0.000 [0.000, 0.015] |
| Out-of-policy attacks | 250/250 = 1.000 [0.985, 1.000] | Not applicable | 0/250 = 0.000 [0.000, 0.015] |

## Ablation table on the test split

| Version | Defense increment | Block rate | False positive rate | Leak rate | 95th percentile latency |
|---|---|---:|---:|---:|---:|
| Version 1 | Static profile, profile egress checks, and issued-secret data loss prevention | 373/500 = 0.746 [0.706, 0.782] | 4/500 = 0.008 [0.003, 0.020] | 0/1000 = 0.000 [0.000, 0.004] | 0.575 ms [0.531, 0.642] |
| Final | Version 1 plus task-derived authority, requester-authority checks for untrusted effects, session escalation checks, taint from tool outputs and retrieved documents, destructive-query checks, control-token handling, and canonicalisation before policy evaluation | 500/500 = 1.000 [0.992, 1.000] | 4/500 = 0.008 [0.003, 0.020] | 0/1000 = 0.000 [0.000, 0.004] | 0.412 ms [0.400, 0.435] |

## Claim status

| Claim | Measured | Verdict |
|---|---|---|
| 100% attacks blocked when issued secrets are available | Test: 500/500 blocked | Met on v4.1 test split |
| 0 secret leaks when issued secrets are available | Test: 0/1000 leaking traces | Met on v4.1 test split |
| Low false positives | Test: 4/500 = 0.8%, Wilson high 2.04% | Mostly met; point estimate is below 2%, upper interval is just above 2% |
| 100% attacks blocked without issued secrets | Test: 468/500 blocked, 32 leaking traces | Not met; some in-policy exfiltration requires broker-issued secret values for exact data loss prevention |
| Operating-system enforcement is always active | Windows and ordinary continuous integration jobs use the audit-hook fallback | Not met; Landlock and the Berkeley Packet Filter Linux Security Module require compatible Linux kernels and privileges |

## Validation

Local Windows validation after the change: `ruff check .`, `ruff format --check .`, `mypy src`, and `pytest -q -m "not integration" --cov=least_privilege_agent_sandbox --cov-report=term-missing --cov-fail-under=90` all passed. The targeted no-label, literal-guard, reproducibility, and adversarial property tests passed.

## Remaining gaps

* The false-positive Wilson upper bound is 2.04%, slightly above the 2% target despite the point estimate being 0.8%.
* Without issued secrets, the defense cannot always recognise encoded or transformed secret values, so in-policy leak prevention is incomplete.
* The audit-hook backend remains cooperative and is not a security boundary against native code or code paths that avoid audited application programming interfaces.
* Landlock and Berkeley Packet Filter Linux Security Module enforcement cannot be honestly claimed on Windows or on Linux runners without the required kernel support and privileges.
