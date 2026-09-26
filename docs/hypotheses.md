# What we measured

Reference microbenchmark run: `results/20260925T211429Z-a01d479f` on Docker `python:3.12-slim` (100 trials). Landlock corpus artifact: `results/landlock-corpus` (490 operations). Zero Trust Agent Benchmark v4 artifacts are `results/azt-dev` and `results/azt-test`; `test.jsonl` sha256 is `4f6fff41fe77aefb2ec96336b65a58d571986e0036ac3e368cc9975ed029dfc7` from `zero-trust-agent-benchmark` commit `e234839`. Rates use Wilson intervals over distinct traces or denied operations.

| ID | Hypothesis | Procedure | Result |
|---|---|---|---|
| H1 | Decision p50 < 3 ms | 100 policy checks across policy sizes 1/10/100 | PASS: p50 60.25 µs, p95 107.68 µs |
| H2 | Landlock per-open overhead p95 < 5 µs | Child process loop with and without Landlock; p95 is the verdict statistic because tail cost matters for tool execution, not only steady-state median | FAIL: p50 0.68 µs [−0.05, 4.20], p95 194.67 µs [67.29, 226.16], p99 261.75 µs [194.69, 306.88], mean 6.42 µs [−9.94, 22.78] |
| H3 | Landlock denies 100% forbidden filesystem operations | Seeded Landlock corpus: outside read/write, symlink chains, `..`, mkdir/unlink/rename/truncate, non-allowlisted exec, and permitted read/write/mkdir/unlink/rename/hardlink/symlink | PASS: denial 335/335 = 1.000 [0.989, 1.000]; permitted success 155/155 = 1.000 [0.976, 1.000] |
| H4 | BPF-LSM overhead | Runtime BPF LSM benchmark | INCONCLUSIVE locally; Docker kernel lacks BPF LSM. The C program compiles with `clang -target bpf` after installing `clang libbpf-dev`. |

TLC main config: PASS, 472,637 states generated, 113,442 distinct states, depth 17. Cooperative-only config: expected counterexample, 1,171 states generated, 673 distinct states, depth 5.

Zero Trust Agent Benchmark real CLI runs:

| Dataset/split | Overall block | In-policy block | Out-of-policy block | FPR | Leaks |
|---|---:|---:|---:|---:|---:|
| v4 dev | 0.684 [0.624, 0.738] | 0.461 [0.381, 0.543] | 0.972 [0.922, 0.991] | 0.008 [0.002, 0.029] | 0 |
| v4 test | 0.746 [0.706, 0.782] | 0.520 [0.458, 0.581] | 0.972 [0.943, 0.986] | 0.008 [0.003, 0.020] | 0 |
| v3 test (superseded: had shortcuts) | 0.946 [0.923, 0.963] | 0.892 [0.847, 0.925] | 1.000 [0.985, 1.000] | 0.000 [0.000, 0.008] | 0 |

Test split policy-slice table:

| Slice | Block rate | FPR | Leak rate |
|---|---:|---:|---:|
| Overall | 373/500 = 0.746 [0.706, 0.782] | 4/500 = 0.008 [0.003, 0.020] | 0/1000 = 0.000 [0.000, 0.004] |
| In-policy attacks | 130/250 = 0.520 [0.458, 0.581] | N/A (attack slice) | 0/250 = 0.000 [0.000, 0.015] |
| Out-of-policy attacks | 243/250 = 0.972 [0.943, 0.986] | N/A (attack slice) | 0/250 = 0.000 [0.000, 0.015] |

Validation: Windows `pytest -m "not integration"` passed with 116 tests and 92.70% coverage. Docker run with `ZTAP_INTEGRATION=1` passed with 113 tests and 92.87% coverage; Landlock filesystem tests ran, network enforcement skipped because Landlock ABI is below 4.

Zero Trust Agent Benchmark v4 scope: Least-Privilege Agent Sandbox blocks most out-of-policy attacks using profile and policy checks, and prevents benchmark secret leaks with issued-secret DLP over common encodings. Remaining misses are in-policy attacks whose requested effect stays within configured policy and does not carry recognizable secret material; this is expected for a least-privilege enforcement mechanism rather than a full semantic intent verifier. The adapter uses only deployment-profile information (tool catalog/scopes and egress/email allowlists), generic Unicode-format and JSON-frame validation, executable/path/network policy checks, and generic secret-format/issued-secret DLP; no trace id, role, template id, label, or generator-owned literal is consulted. The v3 numbers are retained only as superseded evidence because v3 had shortcutable surfaces such as untrusted-origin egress not appearing in benign traces.

H2 tail note: the median Landlock per-open delta remains sub-microsecond, but the p95/p99 are dominated by separate short subprocesses, scheduling jitter, and cache/page-fault noise around tiny 50-open loops. The result is reported as a tail-latency failure rather than using the favorable median.
