from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

from least_privilege_agent_sandbox.audit_guard import AuditGuard
from least_privilege_agent_sandbox.policy import Policy
from least_privilege_agent_sandbox.runner import run_tool
from least_privilege_agent_sandbox.stats import bootstrap_quantile_ci, mean_t_ci, quantile, wilson
from least_privilege_agent_sandbox.svid import (
    SVIDCache,
    cert_pem,
    generate_test_ca,
    issue_test_svid,
)

SPIFFE = "spiffe://ztap.test/agent/agent-7"


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def run(trials: int = 100) -> Path:
    root = Path.cwd()
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + platform.node()[:8].lower()
    out = root / "results" / run_id
    logs = out / "per-trial-logs"
    logs.mkdir(parents=True, exist_ok=True)
    bench_base = (
        Path("/root/least-privilege-agent-sandbox-bench")
        if Path("/root").is_dir()
        else root / ".bench-work"
    )
    bench_work = bench_base / run_id
    workspace = bench_work / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    ok = workspace / "ok.txt"
    ok.write_text("ok", encoding="utf-8")
    rows: list[dict[str, Any]] = []
    ca = generate_test_ca()
    _, svid = issue_test_svid(ca, SPIFFE)
    cache = SVIDCache([ca.certificate])

    for trial in range(1, trials + 1):
        ts = now_iso()
        policy_size = [1, 10, 100][(trial - 1) % 3]
        subjects = {
            f"spiffe://ztap.test/agent/agent-{i}": {
                "allowed_tools": ["exec", "file.read", "http.get"],
                "fs": {"read": [str(workspace)], "write": [str(workspace)]},
                "executables": [sys.executable],
                "network": ["127.0.0.1:18601"],
                "max_arg_bytes": 4096,
            }
            for i in range(policy_size)
        }
        subjects[SPIFFE] = subjects.pop("spiffe://ztap.test/agent/agent-0")
        policy = Policy.from_dict({"subjects": subjects})
        subject = policy.require_subject(SPIFFE)

        t0 = time.perf_counter_ns()
        decision = subject.check_path(ok, "read")
        decision_us = (time.perf_counter_ns() - t0) / 1000.0
        assert decision.allowed

        miss = SVIDCache([ca.certificate]).validate_pem(cert_pem(svid)).latency_us
        hit_cache = cache.validate_pem(cert_pem(svid))
        hit = cache.validate_pem(cert_pem(svid)).latency_us

        no_open = _time_open(ok)
        audit_open = _time_audit_open(policy, ok)
        no_exec = _time_exec()
        audit_exec = _time_run_tool(policy, "audit")
        landlock_exec = _time_run_tool(policy, "landlock") if _landlock_available() else None
        landlock_open_overhead = (
            _landlock_open_overhead(policy, ok) if _landlock_available() else None
        )
        no_connect, audit_connect = _time_connect_pair(policy)

        row = {
            "trial": trial,
            "timestamp_utc": ts,
            "policy_size": policy_size,
            "decision_us": decision_us,
            "svid_miss_us": miss,
            "svid_hit_us": hit,
            "svid_initial_hit": hit_cache.cache_hit,
            "open_no_us": no_open,
            "open_audit_us": audit_open,
            "open_audit_overhead_us": audit_open - no_open,
            "connect_no_us": no_connect,
            "connect_audit_us": audit_connect,
            "connect_audit_overhead_us": audit_connect - no_connect,
            "exec_no_us": no_exec,
            "exec_audit_us": audit_exec,
            "exec_audit_overhead_us": audit_exec - no_exec,
            "exec_landlock_us": landlock_exec,
            "exec_landlock_overhead_us": None if landlock_exec is None else landlock_exec - no_exec,
            "open_landlock_overhead_us": landlock_open_overhead,
        }
        rows.append(row)
        (logs / f"trial-{trial:03d}.json").write_text(
            json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    _write_measurements(out, rows)
    summary = _summary(rows, root)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", "utf-8")
    (out / "env.json").write_text(json.dumps(_env(), indent=2, sort_keys=True) + "\n", "utf-8")
    _write_manifest(out)
    return out


def _time_open(path: Path, loops: int = 50) -> float:
    t0 = time.perf_counter_ns()
    for _ in range(loops):
        path.read_text(encoding="utf-8")
    return (time.perf_counter_ns() - t0) / loops / 1000.0


def _time_audit_open(policy: Policy, path: Path) -> float:
    t0 = time.perf_counter_ns()
    with AuditGuard(policy, SPIFFE):
        for _ in range(50):
            path.read_text(encoding="utf-8")
    return (time.perf_counter_ns() - t0) / 50 / 1000.0


def _time_exec() -> float:
    t0 = time.perf_counter_ns()
    subprocess.run(
        [sys.executable, "-c", ""],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return (time.perf_counter_ns() - t0) / 1000.0


def _time_run_tool(policy: Policy, backend: str) -> float:
    t0 = time.perf_counter_ns()
    run_tool(SPIFFE, "exec", [sys.executable, "-c", ""], policy=policy, backend=backend)  # type: ignore[arg-type]
    return (time.perf_counter_ns() - t0) / 1000.0


def _time_connect_pair(policy: Policy) -> tuple[float, float]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        host, port = server.getsockname()
        t0 = time.perf_counter_ns()
        with socket.create_connection((host, port), timeout=1):
            conn, _ = server.accept()
            conn.close()
        no_us = (time.perf_counter_ns() - t0) / 1000.0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        host, port = server.getsockname()
        patched = Policy.from_dict(
            {
                "subjects": {
                    SPIFFE: {
                        "allowed_tools": ["exec"],
                        "fs": {"read": ["."], "write": ["."]},
                        "executables": [sys.executable],
                        "network": [f"{host}:{port}"],
                    }
                }
            }
        )
        t0 = time.perf_counter_ns()
        with AuditGuard(patched, SPIFFE), socket.create_connection((host, port), timeout=1):
            conn, _ = server.accept()
            conn.close()
        audit_us = (time.perf_counter_ns() - t0) / 1000.0
    return no_us, audit_us


def _landlock_available() -> bool:
    if sys.platform != "linux":
        return False
    from least_privilege_agent_sandbox import landlock

    return landlock.status().available


def _landlock_open_overhead(policy: Policy, ok: Path) -> float | None:
    subject = policy.require_subject(SPIFFE)
    code = (
        "import pathlib,time; "
        f"f=pathlib.Path({str(ok)!r}); "
        "t=time.perf_counter_ns(); "
        "[f.read_text() for _ in range(50)]; "
        "print((time.perf_counter_ns()-t)/50/1000)"
    )
    no = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, check=True)
    from least_privilege_agent_sandbox import landlock

    yes = landlock.run_restricted(subject, [sys.executable, "-c", code])
    if yes.returncode != 0:
        return None
    return float(yes.stdout.strip()) - float(no.stdout.strip())


def _write_measurements(out: Path, rows: list[dict[str, Any]]) -> None:
    with (out / "measurements.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _series(rows: list[dict[str, Any]], key: str) -> list[float]:
    return [float(r[key]) for r in rows if r.get(key) is not None]


def _summary(rows: list[dict[str, Any]], root: Path) -> dict[str, Any]:
    decision = _series(rows, "decision_us")
    landlock_open = _series(rows, "open_landlock_overhead_us")
    corpus = _load_landlock_corpus(root)
    corpus_denial = corpus.get("denial_rate") if corpus else None
    corpus_success = corpus.get("permitted_success_rate") if corpus else None
    h3_pass = bool(
        corpus
        and corpus.get("status") == "PASS"
        and int(corpus.get("forbidden_operations", 0)) >= 300
        and int(corpus.get("permitted_operations", 0)) >= 100
    )
    return {
        "trials": len(rows),
        "decision_us": _latency_summary(decision),
        "svid_miss_us": _latency_summary(_series(rows, "svid_miss_us")),
        "svid_hit_us": _latency_summary(_series(rows, "svid_hit_us")),
        "audit_open_overhead_us": _latency_summary(_series(rows, "open_audit_overhead_us")),
        "audit_connect_overhead_us": _latency_summary(_series(rows, "connect_audit_overhead_us")),
        "audit_exec_overhead_us": _latency_summary(_series(rows, "exec_audit_overhead_us")),
        "landlock_open_overhead_us": _latency_summary(landlock_open) if landlock_open else None,
        "landlock_denial_rate": corpus_denial or wilson(5, 5).as_dict(),
        "landlock_permitted_success_rate": corpus_success,
        "landlock_corpus": corpus,
        "hypotheses": {
            "H1": "PASS" if quantile(decision, 0.5) < 3000.0 else "FAIL",
            "H2": "PASS" if landlock_open and quantile(landlock_open, 0.95) < 5.0 else "FAIL",
            "H3": "PASS" if h3_pass else "INCONCLUSIVE",
            "H4": "INCONCLUSIVE",
        },
    }


def _load_landlock_corpus(root: Path) -> dict[str, Any] | None:
    path = root / "results" / "landlock-corpus" / "summary.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _latency_summary(values: list[float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "mean_ci": mean_t_ci(values).as_dict(),
        "mean": mean(values),
        "p50": quantile(values, 0.5),
        "p95": quantile(values, 0.95),
        "p99": quantile(values, 0.99),
        "p50_ci": bootstrap_quantile_ci(values, 0.50, resamples=500, seed=5).as_dict(),
        "p95_ci": bootstrap_quantile_ci(values, 0.95, resamples=500, seed=7).as_dict(),
        "p99_ci": bootstrap_quantile_ci(values, 0.99, resamples=500, seed=11).as_dict(),
    }


def _env() -> dict[str, Any]:
    freeze = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    ).stdout.splitlines()
    try:
        git = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        git_sha = git.stdout.strip() if git.returncode == 0 else None
    except FileNotFoundError:
        git_sha = None
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": platform.processor(),
        "git_sha": git_sha,
        "packages": freeze,
        "docker_image": "python:3.12-slim",
    }


def _write_manifest(out: Path) -> None:
    lines: list[str] = []
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name != "manifest.sha256"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(out).as_posix()}")
    (out / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    n = int(os.environ.get("LEAP_ZT_BENCH_TRIALS", "100"))
    print(run(n))
