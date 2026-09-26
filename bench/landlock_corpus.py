from __future__ import annotations

import csv
import json
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from least_privilege_agent_sandbox import landlock
from least_privilege_agent_sandbox.policy import Policy, PolicyDeny, SubjectPolicy
from least_privilege_agent_sandbox.stats import wilson

SPIFFE = "spiffe://ztap.test/agent/agent-7"
Outcome = Literal["permitted", "forbidden"]


@dataclass(frozen=True, slots=True)
class Operation:
    id: str
    category: str
    expected: Outcome
    code: str
    argv: tuple[str, ...] | None = None


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("Landlock corpus requires Linux")
    st = landlock.status()
    if not st.available:
        raise SystemExit(st.reason)

    root = Path("/root/least-privilege-agent-sandbox-landlock-corpus")
    if root.exists():
        shutil.rmtree(root)
    workspace = root / "workspace"
    outside = root / "outside"
    workspace.mkdir(parents=True)
    outside.mkdir()
    subject = _subject(workspace)
    operations = _operations(workspace, outside)
    rows = [_run_operation(subject, op) for op in operations]
    summary = _summary(rows, st.abi)

    out = Path("results") / "landlock-corpus"
    out.mkdir(parents=True, exist_ok=True)
    with (out / "operations.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


def _subject(workspace: Path) -> SubjectPolicy:
    policy = Policy.from_dict(
        {
            "subjects": {
                SPIFFE: {
                    "allowed_tools": ["exec"],
                    "fs": {"read": [str(workspace)], "write": [str(workspace)]},
                    "executables": [sys.executable],
                    "network": [],
                    "max_arg_bytes": 4096,
                    "require_kernel": True,
                }
            }
        }
    )
    return policy.require_subject(SPIFFE)


def _operations(workspace: Path, outside: Path) -> list[Operation]:
    rng = random.Random(20260925)  # noqa: S311 - deterministic corpus, not cryptography.
    ops: list[Operation] = []

    for i in range(45):
        p = _write(workspace / "allowed-read" / f"{i}-{rng.randrange(10**9)}.txt", "ok")
        ops.append(Operation(f"permit-read-{i:03d}", "permit.read", "permitted", _read_code(p)))
    for i in range(30):
        p = workspace / "allowed-write" / f"{i}-{rng.randrange(10**9)}.txt"
        ops.append(Operation(f"permit-write-{i:03d}", "permit.write", "permitted", _write_code(p)))
    for i in range(20):
        p = workspace / "allowed-mkdir" / f"{i}-{rng.randrange(10**9)}"
        ops.append(Operation(f"permit-mkdir-{i:03d}", "permit.mkdir", "permitted", _mkdir_code(p)))
    for i in range(20):
        p = _write(workspace / "allowed-unlink" / f"{i}-{rng.randrange(10**9)}.txt", "ok")
        ops.append(
            Operation(f"permit-unlink-{i:03d}", "permit.unlink", "permitted", _unlink_code(p))
        )
    for i in range(20):
        src = _write(workspace / "allowed-rename" / f"{i}-{rng.randrange(10**9)}.txt", "ok")
        dst = src.with_suffix(".moved")
        ops.append(
            Operation(
                f"permit-rename-{i:03d}", "permit.rename", "permitted", _rename_code(src, dst)
            )
        )
    for i in range(10):
        src = _write(workspace / "allowed-hardlink-src" / f"{i}.txt", "ok")
        dst = workspace / "allowed-hardlink-dst" / f"{i}.txt"
        dst.parent.mkdir(parents=True, exist_ok=True)
        ops.append(
            Operation(
                f"permit-hardlink-{i:03d}", "permit.hardlink", "permitted", _link_code(src, dst)
            )
        )
    for i in range(10):
        target = _write(workspace / "allowed-symlink-target" / f"{i}.txt", "ok")
        link = workspace / "allowed-symlink-link" / f"{i}.lnk"
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except OSError:
            continue
        ops.append(
            Operation(f"permit-symlink-{i:03d}", "permit.symlink", "permitted", _read_code(link))
        )

    for i in range(50):
        p = _write(outside / "deny-read" / f"{i}-{rng.randrange(10**9)}.txt", "secret")
        ops.append(Operation(f"deny-read-{i:03d}", "deny.read", "forbidden", _read_code(p)))
    for i in range(50):
        p = outside / "deny-write" / f"{i}-{rng.randrange(10**9)}.txt"
        ops.append(Operation(f"deny-write-{i:03d}", "deny.write", "forbidden", _write_code(p)))
    for i in range(35):
        p = outside / "deny-mkdir" / f"{i}-{rng.randrange(10**9)}"
        ops.append(Operation(f"deny-mkdir-{i:03d}", "deny.mkdir", "forbidden", _mkdir_code(p)))
    for i in range(35):
        p = _write(outside / "deny-unlink" / f"{i}-{rng.randrange(10**9)}.txt", "secret")
        ops.append(Operation(f"deny-unlink-{i:03d}", "deny.unlink", "forbidden", _unlink_code(p)))
    for i in range(35):
        src = _write(outside / "deny-rename" / f"{i}-{rng.randrange(10**9)}.txt", "secret")
        dst = src.with_suffix(".moved")
        ops.append(
            Operation(f"deny-rename-{i:03d}", "deny.rename", "forbidden", _rename_code(src, dst))
        )
    for i in range(35):
        p = _write(outside / "deny-truncate" / f"{i}-{rng.randrange(10**9)}.txt", "secret")
        ops.append(
            Operation(f"deny-truncate-{i:03d}", "deny.truncate", "forbidden", _truncate_code(p))
        )
    for i in range(35):
        p = _write(outside / "deny-dotdot" / f"{i}-{rng.randrange(10**9)}.txt", "secret")
        traversed = workspace / ".." / "outside" / p.relative_to(outside)
        ops.append(
            Operation(f"deny-dotdot-{i:03d}", "deny.dotdot", "forbidden", _read_code(traversed))
        )
    for i in range(35):
        target = _write(outside / "deny-symlink-target" / f"{i}.txt", "secret")
        mid = workspace / "deny-symlink-mid" / f"{i}.lnk"
        link = workspace / "deny-symlink-link" / f"{i}.lnk"
        mid.parent.mkdir(parents=True, exist_ok=True)
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            mid.symlink_to(target)
            link.symlink_to(mid)
        except OSError:
            continue
        ops.append(
            Operation(f"deny-symlink-{i:03d}", "deny.symlink", "forbidden", _read_code(link))
        )
    for i in range(25):
        ops.append(
            Operation(
                f"deny-exec-{i:03d}",
                "deny.exec",
                "forbidden",
                "",
                argv=("/bin/echo", f"blocked-{i}"),
            )
        )

    rng.shuffle(ops)
    return ops


def _run_operation(subject: SubjectPolicy, op: Operation) -> dict[str, Any]:
    argv = list(op.argv) if op.argv else [sys.executable, "-c", op.code]
    denied_by = "kernel"
    try:
        proc = landlock.run_restricted(subject, argv, timeout=5.0)
        returncode = proc.returncode
        stderr = proc.stderr[-200:]
    except PolicyDeny as exc:
        denied_by = "policy-preflight"
        returncode = 126
        stderr = str(exc)
    except subprocess.TimeoutExpired:
        returncode = 124
        stderr = "timeout"
    permitted_ok = op.expected == "permitted" and returncode == 0
    forbidden_denied = op.expected == "forbidden" and returncode != 0
    return {
        "id": op.id,
        "category": op.category,
        "expected": op.expected,
        "returncode": returncode,
        "ok": permitted_ok or forbidden_denied,
        "denied_by": denied_by if returncode != 0 else "",
        "stderr_tail": stderr,
    }


def _summary(rows: list[dict[str, Any]], abi: int) -> dict[str, Any]:
    forbidden = [r for r in rows if r["expected"] == "forbidden"]
    permitted = [r for r in rows if r["expected"] == "permitted"]
    denied = sum(1 for r in forbidden if r["returncode"] != 0)
    allowed = sum(1 for r in permitted if r["returncode"] == 0)
    by_category: dict[str, dict[str, int]] = {}
    for row in rows:
        item = by_category.setdefault(row["category"], {"ok": 0, "total": 0})
        item["total"] += 1
        item["ok"] += int(bool(row["ok"]))
    return {
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "landlock_abi": abi,
        "total_operations": len(rows),
        "forbidden_operations": len(forbidden),
        "permitted_operations": len(permitted),
        "denial_rate": {
            "count": denied,
            "n": len(forbidden),
            **wilson(denied, len(forbidden)).as_dict(),
        },
        "permitted_success_rate": {
            "count": allowed,
            "n": len(permitted),
            **wilson(allowed, len(permitted)).as_dict(),
        },
        "by_category": by_category,
        "status": "PASS" if denied == len(forbidden) and allowed == len(permitted) else "FAIL",
    }


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _read_code(path: Path) -> str:
    return f"from pathlib import Path\nPath({os.fspath(path)!r}).read_text(encoding='utf-8')\n"


def _write_code(path: Path) -> str:
    return (
        "from pathlib import Path\n"
        f"p=Path({os.fspath(path)!r})\n"
        "p.parent.mkdir(parents=True, exist_ok=True)\n"
        "p.write_text('ok', encoding='utf-8')\n"
    )


def _mkdir_code(path: Path) -> str:
    return (
        f"from pathlib import Path\nPath({os.fspath(path)!r}).mkdir(parents=True, exist_ok=True)\n"
    )


def _unlink_code(path: Path) -> str:
    return f"from pathlib import Path\nPath({os.fspath(path)!r}).unlink()\n"


def _rename_code(src: Path, dst: Path) -> str:
    return f"from pathlib import Path\nPath({os.fspath(src)!r}).rename({os.fspath(dst)!r})\n"


def _truncate_code(path: Path) -> str:
    return f"from pathlib import Path\nPath({os.fspath(path)!r}).open('w').truncate(0)\n"


def _link_code(src: Path, dst: Path) -> str:
    return f"import os\nos.link({os.fspath(src)!r}, {os.fspath(dst)!r})\n"


if __name__ == "__main__":
    raise SystemExit(main())
