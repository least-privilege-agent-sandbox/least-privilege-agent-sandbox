"""BPF LSM loader utilities.

Runtime loading requires a kernel booted with the BPF LSM (``lsm=...,bpf``). The local Docker
Desktop kernel used for development does not expose BPF LSM, so runtime tests skip with a clear
reason. The VM workflow compiles the C program with clang's BPF target.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class BPFStatus:
    available: bool
    reason: str


def status() -> BPFStatus:
    lsm_file = Path("/sys/kernel/security/lsm")
    if not lsm_file.exists():
        return BPFStatus(False, "securityfs LSM list is unavailable")
    try:
        lsms = lsm_file.read_text(encoding="utf-8").strip().split(",")
    except OSError as exc:
        return BPFStatus(False, f"cannot read LSM list: {exc}")
    if "bpf" not in lsms:
        return BPFStatus(False, "BPF LSM is not enabled on this kernel")
    if shutil.which("bpftool") is None:
        return BPFStatus(False, "bpftool is not installed")
    return BPFStatus(True, "BPF LSM appears available")


def compile_bpf(source: str | os.PathLike[str], output: str | os.PathLike[str]) -> None:
    clang = shutil.which("clang")
    if clang is None:
        raise RuntimeError("clang not found")
    subprocess.run(
        [clang, "-O2", "-g", "-target", "bpf", "-c", os.fspath(source), "-o", os.fspath(output)],
        check=True,
    )
