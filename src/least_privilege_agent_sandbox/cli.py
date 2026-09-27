"""Command-line interface for Least-Privilege Agent Sandbox."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from least_privilege_agent_sandbox.policy import Policy, PolicyDeny
from least_privilege_agent_sandbox.runner import run_tool


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="least-privilege-agent-sandbox")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run a command under the strongest available backend")
    run.add_argument("--policy", required=True)
    run.add_argument("--svid", required=True, help="PEM X.509-SVID certificate")
    run.add_argument("--trust-bundle", required=True, help="PEM trust bundle")
    run.add_argument("--tool", default="exec")
    run.add_argument("cmd", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        cmd = list(args.cmd)
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("least-privilege-agent-sandbox run requires -- <cmd>", file=sys.stderr)
            return 2
        try:
            from cryptography import x509

            from least_privilege_agent_sandbox.svid import SVIDCache

            policy = Policy.from_file(args.policy)
            cert_pem = Path(args.svid).read_bytes()
            bundle = [x509.load_pem_x509_certificate(Path(args.trust_bundle).read_bytes())]
            spiffe_id = SVIDCache(bundle).validate_pem(cert_pem).spiffe_id
            result = run_tool(spiffe_id, args.tool, cmd, policy=policy)
        except (ImportError, OSError, PolicyDeny, RuntimeError, ValueError) as exc:
            print(f"DENY: {exc}", file=sys.stderr)
            return 126
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        print(
            f"least-privilege-agent-sandbox backend={result.backend} exit={result.returncode}",
            file=sys.stderr,
        )
        return result.returncode
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
