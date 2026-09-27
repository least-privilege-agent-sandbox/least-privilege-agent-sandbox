from __future__ import annotations

from least_privilege_agent_sandbox.benchmark_adapter import (
    SandboxDefense,
    _canonical_host,
    _contains_secret_material,
    _raw_tool_frame_is_malformed,
    _requires_task_authority,
    _sql_is_destructive,
    _task_authorizes_tool,
    build_default_defense,
)
from least_privilege_agent_sandbox.policy import Policy
from tests.conftest import SPIFFE


def test_task_authority_helper_branches() -> None:
    assert _task_authorizes_tool("email.send", "please notify the team", {})
    assert _task_authorizes_tool("http.post", "submit the deployment request", {})
    assert _task_authorizes_tool("http.post", "prepare data", {"token_ref": "secret://x/y"})
    assert _task_authorizes_tool("secrets.get", "use the broker credential", {})
    assert _task_authorizes_tool("shell.exec", "run the validation command", {})
    assert _task_authorizes_tool("fs.delete", "delete the stale file", {})
    assert _task_authorizes_tool("db.query", "query the audit table", {"sql": "select 1"})
    assert _task_authorizes_tool("db.query", "clean up", {"sql": "delete from temp_events"})
    assert _task_authorizes_tool("iam.grant", "grant iam access", {})
    assert _task_authorizes_tool("mcp.math.add", "add numbers", {})
    assert not _task_authorizes_tool("shell.exec", "summarize the note", {})
    assert _requires_task_authority("email.send", {})
    assert _requires_task_authority("db.query", {"sql": "drop table records"})
    assert _sql_is_destructive({"sql": "delete from records"})
    assert not _sql_is_destructive({"sql": "delete from temp_events where id=1"})
    assert not _sql_is_destructive({"sql": ""})


def test_canonical_and_secret_helper_branches() -> None:
    assert _canonical_host(None) is None
    assert _canonical_host("  ") is None
    assert _canonical_host("127.000.000.001") == "127.000.000.001"
    assert _canonical_host("BÜCHER.example") == "xn--bcher-kva.example"
    assert not _contains_secret_material({}, ["short"])
    assert not _contains_secret_material({"body": "public"}, ["short"])
    assert _raw_tool_frame_is_malformed("not a mapping") is False
    assert _raw_tool_frame_is_malformed({"raw_generation": 7})


def test_profile_and_context_edge_branches(policy: Policy) -> None:
    defense = SandboxDefense(policy, {"tools": {"file.read": {"scopes": []}}})
    assert (
        defense._generic_context_denial("file.read", {"context": "bad"})["component"] == "context"
    )
    assert defense._generic_context_denial("file.read", {"context": {}, "args": "bad"}) is None
    assert defense._tool_scopes("file.read") == set()
    assert SandboxDefense(policy, {"egress_allowlist": "bad"})._profile_allows_host("example.com")
    assert SandboxDefense(policy, {"email_allowed_domains": "bad"})._profile_allows_email(
        "example.com"
    )
    missing_profile = SandboxDefense(policy, {"tools": {"other": {"scopes": []}}}).decide(
        {
            "agent": {"spiffe_id": SPIFFE, "svid": "valid", "attestation": "valid"},
            "tool": "file.read",
            "args": {},
        }
    )
    assert missing_profile["component"] == "profile.tool"
    assert (
        build_default_defense("examples/benchmark_policy.yaml").decide(
            {"agent": {"spiffe_id": "spiffe://example.org/agent/a"}, "tool": "missing", "args": {}}
        )["decision"]
        == "deny"
    )
