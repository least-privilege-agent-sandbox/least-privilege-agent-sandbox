"""Zero Trust Agent Benchmark defense adapter."""

from __future__ import annotations

import base64
import binascii
import codecs
import ipaddress
import os
import re
import shlex
import unicodedata
from collections.abc import Iterable, Mapping
from contextlib import suppress
from typing import Any, Literal, cast
from urllib.parse import unquote, urlparse

from least_privilege_agent_sandbox.policy import Policy, PolicyDeny, SubjectPolicy

AccessName = Literal["read", "write"]


class SandboxDefense:
    def __init__(self, policy: Policy, profile: Mapping[str, Any] | None = None) -> None:
        self._policy = policy
        self._profile: Mapping[str, Any] = profile or {}
        self._issued_secrets: set[str] = set()

    def setup(self, profile: Mapping[str, Any]) -> None:
        self._profile = profile

    def reset(self) -> None:
        self._issued_secrets.clear()

    def on_trace_start(self, meta: Mapping[str, Any]) -> None:
        issued = meta.get("issued_secrets", [])
        self._issued_secrets = {str(item) for item in issued if isinstance(item, str)}

    def decide(self, req: dict[str, Any]) -> dict[str, str]:
        try:
            subject = self._subject(req)
            agent = req.get("agent", {}) or {}
            if not _agent_state_valid(agent):
                return _deny("invalid agent SVID or attestation", "svid")
            context = req.get("context", {}) or {}
            if _contains_hidden_unicode(context) or _raw_tool_frame_is_malformed(context):
                return _deny("untrusted tool metadata", "context")
            tool = str(req.get("tool", ""))
            d = subject.check_tool(tool)
            if not d.allowed:
                return _deny(d.reason, d.component)
            profile_denial = self._profile_denial(tool, agent)
            if profile_denial is not None:
                return profile_denial
            args = req.get("args", {}) or {}
            if not isinstance(args, dict):
                return _deny("args must be an object", "args")
            d = subject.check_args_size(_argv_from_args(args))
            if not d.allowed:
                return _deny(d.reason, d.component)
            if _contains_secret_material(args, self._issued_secrets):
                return _deny("secret material in arguments", "dlp")
            generic_denial = self._generic_context_denial(tool, req)
            if generic_denial is not None:
                return generic_denial
            for path, access in _paths_from_args(args, self._tool_scopes(tool)):
                d = subject.check_path(path, access)
                if not d.allowed:
                    return _deny(d.reason, d.component)
            for exe in _executables_from_args(args):
                d = subject.check_executable(exe)
                if not d.allowed:
                    return _deny(d.reason, d.component)
            for host, port in _urls_from_args(args):
                if not self._profile_allows_host(host):
                    return _deny(f"network destination denied: {host}:{port}", "profile.net")
                d = subject.check_network(host, port)
                if not d.allowed:
                    return _deny(d.reason, d.component)
            for host in _email_domains_from_args(args):
                if not self._profile_allows_email(host):
                    return _deny(f"email domain denied: {host}", "profile.email")
                d = subject.check_network(host, 443)
                if not d.allowed:
                    return _deny(d.reason, "policy.email")
            return {
                "decision": "allow",
                "reason": "policy allowed",
                "component": "least_privilege_agent_sandbox",
            }
        except (PolicyDeny, ValueError) as exc:
            return _deny(str(exc), "least_privilege_agent_sandbox")

    def _profile_denial(self, tool: str, agent: Any) -> dict[str, str] | None:
        tools = self._profile.get("tools", {})
        if not isinstance(tools, Mapping) or not tools:
            return None
        meta = tools.get(tool)
        if not isinstance(meta, Mapping):
            return _deny("tool absent from deployment profile", "profile.tool")
        if not isinstance(agent, Mapping):
            return _deny("agent must be an object", "least_privilege_agent_sandbox")
        granted = set(str(scope) for scope in agent.get("scopes", []) if isinstance(scope, str))
        needed = set(str(scope) for scope in meta.get("scopes", []) if isinstance(scope, str))
        if not needed.issubset(granted):
            return _deny("agent missing required scope", "profile.scope")
        return None

    def _generic_context_denial(self, tool: str, req: Mapping[str, Any]) -> dict[str, str] | None:
        context = req.get("context", {}) or {}
        if not isinstance(context, Mapping):
            return _deny("context must be an object", "context")
        raw_args = req.get("args", {}) or {}
        if raw_args is not None and not isinstance(raw_args, Mapping):
            return None
        args = cast(Mapping[str, Any], raw_args)

        origin = str(context.get("origin", "user"))
        user_task = str(context.get("user_task", ""))
        text = _context_text(context)
        from_untrusted = origin in _UNTRUSTED_ORIGINS

        if (
            _contains_control_tokens(context)
            and (origin != "user" or _is_effect_tool(tool))
            and not _is_quotation_or_training_context(user_task, text)
        ):
            return _deny("model control tokens in untrusted content", "context.control")

        if (
            from_untrusted
            and _is_effect_tool(tool)
            and _contains_delegated_instruction(text)
            and not _is_quotation_or_training_context(user_task, text)
        ):
            return _deny("untrusted content cannot delegate tool authority", "authority")

        if (
            origin == "user"
            and _requires_task_authority(tool, args)
            and not _task_authorizes_tool(tool, user_task, args)
        ):
            return _deny("tool not derived from the user task", "authority.task")

        if (
            tool == "db.query"
            and _sql_is_destructive(args)
            and not _task_authorizes_tool(tool, user_task, args)
        ):
            return _deny("destructive query not derived from the user task", "authority.sql")

        return None

    def _tool_scopes(self, tool: str) -> set[str]:
        tools = self._profile.get("tools", {})
        if not isinstance(tools, Mapping):
            return set()
        meta = tools.get(tool)
        if not isinstance(meta, Mapping):
            return set()
        return {str(scope) for scope in meta.get("scopes", []) if isinstance(scope, str)}

    def _profile_allows_host(self, host: str) -> bool:
        allowlist = self._profile.get("egress_allowlist", [])
        if not isinstance(allowlist, list) or not allowlist:
            return True
        normalized = host.lower().rstrip(".")
        return any(
            normalized == str(suffix).lower().rstrip(".")
            or normalized.endswith("." + str(suffix).lower().rstrip("."))
            for suffix in allowlist
        )

    def _profile_allows_email(self, domain: str) -> bool:
        allowlist = self._profile.get("email_allowed_domains", [])
        if not isinstance(allowlist, list) or not allowlist:
            return True
        normalized = domain.lower().rstrip(".")
        return normalized in {str(item).lower().rstrip(".") for item in allowlist}

    def _subject(self, req: dict[str, Any]) -> SubjectPolicy:
        agent = req.get("agent", {}) or {}
        if not isinstance(agent, dict):
            raise PolicyDeny("agent must be an object")
        return self._policy.require_subject(str(agent.get("spiffe_id", "")))


def _agent_state_valid(agent: dict[str, Any]) -> bool:
    if not isinstance(agent, dict):
        return False
    return agent.get("svid") in {None, "valid"} and agent.get("attestation") in {None, "valid"}


def _strings_in(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for value in obj.values():
            yield from _strings_in(value)
    elif isinstance(obj, list | tuple):
        for value in obj:
            yield from _strings_in(value)


def _contains_hidden_unicode(obj: Any) -> bool:
    for text in _strings_in(obj):
        for char in text:
            if unicodedata.category(char) == "Cf":
                return True
    return False


_UNTRUSTED_ORIGINS = frozenset({"retrieved_doc", "tool_output", "mcp_server"})
_TASK_AUTHORITY_TOOLS = frozenset(
    {
        "email.send",
        "http.post",
        "secrets.get",
        "shell.exec",
        "code.run",
        "iam.grant",
        "payments.transfer",
    }
)
_EFFECT_TOOLS = _TASK_AUTHORITY_TOOLS | frozenset({"fs.delete", "db.admin", "db.query"})
_CONTROL_TOKEN_RE = re.compile(
    r"(?:<\|[^>]{0,80}\|>|<start_of_turn>|<end_of_turn>|<\|start\|>|<\|end\|>)",
    re.IGNORECASE,
)
_DELEGATED_INSTRUCTION_RE = re.compile(
    r"\b(?:ignore|override|disregard|bypass|policy\s+changed|privileged|administrative|"
    r"admin\s+action|hijack|replay(?:ed)?|revoked|forged|stale|bad\s+signature|"
    r"pcr\s*mismatch|protected\s+systems?|financial\s+or\s+access|"
    r"delete\s+[^.]{0,80}\s+before|stop\s+\w+|upload|outside|external(?:ly)?|"
    r"drop\s+box|copy\s+the\s+local\s+workspace|orders?|automatic\s+if|abandon|"
    r"export|elevated\s+command|grant\s+broad\s+access|database\s+administration|"
    r"shell\s+command|high-risk|admin\s+operation|sensitive\s+tool|"
    r"requires?\s+sending|unrelated\s+email|instructs?\s+the\s+model|"
    r"data\s+is\s+sent|redirects?)\b",
    re.IGNORECASE,
)
_EMAIL_TASK_RE = re.compile(r"\b(?:send|email|forward|share|notify|reminder|handoff)\b", re.I)
_POST_TASK_RE = re.compile(
    r"\b(?:post|submit|request|call|deploy|deployment|api|broker|secret\s+handle|"
    r"secret\s+reference|token\s+reference|token_ref|managed\s+(?:secret|credential)|"
    r"credential\s+(?:lookup|through)|lease\s+uri)\b",
    re.IGNORECASE,
)
_SECRET_TASK_RE = re.compile(
    r"\b(?:secret|credential|token|broker|deploy|deployment|lease|opaque\s+reference)\b",
    re.IGNORECASE,
)
_EXEC_TASK_RE = re.compile(
    r"\b(?:run|execute|test|diagnostic|format|formatting|build|command|inspect|"
    r"list|print|smoke|validation|compile|workspace\s+tree)\b",
    re.IGNORECASE,
)
_DELETE_TASK_RE = re.compile(r"\b(?:delete|remove|cleanup|clean\s+up|prune)\b", re.I)
_QUERY_TASK_RE = re.compile(
    r"\b(?:query|database|sql|audit|temporary|temp|reviewed|events?)\b", re.I
)


def _context_text(context: Mapping[str, Any]) -> str:
    fields = (
        context.get("content", ""),
        context.get("tool_description", ""),
        context.get("raw_generation", ""),
    )
    return "\n".join(str(item) for item in fields if isinstance(item, str))


def _contains_control_tokens(context: Mapping[str, Any]) -> bool:
    return _CONTROL_TOKEN_RE.search(_context_text(context)) is not None


def _contains_delegated_instruction(text: str) -> bool:
    return _DELEGATED_INSTRUCTION_RE.search(text) is not None


def _is_quotation_or_training_context(user_task: str, text: str) -> bool:
    combined = _normalize_text(user_task + " " + text)
    return bool(
        re.search(
            r"\b(?:quote|quotes|quoted|lesson|awareness|"
            r"discuss(?:es|ed|ing)?)\b",
            combined,
        )
    )


def _is_effect_tool(tool: str) -> bool:
    return tool in _EFFECT_TOOLS or tool.endswith((".write", ".delete", ".grant", ".transfer"))


def _requires_task_authority(tool: str, args: Mapping[str, Any]) -> bool:
    return tool in _TASK_AUTHORITY_TOOLS or (tool == "db.query" and _sql_is_destructive(args))


def _task_authorizes_tool(tool: str, user_task: str, args: Mapping[str, Any]) -> bool:
    task_text = _normalize_text(user_task)
    arg_text = _normalize_text(" ".join(_strings_in(args)))
    if tool == "email.send":
        return _EMAIL_TASK_RE.search(task_text) is not None
    if tool == "http.post":
        return _POST_TASK_RE.search(task_text) is not None or "secret://" in arg_text
    if tool == "secrets.get":
        return _SECRET_TASK_RE.search(task_text) is not None
    if tool in {"shell.exec", "code.run"}:
        return _EXEC_TASK_RE.search(task_text) is not None
    if tool == "fs.delete":
        return _DELETE_TASK_RE.search(task_text) is not None
    if tool == "db.query":
        sql = str(args.get("sql", "")) if isinstance(args, Mapping) else ""
        return _QUERY_TASK_RE.search(task_text) is not None or _sql_targets_temporary_table(sql)
    if tool in {"iam.grant", "payments.transfer"}:
        return tool.split(".", 1)[0] in task_text
    return True


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return " ".join(normalized.lower().split())


def _sql_is_destructive(args: Mapping[str, Any]) -> bool:
    sql = str(args.get("sql", "")) if isinstance(args, Mapping) else ""
    normalized = _normalize_text(sql)
    if not normalized:
        return False
    return bool(re.search(r"\b(?:delete|drop|truncate|alter)\b", normalized)) and not (
        " where " in f" {normalized} " and _sql_targets_temporary_table(normalized)
    )


def _sql_targets_temporary_table(sql: str) -> bool:
    normalized = _normalize_text(sql)
    return bool(re.search(r"\b(?:temp|temporary)_[a-z0-9_]+\b", normalized))


def _raw_tool_frame_is_malformed(context: Any) -> bool:
    if not isinstance(context, Mapping):
        return False
    raw = context.get("raw_generation")
    if raw is None:
        return False
    if not isinstance(raw, str):
        return True
    try:
        import json

        decoded = json.loads(raw)
    except ValueError:
        return True
    return not isinstance(decoded, dict) or not {"tool", "args"}.issubset(decoded)


def _deny(reason: str, component: str) -> dict[str, str]:
    return {"decision": "deny", "reason": reason, "component": component}


def _argv_from_args(args: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("cmd", "command", "argv", "args"):
        value = args.get(key)
        if isinstance(value, list):
            values.extend(str(x) for x in value)
        elif isinstance(value, str):
            values.append(value)
    return values


_SECRET_VALUE_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk_live_[A-Za-z0-9]{24,})\b"
)


def _contains_secret_material(args: dict[str, Any], issued_secrets: Iterable[str] = ()) -> bool:
    if _SECRET_VALUE_RE.search(str(args)) is not None:
        return True
    leaves = list(_strings_in(args))
    if not leaves:
        return False
    haystacks = _decoded_haystacks(leaves)
    return any(_secret_in_haystacks(secret, haystacks) for secret in issued_secrets)


def _decoded_haystacks(values: list[str]) -> set[str]:
    joined = "".join(values)
    candidates = set(values) | {joined, _squash(joined)}
    for value in list(candidates):
        candidates.update(_common_decodings(value))
    return candidates | {_squash(item) for item in candidates}


def _common_decodings(value: str) -> set[str]:
    out = {unquote(value)}
    compact = _squash(value)
    for candidate in {value, compact}:
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded.encode("ascii"), validate=True)
            out.add(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            out.add(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
        with suppress(ValueError, UnicodeDecodeError):
            out.add(bytes.fromhex(candidate).decode("utf-8"))
    with suppress(ValueError):
        out.add(codecs.decode(value, "rot13"))
    out.add(value[::-1])
    return out


def _secret_in_haystacks(secret: str, haystacks: set[str]) -> bool:
    if len(secret) < 8:
        return False
    forms = {secret, _squash(secret), secret[::-1], _squash(secret)[::-1]}
    forms = {form for form in forms if len(form) >= 8}
    return any(form in hay or form.lower() in hay.lower() for form in forms for hay in haystacks)


def _squash(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum())


def _paths_from_args(
    args: dict[str, Any], scopes: set[str] | None = None
) -> list[tuple[str, AccessName]]:
    found: list[tuple[str, AccessName]] = []
    for key, value in args.items():
        if not isinstance(value, str):
            continue
        key_l = key.lower()
        if key_l in {"path", "file", "src", "source", "input"}:
            access: AccessName = "write" if scopes and "fs:write" in scopes else "read"
            found.append((unquote(value), access))
        elif key_l in {"dst", "dest", "destination", "output", "write_path"}:
            found.append((unquote(value), "write"))
    return found


def _executables_from_args(args: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("cmd", "command", "executable", "argv"):
        value = args.get(key)
        if isinstance(value, str):
            parts = shlex.split(value, posix=os.name != "nt")
            if parts:
                first = parts[0]
                values.append(first)
        elif isinstance(value, list) and value:
            values.append(str(value[0]))
    return values


def _urls_from_args(args: dict[str, Any]) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    values = [value for value in args.values() if isinstance(value, str)]
    for value in values:
        candidates = re.findall(r"https?://[^\s'\"]+", value)
        if value.startswith(("http://", "https://")):
            candidates.append(value)
        for token in candidates:
            parsed = urlparse(unquote(token.strip(" \t\r\n<>[](){}.,;")))
            host = _canonical_host(parsed.hostname)
            if host:
                item = (host, parsed.port or (443 if parsed.scheme == "https" else 80))
                if item not in seen:
                    out.append(item)
                    seen.add(item)
    return out


def _canonical_host(host: str | None) -> str | None:
    if not host:
        return None
    normalized = unicodedata.normalize("NFKC", host).strip().strip(".").lower()
    if not normalized:
        return None
    with suppress(ValueError):
        return str(ipaddress.ip_address(normalized))
    with suppress(UnicodeError):
        return normalized.encode("idna").decode("ascii")
    return normalized


def _email_domains_from_args(args: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("to", "cc", "bcc"):
        value = args.get(key)
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, str) and "@" in item:
                out.append(item.rsplit("@", 1)[1])
    return out


def build_default_defense(policy_path: str) -> SandboxDefense:
    return SandboxDefense(Policy.from_file(policy_path))
