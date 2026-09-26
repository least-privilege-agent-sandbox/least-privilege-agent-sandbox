from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("cryptography", reason="cryptography wheel unavailable on this platform")
from cryptography.hazmat.primitives import serialization

from least_privilege_agent_sandbox.svid import (
    SVIDCache,
    cert_pem,
    generate_test_ca,
    issue_test_svid,
)


def test_svid_cache_hit_and_revocation() -> None:
    ca = generate_test_ca()
    _, cert = issue_test_svid(ca, "spiffe://ztap.test/agent/agent-7")
    cache = SVIDCache([ca.certificate], max_entries=2)
    first = cache.validate_pem(cert_pem(cert))
    second = cache.validate(cert)
    assert first.spiffe_id == "spiffe://ztap.test/agent/agent-7"
    assert not first.cache_hit
    assert second.cache_hit
    cache.revoke(first.fingerprint)
    with pytest.raises(ValueError, match="revoked"):
        cache.validate(cert)


def test_svid_rejects_expired_and_wrong_ca() -> None:
    ca = generate_test_ca()
    other = generate_test_ca()
    _, expired = issue_test_svid(ca, "spiffe://ztap.test/agent/agent-7", ttl=timedelta(seconds=1))
    cache = SVIDCache([ca.certificate])
    future = datetime.now(UTC) + timedelta(seconds=5)
    with pytest.raises(ValueError, match="validity"):
        cache.validate(expired, now=future)
    with pytest.raises(ValueError, match="trust bundle"):
        SVIDCache([other.certificate]).validate(expired)


def test_svid_key_material_can_be_generated_for_cli() -> None:
    ca = generate_test_ca()
    key, cert = issue_test_svid(ca, "spiffe://ztap.test/agent/agent-7")
    assert b"BEGIN CERTIFICATE" in cert_pem(cert)
    assert b"BEGIN EC PRIVATE KEY" in key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
