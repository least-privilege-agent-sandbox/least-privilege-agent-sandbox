from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("cryptography", reason="cryptography wheel unavailable on this platform")

from least_privilege_agent_sandbox.svid import SVIDCache, generate_test_ca, issue_test_svid


def test_cache_ttl_is_capped_by_certificate_expiry() -> None:
    ca = generate_test_ca()
    _, cert = issue_test_svid(ca, "spiffe://ztap.test/agent/short", ttl=timedelta(seconds=20))
    cache = SVIDCache([ca.certificate])
    validation = cache.validate(cert)
    entry = cache._entries[validation.fingerprint]
    assert entry.deadline_s <= cert.not_valid_after_utc.timestamp()


def test_lru_eviction_removes_oldest_entry() -> None:
    ca = generate_test_ca()
    cache = SVIDCache([ca.certificate], max_entries=2)
    certs = [issue_test_svid(ca, f"spiffe://ztap.test/agent/{idx}")[1] for idx in range(3)]
    vals = [cache.validate(cert) for cert in certs]
    assert vals[0].fingerprint not in cache._entries
    assert vals[1].fingerprint in cache._entries
    assert vals[2].fingerprint in cache._entries


def test_revocation_of_one_fingerprint_does_not_revoke_another() -> None:
    ca = generate_test_ca()
    _, cert_a = issue_test_svid(ca, "spiffe://ztap.test/agent/a")
    _, cert_b = issue_test_svid(ca, "spiffe://ztap.test/agent/b")
    cache = SVIDCache([ca.certificate])
    a = cache.validate(cert_a)
    b = cache.validate(cert_b)
    assert a.fingerprint != b.fingerprint
    cache.revoke(a.fingerprint)
    with pytest.raises(ValueError, match="revoked"):
        cache.validate(cert_a)
    assert cache.validate(cert_b).spiffe_id.endswith("/b")


def test_cache_entry_expires_at_cert_expiry() -> None:
    ca = generate_test_ca()
    _, cert = issue_test_svid(ca, "spiffe://ztap.test/agent/expiry", ttl=timedelta(seconds=1))
    cache = SVIDCache([ca.certificate])
    cache.validate(cert)
    future = datetime.now(UTC) + timedelta(seconds=3)
    with pytest.raises(ValueError, match="validity"):
        cache.validate(cert, now=future)
