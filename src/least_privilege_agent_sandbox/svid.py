"""X.509-SVID validation with bounded LRU caching."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Final, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass(frozen=True, slots=True)
class TestCA:
    private_key: EllipticCurvePrivateKey
    certificate: x509.Certificate

    def cert_pem(self) -> bytes:
        return bytes(self.certificate.public_bytes(serialization.Encoding.PEM))


@dataclass(frozen=True, slots=True)
class SVIDValidation:
    spiffe_id: str
    expires_at: datetime
    fingerprint: bytes
    cache_hit: bool
    latency_us: float


@dataclass(slots=True)
class _Entry:
    validation: SVIDValidation
    deadline_s: float


class SVIDCache:
    """Validate ECDSA X.509-SVIDs and cache by certificate fingerprint."""

    def __init__(self, trust_bundle: list[x509.Certificate], *, max_entries: int = 128) -> None:
        self._trust_bundle = trust_bundle
        self._max_entries = max_entries
        self._entries: OrderedDict[bytes, _Entry] = OrderedDict()
        self._revoked: set[bytes] = set()

    def revoke(self, fingerprint: bytes) -> None:
        self._revoked.add(fingerprint)
        self._entries.pop(fingerprint, None)

    def validate_pem(self, cert_pem: bytes, *, now: datetime | None = None) -> SVIDValidation:
        return self.validate(x509.load_pem_x509_certificate(cert_pem), now=now)

    def validate(self, cert: x509.Certificate, *, now: datetime | None = None) -> SVIDValidation:
        start = time.perf_counter_ns()
        now_dt = now or datetime.now(UTC)
        fp = cert.fingerprint(hashes.SHA256())
        if fp in self._revoked:
            raise ValueError("SVID certificate is revoked")
        now_s = now_dt.timestamp()
        cached = self._entries.get(fp)
        if cached is not None and cached.deadline_s > now_s:
            self._entries.move_to_end(fp)
            v = cached.validation
            return SVIDValidation(v.spiffe_id, v.expires_at, fp, True, _elapsed_us(start))

        self._validate_signature(cert)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if now_dt < not_before or now_dt >= not_after:
            raise ValueError("SVID certificate is outside its validity interval")
        san = cast(
            x509.SubjectAlternativeName,
            cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value,
        )
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        spiffe_uris = [uri for uri in uris if uri.startswith("spiffe://")]
        if len(spiffe_uris) != 1:
            raise ValueError("SVID must contain exactly one spiffe:// URI SAN")
        validation = SVIDValidation(spiffe_uris[0], not_after, fp, False, _elapsed_us(start))
        self._entries[fp] = _Entry(validation, min(not_after.timestamp(), now_s + 300.0))
        self._entries.move_to_end(fp)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
        return validation

    def _validate_signature(self, cert: x509.Certificate) -> None:
        for ca in self._trust_bundle:
            public_key = ca.public_key()
            if not isinstance(public_key, EllipticCurvePublicKey):
                continue
            try:
                signature_hash = cert.signature_hash_algorithm
                if signature_hash is None:
                    continue
                public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(signature_hash),
                )
                return
            except InvalidSignature:
                continue
        raise ValueError("SVID was not signed by the trust bundle")


def _elapsed_us(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1000.0


def generate_test_ca(*, common_name: str = "Least-Privilege Agent Sandbox Test CA") -> TestCA:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return TestCA(key, cert)


def issue_test_svid(
    ca: TestCA, spiffe_id: str, *, ttl: timedelta = timedelta(minutes=5)
) -> tuple[EllipticCurvePrivateKey, x509.Certificate]:
    if not spiffe_id.startswith("spiffe://"):
        raise ValueError("test SVID SPIFFE ID must start with spiffe://")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    subject: Final = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=5))
        .not_valid_after(now + ttl)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )
    return key, cert


def cert_pem(cert: x509.Certificate) -> bytes:
    return bytes(cert.public_bytes(serialization.Encoding.PEM))
