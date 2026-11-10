"""
Cross-entry regression tests for the corpus in tests/corpus.py.

Every corpus case is evaluated through three entry points and each result
is compared against the case's hand-written expectation:

1. the ``cryptography`` adapter
   (:func:`service_identity.cryptography.extract_patterns`),
2. the ``pyOpenSSL`` adapter
   (:func:`service_identity.pyopenssl.extract_patterns`),
3. the low-level matching API
   (:func:`service_identity.hazmat.verify_service_identity`) fed with the
   case's independent, hand-written pattern oracle.

Because the pyOpenSSL adapter delegates extraction to the cryptography
adapter, equality between the two is *not* treated as evidence of
correctness; both must independently satisfy the expectation.
"""

from __future__ import annotations

import re

from dataclasses import dataclass

import pytest

from cryptography.x509 import ObjectIdentifier

from service_identity import cryptography as crypto_mod
from service_identity import pyopenssl as po_mod
from service_identity.exceptions import (
    CertificateError,
    VerificationError,
)
from service_identity.hazmat import (
    DNS_ID,
    IPAddress_ID,
    verify_service_identity,
)

from .corpus import (
    CASES,
    ExpectMalformed,
    ExpectMatch,
    ExpectMismatch,
    ExpectParserReject,
    StubCertificate,
)


if pytest.importorskip("OpenSSL"):
    from OpenSSL.crypto import FILETYPE_ASN1, load_certificate

from cryptography.hazmat.primitives import serialization


@dataclass
class Outcome:
    """Normalized result of running one entry point on one case."""

    kind: str  # "match" | "mismatch" | "malformed" | "parser-reject"
    message: str = ""
    error_types: tuple = ()
    matched: list = None  # type: ignore[assignment]
    patterns: list | None = None


def _verify_outcome(patterns, case) -> Outcome:
    try:
        matches = verify_service_identity(
            cert_patterns=patterns,
            obligatory_ids=list(case.obligatory_ids),
            optional_ids=list(case.optional_ids),
        )
    except CertificateError as e:
        return Outcome(kind="malformed", message=str(e), patterns=patterns)
    except VerificationError as e:
        return Outcome(
            kind="mismatch",
            error_types=tuple(type(err) for err in e.errors),
            patterns=patterns,
        )
    return Outcome(
        kind="match",
        matched=[m.service_id for m in matches],
        patterns=patterns,
    )


def evaluate(extract, cert, case) -> Outcome:
    """Run *extract* + verify_service_identity, normalizing the result."""
    try:
        patterns = extract(cert)
    except CertificateError as e:
        return Outcome(kind="malformed", message=str(e))
    except ValueError as e:
        # cryptography's own DER parser rejected the certificate before
        # service-identity logic could run.
        return Outcome(kind="parser-reject", message=str(e))
    return _verify_outcome(patterns, case)


def _unique(ids):
    out = []
    for i in ids:
        if i not in out:
            out.append(i)
    return out


def matches_expectation(expected, outcome) -> bool:
    if isinstance(expected, ExpectMatch):
        return outcome.kind == "match" and _unique(
            outcome.matched
        ) == _unique(list(expected.matched))
    if isinstance(expected, ExpectMismatch):
        return (
            outcome.kind == "mismatch"
            and outcome.error_types == expected.errors
        )
    if isinstance(expected, ExpectMalformed):
        return outcome.kind == "malformed" and (
            expected.match is None
            or re.search(expected.match, outcome.message)
        )
    if isinstance(expected, ExpectParserReject):
        return outcome.kind == "parser-reject"
    raise AssertionError(f"unknown expectation {expected!r}")


def assert_outcome(expected, outcome, where):
    assert matches_expectation(expected, outcome), (
        f"{where}: expected {expected!r}, got {outcome!r}"
    )


def as_pyopenssl(cert):
    """Convert a corpus certificate into the pyOpenSSL-side input."""
    if isinstance(cert, StubCertificate):
        # Duck-typed pyOpenSSL X509: only to_cryptography() is used.
        class _StubX509:
            def to_cryptography(self):
                return cert

        return _StubX509()
    return load_certificate(
        FILETYPE_ASN1, cert.public_bytes(serialization.Encoding.DER)
    )


class FakeConnection:
    def __init__(self, cert):
        self._cert = cert

    def get_peer_certificate(self):
        return self._cert


class TestCrossEntryCorpus:
    @pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
    def test_cryptography_entry(self, case):
        """
        The cryptography adapter reaches the hand-written security
        conclusion and extracts exactly the oracle patterns.
        """
        outcome = evaluate(crypto_mod.extract_patterns, case.cert, case)
        assert_outcome(case.expected, outcome, "cryptography entry")
        if case.expected_patterns is not None:
            assert list(case.expected_patterns) == list(outcome.patterns)

    @pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
    def test_pyopenssl_entry(self, case):
        """
        The pyOpenSSL adapter reaches the same hand-written conclusion and
        the DER round-trip through OpenSSL loses no patterns.
        """
        outcome = evaluate(
            po_mod.extract_patterns, as_pyopenssl(case.cert), case
        )
        assert_outcome(case.expected, outcome, "pyOpenSSL entry")
        if case.expected_patterns is not None:
            assert list(case.expected_patterns) == list(outcome.patterns)

    @pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
    def test_hazmat_oracle(self, case):
        """
        verify_service_identity fed with the independent hand-written
        patterns reaches the same conclusion; low-level oracles confirm
        malformed samples really are malformed.
        """
        if case.oracle is not None:
            case.oracle()
        if case.expected_patterns is None:
            pytest.skip("extraction-level case without pattern oracle")
        outcome = _verify_outcome(list(case.expected_patterns), case)
        assert_outcome(case.expected, outcome, "hazmat oracle")


def _public_api_cases():
    """
    Cases that map onto the public verify_* APIs: exactly one obligatory
    DNS_ID or IPAddress_ID and no optional IDs.
    """
    out = []
    for case in CASES:
        if len(case.obligatory_ids) != 1 or case.optional_ids:
            continue
        if isinstance(case.obligatory_ids[0], (DNS_ID, IPAddress_ID)):
            out.append(case)
    return out


class TestPublicAPIEntries:
    @pytest.mark.parametrize(
        "case", _public_api_cases(), ids=[c.id for c in _public_api_cases()]
    )
    def test_verify_certificate_public_api(self, case):
        """
        The public verify_certificate_hostname / verify_certificate_ip_address
        and verify_hostname / verify_ip_address entries reach the same
        conclusion as the corpus expectation.
        """
        sid = case.obligatory_ids[0]
        if isinstance(sid, DNS_ID):
            target = sid.hostname.decode("ascii")
            crypto_run = lambda: crypto_mod.verify_certificate_hostname(
                case.cert, target
            )
            po_run = lambda: po_mod.verify_hostname(
                FakeConnection(as_pyopenssl(case.cert)), target
            )
        else:
            target = str(sid.ip)
            crypto_run = lambda: crypto_mod.verify_certificate_ip_address(
                case.cert, target
            )
            po_run = lambda: po_mod.verify_ip_address(
                FakeConnection(as_pyopenssl(case.cert)), target
            )

        for where, run in [("cryptography", crypto_run), ("pyOpenSSL", po_run)]:
            outcome = _capture_public(run)
            if isinstance(case.expected, ExpectMatch):
                # The public APIs return None on success, so only the
                # conclusion kind is observable here.
                assert outcome.kind == "match", (
                    f"{where} public API: expected match, got {outcome!r}"
                )
            else:
                assert_outcome(case.expected, outcome, f"{where} public API")


def _capture_public(run) -> Outcome:
    try:
        run()
    except CertificateError as e:
        return Outcome(kind="malformed", message=str(e))
    except ValueError as e:
        return Outcome(kind="parser-reject", message=str(e))
    except VerificationError as e:
        return Outcome(
            kind="mismatch",
            error_types=tuple(type(err) for err in e.errors),
        )
    return Outcome(kind="match", matched=[])


class TestMutationCheck:
    def test_corpus_detects_disabled_srv_othername(self, monkeypatch):
        """
        Mutation check: pretending id-on-dnsSRV is an unknown OID (i.e.
        skipping known-OtherName verification entirely) must change the
        outcome of the SRV corpus cases.  If it did not, the corpus would
        not actually exercise OtherName verification.
        """
        monkeypatch.setattr(
            crypto_mod, "ID_ON_DNS_SRV", ObjectIdentifier("1.2.3.4.999")
        )

        diverged = []
        for case in CASES:
            outcome = evaluate(crypto_mod.extract_patterns, case.cert, case)
            if not matches_expectation(case.expected, outcome):
                diverged.append(case.id)

        # The mutation must be killed by the SRV match/mismatch cases.
        assert "SRV-MATCH-001" in diverged
        assert "SRV-MISMATCH-002" in diverged
        # Cases without SRV otherNames must be unaffected by the mutation.
        assert "DNS-MATCH-001" not in diverged
        assert "IP-MATCH-001" not in diverged
        assert "URI-MATCH-001" not in diverged
