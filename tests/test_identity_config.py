"""
Tests for per-verification IdentityConfig (legacy vs. RFC 9525 strict).
"""

import datetime
import ipaddress

import attr
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import service_identity

from service_identity import IdentityRuleError
from service_identity.cryptography import (
    verify_certificate_hostname,
    verify_certificate_ip_address,
)
from service_identity.exceptions import CertificateError, VerificationError
from service_identity.hazmat import (
    DNS_ID,
    DNSPattern,
    IdentityConfig,
    verify_service_identity,
)


try:
    import idna
except ImportError:
    idna = None


STRICT = IdentityConfig.strict()


def _make_cert(dns_names=(), ip_addresses=()):
    """
    Create a self-signed certificate with the given SANs locally.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    san = x509.SubjectAlternativeName(
        [x509.DNSName(n) for n in dns_names]
        + [x509.IPAddress(ipaddress.ip_address(a)) for a in ip_addresses]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )


CERT_SIMPLE = _make_cert(dns_names=["www.example.com"])
CERT_WILDCARD = _make_cert(dns_names=["*.example.com"])
CERT_IDN = _make_cert(dns_names=["xn--bcher-kva.example.com"])
CERT_INVALID_SYNTAX = _make_cert(dns_names=["foo..example.com"])
CERT_PARTIAL_WILDCARD = _make_cert(dns_names=["ww*.example.com"])
CERT_MIXED_INVALID = _make_cert(
    dns_names=["foo..example.com", "www.example.com"]
)
CERT_IPV6 = _make_cert(ip_addresses=["2001:db8::1"])
CERT_DNS_IP_LOOKALIKE = _make_cert(dns_names=["10.0.0.1"])


class TestIdentityConfig:
    def test_defaults_are_legacy(self):
        """
        The default config tolerates everything the historical
        implementation tolerated.
        """
        assert IdentityConfig() == IdentityConfig(
            allow_partial_wildcards=True,
            allow_invalid_dns_syntax=True,
            allow_trailing_dot=True,
        )

    def test_strict_disallows_all(self):
        """
        The strict preset disables all legacy tolerances.
        """
        assert IdentityConfig.strict() == IdentityConfig(
            allow_partial_wildcards=False,
            allow_invalid_dns_syntax=False,
            allow_trailing_dot=False,
        )

    def test_immutable(self):
        """
        Configs are frozen so they can be shared between verifications.
        """
        with pytest.raises(attr.exceptions.FrozenInstanceError):
            IdentityConfig.strict().allow_trailing_dot = True


class TestStrictPass:
    """
    Cases that pass under both the strict and the legacy configuration.
    """

    @pytest.mark.parametrize("config", [None, IdentityConfig(), STRICT])
    def test_simple(self, config):
        verify_certificate_hostname(
            CERT_SIMPLE, "www.example.com", config=config
        )

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_case_insensitive(self, config):
        """
        DNS matching is case-insensitive in both configurations.
        """
        verify_certificate_hostname(
            CERT_SIMPLE, "WWW.Example.COM", config=config
        )

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_wildcard(self, config):
        verify_certificate_hostname(
            CERT_WILDCARD, "www.example.com", config=config
        )

    @pytest.mark.skipif(idna is None, reason="idna not installed")
    @pytest.mark.parametrize("config", [None, STRICT])
    def test_unicode_ulabel_matches_alabel(self, config):
        """
        A U-label DNS-ID matches the A-label SAN from the certificate.
        """
        verify_certificate_hostname(
            CERT_IDN, "bücher.example.com", config=config
        )

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_ipv6(self, config):
        verify_certificate_ip_address(CERT_IPV6, "2001:db8::1", config=config)

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_ipv6_normalized(self, config):
        """
        Different spellings of the same IPv6 address match.
        """
        verify_certificate_ip_address(
            CERT_IPV6, "2001:0db8:0000:0:0:0:0:1", config=config
        )


class TestLegacyOnlyPass:
    """
    Cases that pass only under the legacy configuration.
    """

    def test_invalid_dns_syntax_san(self):
        """
        A SAN with an empty label matches under legacy rules.
        """
        verify_certificate_hostname(CERT_INVALID_SYNTAX, "foo..example.com")

    def test_default_config_is_legacy(self):
        """
        Omitting config keeps the legacy behavior.
        """
        verify_certificate_hostname(
            CERT_INVALID_SYNTAX, "foo..example.com", config=IdentityConfig()
        )

    def test_strict_rejects_invalid_dns_syntax_san(self):
        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_INVALID_SYNTAX, "foo..example.com", config=STRICT
            )

        assert ei.value.rule == "allow_invalid_dns_syntax"

    def test_invalid_san_is_not_ignored(self):
        """
        Under strict rules, an invalid SAN fails the verification even if
        another SAN would match: it is not skipped in favor of a more
        lenient candidate.
        """
        verify_certificate_hostname(CERT_MIXED_INVALID, "www.example.com")

        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_MIXED_INVALID, "www.example.com", config=STRICT
            )

        assert ei.value.rule == "allow_invalid_dns_syntax"


class TestBothReject:
    """
    Cases that are rejected under both configurations.
    """

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_wildcard_matches_exactly_one_label(self, config):
        """
        A wildcard does not match multiple sub-domain levels.
        """
        with pytest.raises(VerificationError):
            verify_certificate_hostname(
                CERT_WILDCARD, "a.b.example.com", config=config
            )

    @pytest.mark.skipif(idna is None, reason="idna not installed")
    @pytest.mark.parametrize("config", [None, STRICT])
    def test_wildcard_does_not_match_alabel(self, config):
        """
        A wildcard does not match an IDNA A-label head.
        """
        with pytest.raises(VerificationError):
            verify_certificate_hostname(
                CERT_WILDCARD, "bücher.example.com", config=config
            )

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_ip_literal_is_not_a_dns_name(self, config):
        """
        An IP literal is rejected as a DNS-ID: DNS and IP identities stay
        distinct types.
        """
        with pytest.raises(ValueError, match="Invalid DNS-ID"):
            verify_certificate_hostname(
                CERT_IPV6, "2001:db8::1", config=config
            )

    @pytest.mark.parametrize("config", [None, STRICT])
    def test_dns_san_with_ip_lookalike_rejected(self, config):
        """
        A DNS SAN that looks like an IP address is invalid certificate
        data, not a DNS match candidate.
        """
        with pytest.raises(CertificateError, match="Invalid DNS pattern"):
            verify_certificate_hostname(
                CERT_DNS_IP_LOOKALIKE, "example.com", config=config
            )


class TestTrailingDot:
    def test_legacy_accepts_id_but_never_matches(self):
        """
        Legacy tolerates a trailing dot in the DNS-ID, but it doesn't
        match the certificate.
        """
        with pytest.raises(VerificationError):
            verify_certificate_hostname(CERT_SIMPLE, "www.example.com.")

    def test_strict_rejects_with_named_rule(self):
        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_SIMPLE, "www.example.com.", config=STRICT
            )

        assert ei.value.rule == "allow_trailing_dot"
        assert "www.example.com." in str(ei.value)


class TestPartialWildcard:
    def test_legacy_tolerates_but_never_matches(self):
        """
        Legacy keeps a partial-wildcard SAN, but it matches nothing.
        """
        with pytest.raises(VerificationError):
            verify_certificate_hostname(
                CERT_PARTIAL_WILDCARD, "ww1.example.com"
            )

    def test_strict_rejects_with_named_rule(self):
        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_PARTIAL_WILDCARD, "ww1.example.com", config=STRICT
            )

        assert ei.value.rule == "allow_partial_wildcards"

    def test_strict_rejects_regardless_of_hostname(self):
        """
        The invalid SAN fails verification even for a hostname that does
        not involve the wildcard.
        """
        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_PARTIAL_WILDCARD, "example.com", config=STRICT
            )

        assert ei.value.rule == "allow_partial_wildcards"


class TestMigration:
    """
    A migrating caller can tell which rule to adjust and relax rules
    individually per verification.
    """

    def test_rule_names_config_field(self):
        """
        IdentityRuleError.rule names the IdentityConfig field that
        governs the violated rule.
        """
        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_INVALID_SYNTAX, "foo..example.com", config=STRICT
            )

        assert ei.value.rule == "allow_invalid_dns_syntax"
        assert hasattr(IdentityConfig, ei.value.rule)

    def test_relax_single_rule(self):
        """
        Relaxing exactly the reported rule lets the legacy service pass
        while keeping the other strict rules.
        """
        config = attr.evolve(STRICT, allow_invalid_dns_syntax=True)

        verify_certificate_hostname(
            CERT_INVALID_SYNTAX, "foo..example.com", config=config
        )

        # The other strict rules are still active.
        with pytest.raises(IdentityRuleError) as ei:
            verify_certificate_hostname(
                CERT_SIMPLE, "www.example.com.", config=config
            )

        assert ei.value.rule == "allow_trailing_dot"

    def test_error_is_certificate_error(self):
        """
        IdentityRuleError is a CertificateError for backward-compatible
        error handling.
        """
        with pytest.raises(CertificateError):
            verify_certificate_hostname(
                CERT_PARTIAL_WILDCARD, "ww1.example.com", config=STRICT
            )

    def test_exported_from_top_level(self):
        assert service_identity.IdentityRuleError is IdentityRuleError


class TestHazmat:
    """
    The hazmat layer shares the same config semantics.
    """

    def test_verify_service_identity_config(self):
        """
        verify_service_identity accepts an optional config and enforces
        it on cert patterns.
        """
        patterns = [DNSPattern.from_bytes(b"foo..example.com")]

        verify_service_identity(patterns, [DNS_ID("foo..example.com")], [])

        with pytest.raises(IdentityRuleError) as ei:
            verify_service_identity(
                patterns,
                [DNS_ID("foo..example.com")],
                [],
                config=STRICT,
            )

        assert ei.value.rule == "allow_invalid_dns_syntax"

    def test_verify_service_identity_trailing_dot_id(self):
        """
        The trailing-dot rule applies to service IDs, not only patterns.
        """
        patterns = [DNSPattern.from_bytes(b"www.example.com")]

        with pytest.raises(IdentityRuleError) as ei:
            verify_service_identity(
                patterns,
                [DNS_ID("www.example.com.")],
                [],
                config=STRICT,
            )

        assert ei.value.rule == "allow_trailing_dot"

    def test_no_patterns_still_certificate_error(self):
        """
        The missing-SAN error is unaffected by configs.
        """
        with pytest.raises(CertificateError, match="subjectAltName"):
            verify_service_identity([], [], [], config=STRICT)


class TestPyOpenSSL:
    """
    The pyOpenSSL frontend shares the same config semantics.
    """

    @pytest.fixture(autouse=True)
    def _require_pyopenssl(self):
        pytest.importorskip("OpenSSL")

    @staticmethod
    def _connection(cert):
        from OpenSSL.crypto import X509

        class FakeConnection:
            def get_peer_certificate(self):
                return X509.from_cryptography(cert)

        return FakeConnection()

    def test_strict_pass(self):
        from service_identity.pyopenssl import verify_hostname

        verify_hostname(
            self._connection(CERT_SIMPLE), "www.example.com", config=STRICT
        )

    def test_strict_trailing_dot(self):
        from service_identity.pyopenssl import verify_hostname

        with pytest.raises(IdentityRuleError) as ei:
            verify_hostname(
                self._connection(CERT_SIMPLE),
                "www.example.com.",
                config=STRICT,
            )

        assert ei.value.rule == "allow_trailing_dot"

    def test_legacy_default_unchanged(self):
        from service_identity.pyopenssl import verify_hostname

        with pytest.raises(VerificationError):
            verify_hostname(self._connection(CERT_SIMPLE), "www.example.com.")

    def test_strict_ipv6(self):
        from service_identity.pyopenssl import verify_ip_address

        verify_ip_address(
            self._connection(CERT_IPV6), "2001:db8::1", config=STRICT
        )
