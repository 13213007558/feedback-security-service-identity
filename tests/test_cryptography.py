import ipaddress

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    ExtensionOID,
    OtherName,
    SubjectAlternativeName,
    load_pem_x509_certificate,
)

from service_identity.cryptography import (
    ID_ON_DNS_SRV,
    extract_ids,
    extract_patterns,
    verify_certificate_hostname,
    verify_certificate_ip_address,
    verify_certificate_spiffe_id,
)
from service_identity.exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    SPIFFEMismatch,
    VerificationError,
)
from service_identity.hazmat import (
    DNS_ID,
    DNSPattern,
    IPAddress_ID,
    IPAddressPattern,
    SPIFFE_ID,
    SPIFFEPattern,
    SRVPattern,
    URIPattern,
)

from .certificates import (
    PEM_CN_ONLY,
    PEM_DNS_ONLY,
    PEM_EVERYTHING,
    PEM_OTHER_NAME,
    make_cert_with_sans,
)


backend = default_backend()
X509_DNS_ONLY = load_pem_x509_certificate(PEM_DNS_ONLY, backend)
X509_CN_ONLY = load_pem_x509_certificate(PEM_CN_ONLY, backend)
X509_OTHER_NAME = load_pem_x509_certificate(PEM_OTHER_NAME, backend)
CERT_EVERYTHING = load_pem_x509_certificate(PEM_EVERYTHING, backend)


class TestPublicAPI:
    def test_no_cert_patterns_hostname(self):
        """
        A certificate without subjectAltNames raises a helpful
        CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            verify_certificate_hostname(X509_CN_ONLY, "example.com")

    @pytest.mark.parametrize("ip", ["203.0.113.0", "2001:db8::"])
    def test_no_cert_patterns_ip_address(self, ip):
        """
        A certificate without subjectAltNames raises a helpful
        CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            verify_certificate_ip_address(X509_CN_ONLY, ip)

    def test_certificate_verify_hostname_ok(self):
        """
        verify_certificate_hostname succeeds if the hostnames match.
        """
        verify_certificate_hostname(X509_DNS_ONLY, "twistedmatrix.com")

    def test_certificate_verify_hostname_fail(self):
        """
        verify_certificate_hostname fails if the hostnames don't match and
        provides the user with helpful information.
        """
        with pytest.raises(VerificationError) as ei:
            verify_certificate_hostname(X509_DNS_ONLY, "google.com")

        assert [
            DNSMismatch(mismatched_id=DNS_ID("google.com"))
        ] == ei.value.errors

    @pytest.mark.parametrize("ip", ["1.1.1.1", "::1"])
    def test_verify_certificate_ip_address_ok(self, ip):
        """
        verify_certificate_ip_address succeeds if the addresses match. Works
        both with IPv4 and IPv6.
        """
        verify_certificate_ip_address(CERT_EVERYTHING, ip)

    @pytest.mark.parametrize("ip", ["1.1.1.2", "::2"])
    def test_verify_ip_address_fail(self, ip):
        """
        verify_ip_address fails if the addresses don't match and provides the
        user with helpful information.  Works both with IPv4 and IPv6.
        """
        with pytest.raises(VerificationError) as ei:
            verify_certificate_ip_address(CERT_EVERYTHING, ip)

        assert [
            IPAddressMismatch(mismatched_id=IPAddress_ID(ip))
        ] == ei.value.errors


class TestExtractPatterns:
    def test_dns(self):
        """
        Returns the correct DNSPattern from a certificate.
        """
        rv = extract_patterns(X509_DNS_ONLY)
        assert [
            DNSPattern.from_bytes(b"www.twistedmatrix.com"),
            DNSPattern.from_bytes(b"twistedmatrix.com"),
        ] == rv

    def test_cn_ids_are_ignored(self):
        """
        commonName is not supported anymore and therefore ignored.
        """
        assert [] == extract_patterns(X509_CN_ONLY)

    def test_uri(self):
        """
        Returns the correct URIPattern from a certificate.
        """
        rv = extract_patterns(X509_OTHER_NAME)
        assert [URIPattern.from_bytes(b"http://example.com/")] == [
            id for id in rv if isinstance(id, URIPattern)
        ]

    def test_srv(self):
        """
        Returns the correct SRVPattern from a certificate.
        """
        rv = extract_patterns(X509_OTHER_NAME)
        assert [SRVPattern.from_bytes(b"_xmpp-client.example.net")] == [
            id for id in rv if isinstance(id, SRVPattern)
        ]

    def test_malformed_srv_other_name(self):
        """
        Malformed DER in a SRV-ID otherName raises a CertificateError.
        """

        class Extension:
            def __init__(self, value):
                self.value = value

        class Extensions:
            def __init__(self, value):
                self._value = value

            def get_extension_for_oid(self, oid):
                assert oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME

                return Extension(self._value)

        class Certificate:
            def __init__(self, san):
                self.extensions = Extensions(san)

        cert = Certificate(
            SubjectAlternativeName(
                [OtherName(ID_ON_DNS_SRV, b"\x16\x03abc\x00")]
            )
        )

        with pytest.raises(
            CertificateError, match=r"Unexpected certificate content\."
        ):
            extract_patterns(cert)

    def test_ip(self):
        """
        Returns IP patterns.
        """
        rv = extract_patterns(CERT_EVERYTHING)

        assert [
            DNSPattern.from_bytes(pattern=b"service.identity.invalid"),
            DNSPattern.from_bytes(
                pattern=b"*.wildcard.service.identity.invalid"
            ),
            DNSPattern.from_bytes(pattern=b"service.identity.invalid"),
            DNSPattern.from_bytes(pattern=b"single.service.identity.invalid"),
            IPAddressPattern(pattern=ipaddress.IPv4Address("1.1.1.1")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("::1")),
            IPAddressPattern(pattern=ipaddress.IPv4Address("2.2.2.2")),
            IPAddressPattern(pattern=ipaddress.IPv6Address("2a00:1c38::53")),
        ] == rv

    def test_extract_ids_deprecated(self):
        """
        `extract_ids` raises a DeprecationWarning with correct stacklevel.
        """
        with pytest.deprecated_call() as wr:
            extract_ids(CERT_EVERYTHING)

        w = wr.pop()

        assert (
            "`extract_ids()` is deprecated, please use `extract_patterns()`."
            == w.message.args[0]
        )
        assert __file__ == w.filename


class TestVerifyCertificateSPIFFEID:
    def test_ok(self):
        """
        verify_certificate_spiffe_id succeeds if the certificate contains
        the exact SPIFFE ID and the trust domain is allowed. Returns the
        matches with the full identity.
        """
        cert = make_cert_with_sans(
            uris=["spiffe://example.com/ns/default/sa/web"]
        )

        matches = verify_certificate_spiffe_id(
            cert,
            "spiffe://example.com/ns/default/sa/web",
            ["example.com"],
        )

        assert 1 == len(matches)
        assert (
            SPIFFEPattern.from_bytes(b"spiffe://example.com/ns/default/sa/web")
            == matches[0].cert_pattern
        )
        assert (
            SPIFFE_ID("spiffe://example.com/ns/default/sa/web")
            == matches[0].service_id
        )

    def test_same_trust_domain_different_path_fails(self):
        """
        Same trust domain but a different path does not match: the path is
        part of the identity.
        """
        cert = make_cert_with_sans(uris=["spiffe://example.com/ns/a"])

        with pytest.raises(VerificationError) as ei:
            verify_certificate_spiffe_id(
                cert, "spiffe://example.com/ns/b", ["example.com"]
            )

        assert [
            SPIFFEMismatch(
                mismatched_id=SPIFFE_ID("spiffe://example.com/ns/b")
            )
        ] == ei.value.errors

    def test_lookalike_trust_domain_fails(self):
        """
        Lookalike trust domains neither match nor are allowed implicitly.
        """
        cert = make_cert_with_sans(uris=["spiffe://example.com/ns/a"])

        with pytest.raises(VerificationError):
            verify_certificate_spiffe_id(
                cert,
                "spiffe://example.com.evil.org/ns/a",
                ["example.com.evil.org"],
            )

    def test_trust_domain_not_allowed_fails(self):
        """
        Even a perfectly matching SPIFFE ID fails if the caller does not
        allow its trust domain: the certificate cannot widen the scope.
        """
        cert = make_cert_with_sans(uris=["spiffe://evil.org/ns/a"])

        with pytest.raises(VerificationError):
            verify_certificate_spiffe_id(
                cert, "spiffe://evil.org/ns/a", ["example.com"]
            )

    def test_multiple_spiffe_ids_rejected(self):
        """
        A certificate with more than one SPIFFE ID is rejected with
        CertificateError instead of picking one by order.
        """
        cert = make_cert_with_sans(
            uris=[
                "spiffe://example.com/ns/a",
                "spiffe://example.com/ns/b",
            ]
        )

        with pytest.raises(
            CertificateError,
            match="Certificate contains more than one SPIFFE ID",
        ):
            verify_certificate_spiffe_id(
                cert, "spiffe://example.com/ns/a", ["example.com"]
            )

    def test_invalid_spiffe_encoding_rejected(self):
        """
        A spiffe-scheme URI SAN with invalid encoding is a CertificateError,
        not a silently normalized identity.
        """
        cert = make_cert_with_sans(
            uris=["spiffe://example.com/%6e%73/a"]
        )

        with pytest.raises(CertificateError, match="Invalid SPIFFE pattern"):
            verify_certificate_spiffe_id(
                cert, "spiffe://example.com/ns/a", ["example.com"]
            )

    def test_ordinary_uri_san_cannot_impersonate(self):
        """
        An ordinary URI SAN never satisfies a SPIFFE-ID.
        """
        cert = make_cert_with_sans(uris=["https://example.com/ns/a"])

        with pytest.raises(VerificationError):
            verify_certificate_spiffe_id(
                cert, "spiffe://example.com/ns/a", ["example.com"]
            )

    def test_mixed_sans(self):
        """
        DNS and ordinary URI SANs coexist with a SPIFFE ID; only the SPIFFE
        ID is considered for SPIFFE verification.
        """
        cert = make_cert_with_sans(
            uris=[
                "https://example.com/",
                "spiffe://example.com/ns/default/sa/web",
            ],
            dns_names=["example.com"],
        )

        verify_certificate_spiffe_id(
            cert,
            "spiffe://example.com/ns/default/sa/web",
            ["example.com"],
        )
        verify_certificate_hostname(cert, "example.com")


class TestExtractPatternsSPIFFE:
    def test_spiffe_uri_becomes_spiffe_pattern(self):
        """
        URI SANs with the spiffe scheme are extracted as SPIFFEPatterns.
        """
        cert = make_cert_with_sans(
            uris=["spiffe://example.com/ns/a", "https://example.com/"]
        )

        rv = extract_patterns(cert)

        assert [
            SPIFFEPattern.from_bytes(b"spiffe://example.com/ns/a"),
            URIPattern.from_bytes(b"https://example.com/"),
        ] == rv

    def test_invalid_spiffe_uri_raises(self):
        """
        A URI SAN claiming the spiffe scheme but violating the SPIFFE ID
        syntax raises CertificateError on extraction.
        """
        cert = make_cert_with_sans(uris=["spiffe://example.com/a b"])

        with pytest.raises(CertificateError, match="Invalid SPIFFE pattern"):
            extract_patterns(cert)
