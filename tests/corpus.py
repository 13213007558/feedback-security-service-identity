"""
Cross-entry regression corpus for service identity verification.

Every case has a stable ID (e.g. ``DNS-MATCH-001``) so a single sample can
be replayed on its own::

    pytest tests/test_cross_entry_corpus.py -k DNS-MATCH-001

Expectations are hand-written from RFC 6125 semantics and the documented
``service-identity`` contract *before* any adapter output is consulted, so
the three entry points (``cryptography``, ``pyOpenSSL``, and the low-level
:func:`service_identity.hazmat.verify_service_identity`) are each checked
against an independent oracle -- never merely against each other.  This
matters because the pyOpenSSL adapter shares its extraction code with the
cryptography adapter: equality between the two would not detect a common
bug.

Outcomes are classified into three distinct expectations:

- ``ExpectMatch``: verification succeeds and exactly the given service IDs
  are matched.
- ``ExpectMismatch``: :class:`VerificationError` with exactly the given
  ``Mismatch`` types (a certificate that *has* a pattern type but does not
  match it is different from one that lacks the type entirely).
- ``ExpectMalformed``: :class:`CertificateError` -- the certificate content
  is invalid and must never be treated as a mere non-match.

A fourth, ``ExpectParserReject``, documents inputs that ``cryptography``'s
own DER parser rejects with :class:`ValueError` before service-identity's
extraction logic even runs.
"""

from __future__ import annotations

import datetime
import ipaddress

from dataclasses import dataclass
from typing import Any

import pytest

from cryptography import x509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    DNSName,
    ExtensionOID,
    IPAddress,
    ObjectIdentifier,
    OtherName,
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID

from service_identity.cryptography import ID_ON_DNS_SRV
from service_identity.exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    SRVMismatch,
    URIMismatch,
)
from service_identity.hazmat import (
    DNS_ID,
    IPAddress_ID,
    SRV_ID,
    URI_ID,
    DNSPattern,
    IPAddressPattern,
    SRVPattern,
    URIPattern,
)


# ---------------------------------------------------------------------------
# Certificate builder
# ---------------------------------------------------------------------------

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NOT_BEFORE = datetime.datetime(2024, 1, 1)
_NOT_AFTER = datetime.datetime(2025, 1, 1)


def build_cert(
    general_names: list[Any] | None,
    common_name: str = "corpus.service-identity.invalid",
) -> x509.Certificate:
    """
    Build a self-signed certificate carrying *general_names* as its
    subjectAltName extension.  ``None`` means the certificate has no SAN
    extension at all.
    """
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
    )
    if general_names is not None:
        builder = builder.add_extension(
            SubjectAlternativeName(general_names), critical=False
        )
    return builder.sign(_KEY, hashes.SHA256())


def _srv_other_name(value: bytes) -> OtherName:
    return OtherName(ID_ON_DNS_SRV, value)


def _ia5(text: str) -> bytes:
    return asn1.encode_der(asn1.IA5String(text))


# ---------------------------------------------------------------------------
# Raw DER samples for content the builder refuses to produce
# ---------------------------------------------------------------------------

#: DER of an SRV OtherName *value*: a valid IA5String "_xmpp.example.net"
#: (16 11 ...) followed by two trailing garbage bytes (DE AD).  The
#: certificate builder refuses it ("OtherName value must be valid DER") and
#: cryptography's own parser rejects a certificate carrying it, so the
#: sample is kept as raw bytes and injected through StubCertificate to
#: exercise service-identity's own error mapping.
SRV_OTHERNAME_VALUE_TRAILING = bytes.fromhex(
    "1611"  # IA5String, length 17
    "5f786d70702e6578616d706c652e6e6574"  # "_xmpp.example.net"
    "dead"  # trailing garbage
)

#: DER of an SRV OtherName *value* with the wrong type: INTEGER 5 instead
#: of the IA5String required for id-on-dnsSRV (RFC 4985).  The builder
#: accepts it because it is well-formed DER, so this sample also exists as
#: the real certificate SRV-WRONG-DER-005 below.
SRV_OTHERNAME_VALUE_WRONG_TYPE = bytes.fromhex("020105")

#: DER of a complete subjectAltName extension value whose only GeneralName
#: is an otherName/id-on-dnsSRV carrying SRV_OTHERNAME_VALUE_TRAILING.
#: Encoded by hand (implicit [0] around OID + explicit [0] value); used to
#: build SRV-TRAILING-REAL-007 via UnrecognizedExtension.
_SAN_SRV_TRAILING = bytes.fromhex(
    "3023"  # SEQUENCE, 35 bytes
    "a021"  # [0] otherName, 33 bytes
    "06082b06010505070807"  # OID 1.3.6.1.5.5.7.8.7 (id-on-dnsSRV)
    "a015"  # [0] EXPLICIT value, 21 bytes
) + SRV_OTHERNAME_VALUE_TRAILING


def _build_cert_with_raw_san(raw_san: bytes) -> x509.Certificate:
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "corpus.service-identity.invalid")]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(
            x509.UnrecognizedExtension(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME, raw_san
            ),
            critical=False,
        )
        .sign(_KEY, hashes.SHA256())
    )


# ---------------------------------------------------------------------------
# Stub certificates for malformed content no real parser accepts
# ---------------------------------------------------------------------------


class StubOtherName:
    """Duck-typed ``cryptography.x509.OtherName`` with arbitrary bytes."""

    def __init__(self, type_id: ObjectIdentifier, value: bytes):
        self.type_id = type_id
        self.value = value


class StubSubjectAlternativeName:
    """
    Duck-typed ``SubjectAlternativeName`` carrying OtherName values that
    the real ``cryptography`` parser would reject outright.
    """

    def __init__(self, other_names: list[StubOtherName]):
        self._other_names = other_names

    def get_values_for_type(self, general_name_type: type) -> list[Any]:
        if general_name_type is OtherName:
            return list(self._other_names)
        return []


class StubCertificate:
    """
    Duck-typed ``cryptography.x509.Certificate``; only ``.extensions`` is
    used by service-identity's extraction code.
    """

    def __init__(self, san_value: Any):
        self._san_value = san_value

    @property
    def extensions(self) -> Any:
        san_value = self._san_value

        class _Extensions:
            def get_extension_for_oid(self, oid):
                if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    return x509.Extension(
                        oid=oid, critical=False, value=san_value
                    )
                raise ExtensionNotFound("no such extension", oid)

        return _Extensions()


# ---------------------------------------------------------------------------
# Expectations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpectMatch:
    """Verification succeeds; exactly these service IDs are matched."""

    matched: tuple[Any, ...]


@dataclass(frozen=True)
class ExpectMismatch:
    """VerificationError carrying exactly these Mismatch types, in order."""

    errors: tuple[type, ...]


@dataclass(frozen=True)
class ExpectMalformed:
    """CertificateError is raised; optionally matching this message."""

    match: str | None = None


@dataclass(frozen=True)
class ExpectParserReject:
    """
    cryptography's own DER parser rejects the input with ValueError before
    service-identity logic runs.  Recorded separately from ExpectMalformed
    because the rejection happens outside service-identity's control.
    """


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    cert: Any
    obligatory_ids: tuple[Any, ...]
    optional_ids: tuple[Any, ...]
    expected: Any
    #: Hand-written pattern oracle for the hazmat entry; None when
    #: extraction itself is expected to fail.
    expected_patterns: tuple[Any, ...] | None
    #: Independent low-level oracle proving the input is what we claim
    #: (e.g. that a raw DER sample really is undecodable).
    oracle: Any = None


_DNS_WWW = DNSPattern(pattern=b"www.example.com")
_DNS_MAIL = DNSPattern(pattern=b"mail.example.com")
_DNS_WILDCARD = DNSPattern(pattern=b"*.example.com")
_DNS_WILDCARD_PARTIAL = DNSPattern(pattern=b"w*.example.com")
_URI_SIP = URIPattern(
    protocol_pattern=b"sip", dns_pattern=DNSPattern(pattern=b"example.com")
)
_URI_SIP_OTHER = URIPattern(
    protocol_pattern=b"sip",
    dns_pattern=DNSPattern(pattern=b"other.example.com"),
)
_IP_192 = IPAddressPattern(pattern=ipaddress.ip_address("192.0.2.1"))
_IP_V6 = IPAddressPattern(pattern=ipaddress.ip_address("2001:db8::1"))
_SRV_XMPP = SRVPattern(
    name_pattern=b"xmpp", dns_pattern=DNSPattern(pattern=b"example.net")
)

_CERT_DNS_WWW = build_cert([DNSName("www.example.com")])
_CERT_DNS_WWW_UPPER = build_cert([DNSName("WWW.EXAMPLE.COM")])
_CERT_DNS_WWW_DUP = build_cert(
    [DNSName("www.example.com"), DNSName("www.example.com")]
)
_CERT_DNS_WWW_MAIL = build_cert(
    [DNSName("www.example.com"), DNSName("mail.example.com")]
)
_CERT_DNS_WILDCARD = build_cert([DNSName("*.example.com")])
_CERT_DNS_WILDCARD_PARTIAL = build_cert([DNSName("w*.example.com")])
_CERT_DNS_WILDCARD_BAD = build_cert([DNSName("*.com")])
_CERT_DNS_IP_FORM = build_cert([DNSName("192.0.2.1")])
_CERT_DNS_EMPTY_SAN = build_cert([])
_CERT_NO_SAN = build_cert(None, common_name="www.example.com")
_CERT_IP_V4 = build_cert([IPAddress(ipaddress.ip_address("192.0.2.1"))])
_CERT_IP_V6 = build_cert([IPAddress(ipaddress.ip_address("2001:db8::1"))])
_CERT_URI_SIP = build_cert([UniformResourceIdentifier("sip:example.com")])
_CERT_SRV_XMPP = build_cert([_srv_other_name(_ia5("_xmpp.example.net"))])
_CERT_UNKNOWN_OTHER_ONLY = build_cert(
    [OtherName(ObjectIdentifier("1.2.3.4.567"), _ia5("_xmpp.example.net"))]
)
_CERT_UNKNOWN_OTHER_PLUS_DNS = build_cert(
    [
        OtherName(ObjectIdentifier("1.2.3.4.567"), _ia5("_xmpp.example.net")),
        DNSName("www.example.com"),
    ]
)
_CERT_SRV_WRONG_DER = build_cert(
    [_srv_other_name(SRV_OTHERNAME_VALUE_WRONG_TYPE)]
)
_CERT_DNS_WWW_URI_OTHER = build_cert(
    [DNSName("www.example.com"), UniformResourceIdentifier("sip:other.example.com")]
)
_CERT_DNS_WWW_URI_SIP = build_cert(
    [DNSName("www.example.com"), UniformResourceIdentifier("sip:example.com")]
)
_CERT_DNS_WWW_SRV_XMPP = build_cert(
    [DNSName("www.example.com"), _srv_other_name(_ia5("_xmpp.example.net"))]
)
_CERT_MIX_ALL = build_cert(
    [
        DNSName("www.example.com"),
        IPAddress(ipaddress.ip_address("192.0.2.1")),
        UniformResourceIdentifier("sip:example.com"),
        _srv_other_name(_ia5("_xmpp.example.net")),
    ]
)
_CERT_SRV_TRAILING_REAL = _build_cert_with_raw_san(_SAN_SRV_TRAILING)
_CERT_SRV_TRAILING_STUB = StubCertificate(
    StubSubjectAlternativeName(
        [StubOtherName(ID_ON_DNS_SRV, SRV_OTHERNAME_VALUE_TRAILING)]
    )
)


def _oracle_raises(exc_type: type, func: Any, *args: Any) -> Any:
    def check() -> None:
        with pytest.raises(exc_type):
            func(*args)

    return check


CASES: list[Case] = [
    # -- DNS ------------------------------------------------------------
    Case(
        id="DNS-MATCH-001",
        description="Single dNSName SAN matches the hostname.",
        cert=_CERT_DNS_WWW,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(DNS_ID("www.example.com"),)),
        expected_patterns=(_DNS_WWW,),
    ),
    Case(
        id="DNS-MISMATCH-002",
        description="Single dNSName SAN does not match a different hostname.",
        cert=_CERT_DNS_WWW,
        obligatory_ids=(DNS_ID("other.example.com"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(DNSMismatch,)),
        expected_patterns=(_DNS_WWW,),
    ),
    Case(
        id="DNS-WILDCARD-003",
        description="Wildcard SAN matches one label.",
        cert=_CERT_DNS_WILDCARD,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(DNS_ID("www.example.com"),)),
        expected_patterns=(_DNS_WILDCARD,),
    ),
    Case(
        id="DNS-WILDCARD-004",
        description="Wildcard SAN does not match the apex name.",
        cert=_CERT_DNS_WILDCARD,
        obligatory_ids=(DNS_ID("example.com"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(DNSMismatch,)),
        expected_patterns=(_DNS_WILDCARD,),
    ),
    Case(
        id="DNS-WILDCARD-005",
        description="Wildcard SAN does not span multiple labels.",
        cert=_CERT_DNS_WILDCARD,
        obligatory_ids=(DNS_ID("a.b.example.com"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(DNSMismatch,)),
        expected_patterns=(_DNS_WILDCARD,),
    ),
    Case(
        id="DNS-PARTIAL-WILDCARD-006",
        description="Partial wildcard (w*) is not a valid match.",
        cert=_CERT_DNS_WILDCARD_PARTIAL,
        obligatory_ids=(DNS_ID("w.example.com"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(DNSMismatch,)),
        expected_patterns=(_DNS_WILDCARD_PARTIAL,),
    ),
    Case(
        id="DNS-CASE-007",
        description="Uppercase dNSName matches case-insensitively.",
        cert=_CERT_DNS_WWW_UPPER,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(DNS_ID("www.example.com"),)),
        expected_patterns=(_DNS_WWW,),
    ),
    Case(
        id="DNS-DUP-008",
        description="Duplicate dNSName SANs are tolerated and preserved.",
        cert=_CERT_DNS_WWW_DUP,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(DNS_ID("www.example.com"),)),
        expected_patterns=(_DNS_WWW, _DNS_WWW),
    ),
    Case(
        id="DNS-MULTI-009",
        description="Multiple dNSName SANs each match their hostname.",
        cert=_CERT_DNS_WWW_MAIL,
        obligatory_ids=(DNS_ID("www.example.com"), DNS_ID("mail.example.com")),
        optional_ids=(),
        expected=ExpectMatch(
            matched=(DNS_ID("www.example.com"), DNS_ID("mail.example.com"))
        ),
        expected_patterns=(_DNS_WWW, _DNS_MAIL),
    ),
    Case(
        id="DNS-IPFORM-010",
        description="A dNSName carrying an IP address is malformed.",
        cert=_CERT_DNS_IP_FORM,
        obligatory_ids=(DNS_ID("host.example.com"),),
        optional_ids=(),
        expected=ExpectMalformed(match="Invalid DNS pattern"),
        expected_patterns=None,
        oracle=_oracle_raises(
            CertificateError, DNSPattern.from_bytes, b"192.0.2.1"
        ),
    ),
    Case(
        id="DNS-WILDCARD-BAD-011",
        description="Wildcard with too few host components is malformed.",
        cert=_CERT_DNS_WILDCARD_BAD,
        obligatory_ids=(DNS_ID("www.com"),),
        optional_ids=(),
        expected=ExpectMalformed(match="too few host components"),
        expected_patterns=None,
        oracle=_oracle_raises(
            CertificateError, DNSPattern.from_bytes, b"*.com"
        ),
    ),
    Case(
        id="DNS-EMPTY-SAN-012",
        description="An empty SAN sequence yields no patterns.",
        cert=_CERT_DNS_EMPTY_SAN,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMalformed(match="does not contain any"),
        expected_patterns=(),
    ),
    Case(
        id="DNS-CN-ONLY-013",
        description="commonName without SAN is not a fallback (23.1.0).",
        cert=_CERT_NO_SAN,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMalformed(match="does not contain any"),
        expected_patterns=(),
    ),
    # -- IP -------------------------------------------------------------
    Case(
        id="IP-MATCH-001",
        description="iPAddress SAN matches the IPv4 address.",
        cert=_CERT_IP_V4,
        obligatory_ids=(IPAddress_ID("192.0.2.1"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(IPAddress_ID("192.0.2.1"),)),
        expected_patterns=(_IP_192,),
    ),
    Case(
        id="IP-MISMATCH-002",
        description="iPAddress SAN does not match a different IPv4 address.",
        cert=_CERT_IP_V4,
        obligatory_ids=(IPAddress_ID("192.0.2.2"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(IPAddressMismatch,)),
        expected_patterns=(_IP_192,),
    ),
    Case(
        id="IP-V6-003",
        description="iPAddress SAN matches the IPv6 address.",
        cert=_CERT_IP_V6,
        obligatory_ids=(IPAddress_ID("2001:db8::1"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(IPAddress_ID("2001:db8::1"),)),
        expected_patterns=(_IP_V6,),
    ),
    # -- URI ------------------------------------------------------------
    Case(
        id="URI-MATCH-001",
        description="uniformResourceIdentifier SAN matches the URI-ID.",
        cert=_CERT_URI_SIP,
        obligatory_ids=(URI_ID("sip:example.com"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(URI_ID("sip:example.com"),)),
        expected_patterns=(_URI_SIP,),
    ),
    Case(
        id="URI-MISMATCH-002",
        description="URI-ID with a different scheme does not match.",
        cert=_CERT_URI_SIP,
        obligatory_ids=(URI_ID("xmpp:example.com"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(URIMismatch,)),
        expected_patterns=(_URI_SIP,),
    ),
    # -- SRV (otherName / id-on-dnsSRV) ---------------------------------
    Case(
        id="SRV-MATCH-001",
        description="id-on-dnsSRV otherName matches the SRV-ID.",
        cert=_CERT_SRV_XMPP,
        obligatory_ids=(SRV_ID("_xmpp.example.net"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(SRV_ID("_xmpp.example.net"),)),
        expected_patterns=(_SRV_XMPP,),
    ),
    Case(
        id="SRV-MISMATCH-002",
        description="id-on-dnsSRV otherName does not match another service.",
        cert=_CERT_SRV_XMPP,
        obligatory_ids=(SRV_ID("_mail.example.net"),),
        optional_ids=(),
        expected=ExpectMismatch(errors=(SRVMismatch,)),
        expected_patterns=(_SRV_XMPP,),
    ),
    Case(
        id="SRV-UNKNOWN-OID-003",
        description="Unknown otherName OID is ignored; DNS SAN still matches.",
        cert=_CERT_UNKNOWN_OTHER_PLUS_DNS,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMatch(matched=(DNS_ID("www.example.com"),)),
        expected_patterns=(_DNS_WWW,),
    ),
    Case(
        id="SRV-UNKNOWN-ONLY-004",
        description="SAN with only an unknown otherName OID yields no patterns.",
        cert=_CERT_UNKNOWN_OTHER_ONLY,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(),
        expected=ExpectMalformed(match="does not contain any"),
        expected_patterns=(),
    ),
    Case(
        id="SRV-WRONG-DER-005",
        description="id-on-dnsSRV with INTEGER instead of IA5String is malformed.",
        cert=_CERT_SRV_WRONG_DER,
        obligatory_ids=(SRV_ID("_xmpp.example.net"),),
        optional_ids=(),
        expected=ExpectMalformed(match="Unexpected certificate content"),
        expected_patterns=None,
        oracle=_oracle_raises(
            ValueError,
            asn1.decode_der,
            asn1.IA5String,
            SRV_OTHERNAME_VALUE_WRONG_TYPE,
        ),
    ),
    Case(
        id="SRV-TRAILING-006",
        description=(
            "id-on-dnsSRV with trailing bytes after the IA5String is "
            "malformed (raw DER sample injected via stub certificate)."
        ),
        cert=_CERT_SRV_TRAILING_STUB,
        obligatory_ids=(SRV_ID("_xmpp.example.net"),),
        optional_ids=(),
        expected=ExpectMalformed(match="Unexpected certificate content"),
        expected_patterns=None,
        oracle=_oracle_raises(
            ValueError, asn1.decode_der, asn1.IA5String, SRV_OTHERNAME_VALUE_TRAILING
        ),
    ),
    Case(
        id="SRV-TRAILING-REAL-007",
        description=(
            "A real certificate carrying the trailing-bytes otherName is "
            "rejected by cryptography's own parser before extraction."
        ),
        cert=_CERT_SRV_TRAILING_REAL,
        obligatory_ids=(SRV_ID("_xmpp.example.net"),),
        optional_ids=(),
        expected=ExpectParserReject(),
        expected_patterns=None,
        oracle=_oracle_raises(
            ValueError, asn1.decode_der, asn1.IA5String, SRV_OTHERNAME_VALUE_TRAILING
        ),
    ),
    # -- obligatory / optional combinations ------------------------------
    Case(
        id="OPT-ABSENT-001",
        description="Optional URI-ID absent from cert: verification succeeds.",
        cert=_CERT_DNS_WWW,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(URI_ID("sip:example.com"),),
        expected=ExpectMatch(matched=(DNS_ID("www.example.com"),)),
        expected_patterns=(_DNS_WWW,),
    ),
    Case(
        id="OPT-PRESENT-MISMATCH-002",
        description="Optional URI-ID present but different: verification fails.",
        cert=_CERT_DNS_WWW_URI_OTHER,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(URI_ID("sip:example.com"),),
        expected=ExpectMismatch(errors=(URIMismatch,)),
        expected_patterns=(_DNS_WWW, _URI_SIP_OTHER),
    ),
    Case(
        id="OPT-PRESENT-MATCH-003",
        description="Optional URI-ID present and matching: both match.",
        cert=_CERT_DNS_WWW_URI_SIP,
        obligatory_ids=(DNS_ID("www.example.com"),),
        optional_ids=(URI_ID("sip:example.com"),),
        expected=ExpectMatch(
            matched=(DNS_ID("www.example.com"), URI_ID("sip:example.com"))
        ),
        expected_patterns=(_DNS_WWW, _URI_SIP),
    ),
    Case(
        id="OBL-ABSENT-001",
        description="Obligatory IP-ID absent from cert: always an error.",
        cert=_CERT_DNS_WWW,
        obligatory_ids=(DNS_ID("www.example.com"), IPAddress_ID("192.0.2.1")),
        optional_ids=(),
        expected=ExpectMismatch(errors=(IPAddressMismatch,)),
        expected_patterns=(_DNS_WWW,),
    ),
    Case(
        id="MULTI-ERR-001",
        description="Obligatory DNS mismatch and optional SRV mismatch aggregate.",
        cert=_CERT_DNS_WWW_SRV_XMPP,
        obligatory_ids=(DNS_ID("other.example.com"),),
        optional_ids=(SRV_ID("_mail.example.net"),),
        expected=ExpectMismatch(errors=(DNSMismatch, SRVMismatch)),
        expected_patterns=(_DNS_WWW, _SRV_XMPP),
    ),
    Case(
        id="MIX-ALL-001",
        description="DNS+IP+URI+SRV SANs all match their service IDs.",
        cert=_CERT_MIX_ALL,
        obligatory_ids=(DNS_ID("www.example.com"), IPAddress_ID("192.0.2.1")),
        optional_ids=(URI_ID("sip:example.com"), SRV_ID("_xmpp.example.net")),
        expected=ExpectMatch(
            matched=(
                DNS_ID("www.example.com"),
                IPAddress_ID("192.0.2.1"),
                URI_ID("sip:example.com"),
                SRV_ID("_xmpp.example.net"),
            )
        ),
        # extract_patterns groups by type: DNS, URI, IP, then otherName.
        expected_patterns=(_DNS_WWW, _URI_SIP, _IP_192, _SRV_XMPP),
    ),
]
