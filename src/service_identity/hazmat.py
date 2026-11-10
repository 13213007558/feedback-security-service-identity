"""
Common verification code.
"""

from __future__ import annotations

import ipaddress
import re

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

import attr

from .exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    Mismatch,
    SPIFFEMismatch,
    SRVMismatch,
    URIMismatch,
    VerificationError,
)


try:
    import idna
except ImportError:
    idna = None  # type: ignore[assignment]


@attr.s(slots=True)
class ServiceMatch:
    """
    A match of a service id and a certificate pattern.
    """

    service_id: ServiceID = attr.ib()
    cert_pattern: CertificatePattern = attr.ib()


def verify_service_identity(
    cert_patterns: Sequence[CertificatePattern],
    obligatory_ids: Sequence[ServiceID],
    optional_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Verify whether *cert_patterns* are valid for *obligatory_ids* and
    *optional_ids*.

    *obligatory_ids* must be both present and match.  *optional_ids* must match
    if a pattern of the respective type is present.
    """
    if not cert_patterns:
        msg = "Certificate does not contain any `subjectAltName`s."
        raise CertificateError(msg)

    errors = []
    matches = _find_matches(cert_patterns, obligatory_ids) + _find_matches(
        cert_patterns, optional_ids
    )

    matched_ids = [match.service_id for match in matches]
    for i in obligatory_ids:
        if i not in matched_ids:
            errors.append(  # noqa: PERF401
                i.error_on_mismatch(mismatched_id=i)
            )

    for i in optional_ids:
        # If an optional ID is not matched by a certificate pattern *but* there
        # is a pattern of the same type , it is an error and the verification
        # fails.  Example: the user passes a SRV-ID for "_mail.domain.com" but
        # the certificate contains an SRV-Pattern for "_xmpp.domain.com".
        if i not in matched_ids and _contains_instance_of(
            cert_patterns, i.pattern_class
        ):
            errors.append(  # noqa: PERF401
                i.error_on_mismatch(mismatched_id=i)
            )

    if errors:
        raise VerificationError(errors=errors)

    return matches


def _find_matches(
    cert_patterns: Sequence[CertificatePattern],
    service_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Search for matching certificate patterns and service_ids.

    Args:
        service_ids: List of service IDs like DNS_ID.
    """
    matches = []
    for sid in service_ids:
        for cid in cert_patterns:
            if sid.verify(cid):
                matches.append(  # noqa: PERF401
                    ServiceMatch(cert_pattern=cid, service_id=sid)
                )

    return matches


def _contains_instance_of(seq: Sequence[object], cl: type) -> bool:
    return any(isinstance(e, cl) for e in seq)


def _is_ip_address(pattern: str | bytes) -> bool:
    """
    Check whether *pattern* could be/match an IP address.

    Args:
        pattern: A pattern for a host name.

    Returns:
        `True` if *pattern* could be an IP address, else `False`.
    """
    if isinstance(pattern, bytes):
        try:
            pattern = pattern.decode("ascii")
        except UnicodeError:
            return False

    try:
        int(pattern)
    except ValueError:
        pass
    else:
        return True

    try:
        ipaddress.ip_address(pattern.replace("*", "1"))
    except ValueError:
        return False

    return True


@attr.s(slots=True)
class DNSPattern:
    """
    A DNS pattern as extracted from certificates.
    """

    #: The pattern.
    pattern: bytes = attr.ib()

    _RE_LEGAL_CHARS = re.compile(rb"^[a-z0-9\-_.]+$")

    @classmethod
    def from_bytes(cls, pattern: bytes) -> DNSPattern:
        if not isinstance(pattern, bytes):
            msg = "The DNS pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip()

        if pattern == b"" or _is_ip_address(pattern) or b"\0" in pattern:
            msg = f"Invalid DNS pattern {pattern!r}."
            raise CertificateError(msg)

        pattern = pattern.translate(_TRANS_TO_LOWER)
        if b"*" in pattern:
            _validate_pattern(pattern)

        return cls(pattern=pattern)


@attr.s(slots=True)
class IPAddressPattern:
    """
    An IP address pattern as extracted from certificates.
    """

    #: The pattern.
    pattern: ipaddress.IPv4Address | ipaddress.IPv6Address = attr.ib()

    @classmethod
    def from_bytes(cls, bs: bytes) -> IPAddressPattern:
        try:
            return cls(pattern=ipaddress.ip_address(bs))
        except ValueError:
            msg = f"Invalid IP address pattern {bs!r}."
            raise CertificateError(msg) from None


@attr.s(slots=True)
class URIPattern:
    """
    An URI pattern as extracted from certificates.
    """

    #: The pattern for the protocol part.
    protocol_pattern: bytes = attr.ib()
    #: The pattern for the DNS part.
    dns_pattern: DNSPattern = attr.ib()

    @classmethod
    def from_bytes(cls, pattern: bytes) -> URIPattern:
        if not isinstance(pattern, bytes):
            msg = "The URI pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if b":" not in pattern or b"*" in pattern or _is_ip_address(pattern):
            msg = f"Invalid URI pattern {pattern!r}."
            raise CertificateError(msg)

        protocol_pattern, hostname = pattern.split(b":")

        return cls(
            protocol_pattern=protocol_pattern,
            dns_pattern=DNSPattern.from_bytes(hostname),
        )


@attr.s(slots=True)
class SRVPattern:
    """
    An SRV pattern as extracted from certificates.
    """

    #: The pattern for the name part.
    name_pattern: bytes = attr.ib()
    #: The pattern for the DNS part.
    dns_pattern: DNSPattern = attr.ib()

    @classmethod
    def from_bytes(cls, pattern: bytes) -> SRVPattern:
        if not isinstance(pattern, bytes):
            msg = "The SRV pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if (
            pattern[0] != b"_"[0]
            or b"." not in pattern
            or b"*" in pattern
            or _is_ip_address(pattern)
        ):
            msg = f"Invalid SRV pattern {pattern!r}."
            raise CertificateError(msg)

        name, hostname = pattern.split(b".", 1)
        return cls(
            name_pattern=name[1:], dns_pattern=DNSPattern.from_bytes(hostname)
        )


@attr.s(slots=True)
class SPIFFEPattern:
    """
    A SPIFFE ID pattern as extracted from certificates.

    Contains the full workload identity: trust domain and path. No
    normalization beyond the SPIFFE ID syntax rules is applied, so distinct
    identities stay distinct.
    """

    #: The trust domain part.
    trust_domain: bytes = attr.ib()
    #: The path part, including the leading slash. Empty if absent.
    path: bytes = attr.ib()

    @classmethod
    def from_bytes(cls, pattern: bytes) -> SPIFFEPattern:
        if not isinstance(pattern, bytes):
            msg = "The SPIFFE pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip()

        try:
            text = pattern.decode("ascii")
        except UnicodeDecodeError:
            msg = f"Invalid SPIFFE pattern {pattern!r}."
            raise CertificateError(msg) from None

        try:
            trust_domain, path = _parse_spiffe_id(text)
        except ValueError:
            msg = f"Invalid SPIFFE pattern {pattern!r}."
            raise CertificateError(msg) from None

        return cls(trust_domain=trust_domain, path=path)


CertificatePattern = (
    SRVPattern | URIPattern | DNSPattern | IPAddressPattern | SPIFFEPattern
)
"""
A :class:`Union` of all possible patterns that can be extracted from a
certificate.
"""


@runtime_checkable
class ServiceID(Protocol):
    @property
    def pattern_class(self) -> type[CertificatePattern]: ...

    @property
    def error_on_mismatch(self) -> type[Mismatch]: ...

    def verify(self, pattern: CertificatePattern) -> bool: ...


@attr.s(init=False, slots=True)
class DNS_ID:
    """
    A DNS service ID, aka hostname.
    """

    hostname: bytes = attr.ib()

    # characters that are legal in a normalized hostname
    _RE_LEGAL_CHARS = re.compile(rb"^[a-z0-9\-_.]+$")
    pattern_class = DNSPattern
    error_on_mismatch = DNSMismatch

    def __init__(self, hostname: str):
        if not isinstance(hostname, str):
            msg = "DNS-ID must be a text string."
            raise TypeError(msg)

        hostname = hostname.strip()
        if not hostname or _is_ip_address(hostname):
            msg = "Invalid DNS-ID."
            raise ValueError(msg)

        if any(ord(c) > 127 for c in hostname):
            if idna:
                ascii_id = idna.encode(hostname)
            else:
                msg = "idna library is required for non-ASCII IDs."
                raise ImportError(msg)
        else:
            ascii_id = hostname.encode("ascii")

        self.hostname = ascii_id.translate(_TRANS_TO_LOWER)
        if self._RE_LEGAL_CHARS.match(self.hostname) is None:
            msg = "Invalid DNS-ID."
            raise ValueError(msg)

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.4
        """
        if isinstance(pattern, self.pattern_class):
            return _hostname_matches(pattern.pattern, self.hostname)

        return False


@attr.s(slots=True)
class IPAddress_ID:
    """
    An IP address service ID.
    """

    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = attr.ib(
        converter=ipaddress.ip_address
    )

    pattern_class = IPAddressPattern
    error_on_mismatch = IPAddressMismatch

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc2818#section-3.1
        """
        if isinstance(pattern, self.pattern_class):
            return self.ip == pattern.pattern

        return False


@attr.s(init=False, slots=True)
class URI_ID:
    """
    An URI service ID.
    """

    protocol: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()

    pattern_class = URIPattern
    error_on_mismatch = URIMismatch

    def __init__(self, uri: str):
        if not isinstance(uri, str):
            msg = "URI-ID must be a text string."
            raise TypeError(msg)

        uri = uri.strip()
        if ":" not in uri or _is_ip_address(uri):
            msg = "Invalid URI-ID."
            raise ValueError(msg)

        prot, hostname = uri.split(":")

        self.protocol = prot.encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname.strip("/"))

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.2
        """
        if isinstance(pattern, self.pattern_class):
            return (
                pattern.protocol_pattern == self.protocol
                and self.dns_id.verify(pattern.dns_pattern)
            )

        return False


@attr.s(init=False, slots=True)
class SRV_ID:
    """
    An SRV service ID.
    """

    name: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()

    pattern_class = SRVPattern
    error_on_mismatch = SRVMismatch

    def __init__(self, srv: str):
        if not isinstance(srv, str):
            msg = "SRV-ID must be a text string."
            raise TypeError(msg)

        srv = srv.strip()
        if "." not in srv or _is_ip_address(srv) or srv[0] != "_":
            msg = "Invalid SRV-ID."
            raise ValueError(msg)

        name, hostname = srv.split(".", 1)

        self.name = name[1:].encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname)

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.1
        """
        if isinstance(pattern, self.pattern_class):
            return self.name == pattern.name_pattern and self.dns_id.verify(
                pattern.dns_pattern
            )

        return False


@attr.s(init=False, slots=True)
class SPIFFE_ID:
    """
    A SPIFFE ID service ID as defined by the
    `SPIFFE specification <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md>`_.

    The full identity -- trust domain and path -- is matched byte-for-byte.
    No URL normalization is applied that could merge distinct workload
    identities.
    """

    trust_domain: bytes = attr.ib()
    path: bytes = attr.ib()

    pattern_class = SPIFFEPattern
    error_on_mismatch = SPIFFEMismatch

    def __init__(self, spiffe_id: str):
        if not isinstance(spiffe_id, str):
            msg = "SPIFFE-ID must be a text string."
            raise TypeError(msg)

        self.trust_domain, self.path = _parse_spiffe_id(spiffe_id.strip())

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        Exact match of the full SPIFFE ID.
        """
        if isinstance(pattern, self.pattern_class):
            return (
                pattern.trust_domain == self.trust_domain
                and pattern.path == self.path
            )

        return False


def verify_spiffe_identity(
    cert_patterns: Sequence[CertificatePattern],
    spiffe_id: SPIFFE_ID,
    allowed_trust_domains: Sequence[str],
) -> list[ServiceMatch]:
    """
    Verify whether *cert_patterns* contain *spiffe_id* under the caller's
    trust domain policy.

    Follows the X.509-SVID policy that a workload certificate carries at
    most one SPIFFE ID: if multiple SPIFFE IDs are present, a
    :exc:`CertificateError` is raised instead of picking one by order.

    *allowed_trust_domains* is provided by the caller; the certificate's
    contents can never widen it. If *spiffe_id*'s trust domain is not
    allowed, a :exc:`VerificationError` is raised.

    Returns the matches so the caller can inspect the full matched identity.
    """
    allowed = set()
    for trust_domain in allowed_trust_domains:
        if not isinstance(trust_domain, str):
            msg = "Trust domains must be text strings."
            raise TypeError(msg)

        trust_domain = trust_domain.strip()
        if _RE_SPIFFE_TRUST_DOMAIN.match(trust_domain) is None:
            msg = f"Invalid trust domain {trust_domain!r}."
            raise ValueError(msg)

        allowed.add(trust_domain.encode("ascii"))

    if sum(isinstance(p, SPIFFEPattern) for p in cert_patterns) > 1:
        msg = "Certificate contains more than one SPIFFE ID."
        raise CertificateError(msg)

    if spiffe_id.trust_domain not in allowed:
        raise VerificationError(
            errors=[spiffe_id.error_on_mismatch(mismatched_id=spiffe_id)]
        )

    return verify_service_identity(
        cert_patterns=cert_patterns,
        obligatory_ids=[spiffe_id],
        optional_ids=[],
    )


_SPIFFE_PREFIX = "spiffe://"

# Trust domains are lowercase ASCII: letters, digits, dot, hyphen, and
# underscore. Anything else (including uppercase and percent-encoding) is
# rejected instead of normalized.
_RE_SPIFFE_TRUST_DOMAIN = re.compile(r"^[a-z0-9._-]{1,255}$")

# Path segments may also contain uppercase letters.
_RE_SPIFFE_PATH_SEGMENT = re.compile(r"^[a-zA-Z0-9._-]+$")


def _parse_spiffe_id(spiffe_id: str) -> tuple[bytes, bytes]:
    """
    Parse *spiffe_id* into its trust domain and path parts, validating the
    SPIFFE ID syntax strictly.

    No generic URL normalization is performed: userinfo, ports, queries,
    fragments, percent-encoding, and dot-segments are rejected rather than
    resolved.

    Returns:
        (trust_domain, path) as bytes. The path includes the leading slash
        and is empty if absent.

    Raises:
        ValueError: If *spiffe_id* is not a valid SPIFFE ID.
    """
    if not spiffe_id.startswith(_SPIFFE_PREFIX):
        msg = f"Invalid SPIFFE-ID {spiffe_id!r}: scheme must be 'spiffe'."
        raise ValueError(msg)

    rest = spiffe_id[len(_SPIFFE_PREFIX) :]

    if "%" in rest:
        msg = f"Invalid SPIFFE-ID {spiffe_id!r}: percent-encoding is not allowed."
        raise ValueError(msg)

    if "?" in rest or "#" in rest:
        msg = f"Invalid SPIFFE-ID {spiffe_id!r}: query and fragment are not allowed."
        raise ValueError(msg)

    trust_domain, sep, remainder = rest.partition("/")
    path = sep + remainder

    if "@" in trust_domain:
        msg = f"Invalid SPIFFE-ID {spiffe_id!r}: userinfo is not allowed."
        raise ValueError(msg)

    if ":" in trust_domain:
        msg = f"Invalid SPIFFE-ID {spiffe_id!r}: ports are not allowed."
        raise ValueError(msg)

    if _RE_SPIFFE_TRUST_DOMAIN.match(trust_domain) is None:
        msg = f"Invalid SPIFFE-ID {spiffe_id!r}: invalid trust domain."
        raise ValueError(msg)

    if path:
        # The segment before the first slash is always empty.
        for segment in path.split("/")[1:]:
            if not segment:
                msg = f"Invalid SPIFFE-ID {spiffe_id!r}: empty path segments are not allowed."
                raise ValueError(msg)

            if segment in (".", ".."):
                msg = f"Invalid SPIFFE-ID {spiffe_id!r}: dot-segments are not allowed."
                raise ValueError(msg)

            if _RE_SPIFFE_PATH_SEGMENT.match(segment) is None:
                msg = f"Invalid SPIFFE-ID {spiffe_id!r}: invalid characters in path."
                raise ValueError(msg)

    return trust_domain.encode("ascii"), path.encode("ascii")


def _hostname_matches(cert_pattern: bytes, actual_hostname: bytes) -> bool:
    """
    :return: `True` if *cert_pattern* matches *actual_hostname*, else `False`.
    """
    if b"*" in cert_pattern:
        if b"." not in actual_hostname:
            return False
        cert_head, cert_tail = cert_pattern.split(b".", 1)
        actual_head, actual_tail = actual_hostname.split(b".", 1)
        if cert_tail != actual_tail:
            return False
        # No patterns for IDNA
        if actual_head.startswith(b"xn--"):
            return False

        return cert_head in (b"*", actual_head)

    return cert_pattern == actual_hostname


def _validate_pattern(cert_pattern: bytes) -> None:
    """
    Check whether the usage of wildcards within *cert_pattern* conforms with
    our expectations.
    """
    cnt = cert_pattern.count(b"*")
    if cnt > 1:
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains too many wildcards."
        raise CertificateError(msg)
    parts = cert_pattern.split(b".")
    if len(parts) < 3:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has too few host components for wildcard usage."
        raise CertificateError(msg)
    # We assume there will always be only one wildcard allowed.
    if b"*" not in parts[0]:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has a wildcard outside the left-most part."
        raise CertificateError(msg)
    if any(not len(p) for p in parts):
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains empty parts."
        raise CertificateError(msg)


# Ensure no locale magic interferes.
_TRANS_TO_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)
