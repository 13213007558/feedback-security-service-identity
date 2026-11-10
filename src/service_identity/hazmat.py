"""
Common verification code.
"""

from __future__ import annotations

import ipaddress
import re

from collections.abc import Sequence
from typing import Protocol, TypeVar, runtime_checkable

import attr

from .exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    Mismatch,
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


@attr.s(slots=True)
class CompiledPatterns:
    """
    A reusable, indexed view over the patterns of one certificate.

    Building a :class:`CompiledPatterns` performs the same validation as
    passing the patterns to :func:`verify_service_identity` directly: every
    pattern is expected to have been produced by one of the ``from_bytes``
    constructors already, so no invalid SAN can be hidden by the indexing.

    The object snapshots its input into a private tuple and never shares the
    caller's list; later mutations of that list therefore cannot corrupt the
    index, and two certificates always get independent indexes.

    Candidates for a service ID are narrowed by identity type and, where it
    is provably safe, by a key derived from the existing matching rules:

    * DNS IDs only consider DNS patterns, further split into exact patterns
      and wildcard patterns sharing the hostname's tail;
    * URI IDs only consider URI patterns with the same protocol;
    * SRV IDs only consider SRV patterns with the same service name;
    * IP address IDs only consider the pattern carrying the same address.

    Wildcard DNS matching, URI service types and SRV names keep following
    the rules of their respective ``ServiceID.verify`` implementations.
    """

    _patterns: tuple[CertificatePattern, ...] = attr.ib()
    _dns_exact: dict[bytes, tuple[int, ...]] = attr.ib()
    _dns_wildcards: dict[bytes, tuple[int, ...]] = attr.ib()
    _uri: dict[bytes, tuple[int, ...]] = attr.ib()
    _srv: dict[bytes, tuple[int, ...]] = attr.ib()
    _ip: dict[
        ipaddress.IPv4Address | ipaddress.IPv6Address, tuple[int, ...]
    ] = attr.ib()
    _other: tuple[int, ...] = attr.ib()

    @classmethod
    def compile(
        cls, cert_patterns: Sequence[CertificatePattern]
    ) -> CompiledPatterns:
        """
        Build an index over *cert_patterns*.

        The caller's sequence is snapshotted into a private tuple: appending,
        removing or reordering it afterwards cannot change the compiled
        result, and each certificate gets an independent index.  The pattern
        objects themselves are the validated value objects produced by the
        ``from_bytes`` constructors and are shared, not duplicated, so object
        identity is preserved.
        """
        patterns = tuple(cert_patterns)

        dns_exact: dict[bytes, list[int]] = {}
        dns_wildcards: dict[bytes, list[int]] = {}
        uri: dict[bytes, list[int]] = {}
        srv: dict[bytes, list[int]] = {}
        ip: dict[
            ipaddress.IPv4Address | ipaddress.IPv6Address, list[int]
        ] = {}
        other: list[int] = []

        for index, pattern in enumerate(patterns):
            if pattern.__class__ is DNSPattern:
                if b"*" in pattern.pattern:
                    tail = pattern.pattern.split(b".", 1)[1]
                    dns_wildcards.setdefault(tail, []).append(index)
                else:
                    dns_exact.setdefault(pattern.pattern, []).append(index)
            elif pattern.__class__ is URIPattern:
                uri.setdefault(pattern.protocol_pattern, []).append(index)
            elif pattern.__class__ is SRVPattern:
                srv.setdefault(pattern.name_pattern, []).append(index)
            elif pattern.__class__ is IPAddressPattern:
                ip.setdefault(pattern.pattern, []).append(index)
            else:
                other.append(index)

        return cls(
            patterns,
            _freeze(dns_exact),
            _freeze(dns_wildcards),
            _freeze(uri),
            _freeze(srv),
            _freeze(ip),
            tuple(other),
        )

    @property
    def patterns(self) -> tuple[CertificatePattern, ...]:
        """
        The indexed certificate patterns in their original order.
        """
        return self._patterns

    def verify(
        self,
        obligatory_ids: Sequence[ServiceID],
        optional_ids: Sequence[ServiceID] = (),
    ) -> list[ServiceMatch]:
        """
        Verify whether the indexed patterns are valid for the given IDs.

        *obligatory_ids* must be both present and match.  *optional_ids*
        must match if a pattern of the respective type is present; their
        semantics are unchanged when no pattern of that type exists.
        """
        if not self._patterns:
            msg = "Certificate does not contain any `subjectAltName`s."
            raise CertificateError(msg)

        matches = self._find_matches(obligatory_ids) + self._find_matches(
            optional_ids
        )

        matched_ids = [match.service_id for match in matches]
        errors = []
        for service_id in obligatory_ids:
            if service_id not in matched_ids:
                errors.append(  # noqa: PERF401
                    service_id.error_on_mismatch(mismatched_id=service_id)
                )

        for service_id in optional_ids:
            # If an optional ID is not matched by a certificate pattern
            # *but* there is a pattern of the same type, it is an error and
            # the verification fails.  Example: the user passes a SRV-ID for
            # "_mail.domain.com" but the certificate contains an SRV-Pattern
            # for "_xmpp.domain.com".
            if service_id not in matched_ids and (
                self._contains_pattern_type(service_id.pattern_class)
            ):
                errors.append(  # noqa: PERF401
                    service_id.error_on_mismatch(mismatched_id=service_id)
                )

        if errors:
            raise VerificationError(errors=errors)

        return matches

    def _find_matches(
        self, service_ids: Sequence[ServiceID]
    ) -> list[ServiceMatch]:
        matches = []
        for service_id in service_ids:
            for index in self._candidates_for(service_id):
                cert_pattern = self._patterns[index]
                if service_id.verify(cert_pattern):
                    matches.append(  # noqa: PERF401
                        ServiceMatch(
                            cert_pattern=cert_pattern,
                            service_id=service_id,
                        )
                    )

        return matches

    def _candidates_for(self, service_id: ServiceID) -> tuple[int, ...]:
        pattern_class = service_id.pattern_class
        if pattern_class is DNSPattern:
            hostname = service_id.hostname  # type: ignore[attr-defined]
            candidates = _merge_indexes(
                self._dns_exact.get(hostname, ()),
                self._wildcard_candidates_for(hostname),
            )
        elif pattern_class is URIPattern:
            protocol = service_id.protocol  # type: ignore[attr-defined]
            candidates = self._uri.get(protocol, ())
        elif pattern_class is SRVPattern:
            name = service_id.name  # type: ignore[attr-defined]
            candidates = self._srv.get(name, ())
        elif pattern_class is IPAddressPattern:
            ip = service_id.ip  # type: ignore[attr-defined]
            candidates = self._ip.get(ip, ())
        else:
            # An unknown ID type may match any pattern, so keep the full
            # scan, which already covers the "other" bucket.
            return tuple(range(len(self._patterns)))

        # Patterns of unknown types stay eligible for known IDs.
        if self._other:
            candidates = _merge_indexes(candidates, self._other)

        return candidates

    def _wildcard_candidates_for(self, hostname: bytes) -> tuple[int, ...]:
        # A wildcard always matches at least two DNS labels, so a
        # single-label hostname can never be a candidate.
        if b"." not in hostname:
            return ()

        tail = hostname.split(b".", 1)[1]

        return self._dns_wildcards.get(tail, ())

    def _contains_known_pattern_type(self, pattern_class: type) -> bool:
        if pattern_class is DNSPattern:
            return bool(self._dns_exact or self._dns_wildcards)
        if pattern_class is URIPattern:
            return bool(self._uri)
        if pattern_class is SRVPattern:
            return bool(self._srv)

        return bool(self._ip)

    def _contains_pattern_type(self, pattern_class: type) -> bool:
        if pattern_class in _KNOWN_PATTERN_CLASSES:
            return self._contains_known_pattern_type(pattern_class)

        return _contains_instance_of(self._patterns, pattern_class)


_T = TypeVar("_T")


def _freeze(index: dict[_T, list[int]]) -> dict[_T, tuple[int, ...]]:
    return {key: tuple(positions) for key, positions in index.items()}


def _merge_indexes(
    left: tuple[int, ...], right: tuple[int, ...]
) -> tuple[int, ...]:
    """
    Merge two sorted tuples of pattern indexes into sorted order.
    """
    merged: list[int] = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
    merged.extend(left[i:])
    merged.extend(right[j:])

    return tuple(merged)


def verify_service_identity(
    cert_patterns: Sequence[CertificatePattern] | CompiledPatterns,
    obligatory_ids: Sequence[ServiceID],
    optional_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Verify whether *cert_patterns* are valid for *obligatory_ids* and
    *optional_ids*.

    *cert_patterns* may either be a sequence of certificate patterns as
    returned by the ``extract_patterns`` functions or a reusable
    :class:`CompiledPatterns` built from such a sequence.

    *obligatory_ids* must be both present and match.  *optional_ids* must match
    if a pattern of the respective type is present.
    """
    if isinstance(cert_patterns, CompiledPatterns):
        compiled = cert_patterns
    else:
        compiled = CompiledPatterns.compile(cert_patterns)

    return compiled.verify(obligatory_ids, optional_ids)


def _find_matches(
    cert_patterns: Sequence[CertificatePattern],
    service_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Search for matching certificate patterns and service_ids.

    This is the unindexed reference scan; production code paths use a
    :class:`CompiledPatterns` instead.

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


CertificatePattern = SRVPattern | URIPattern | DNSPattern | IPAddressPattern
"""
A :class:`Union` of all possible patterns that can be extracted from a
certificate.
"""


_KNOWN_PATTERN_CLASSES = frozenset(
    {DNSPattern, URIPattern, SRVPattern, IPAddressPattern}
)


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
