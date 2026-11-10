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
    IdentityRuleError,
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


@attr.s(frozen=True, slots=True)
class IdentityConfig:
    """
    Per-verification configuration of identity matching rules.

    The defaults are backward-compatible with the historical behavior of
    *service-identity* ("legacy").  Use :meth:`strict` for DNS-ID handling
    aligned with `RFC 9525 <https://www.rfc-editor.org/rfc/rfc9525.html>`_
    and relax individual rules while migrating callers over.

    The configuration is passed per verification call, so strict and
    legacy services can be migrated independently without loosening
    verification process-wide.

    DNS names and IP addresses always remain distinct identity types in
    every configuration: a string that looks like an IP literal is never
    matched as a DNS name, and vice versa.

    .. versionadded:: 26.2.0
    """

    allow_partial_wildcards: bool = attr.ib(default=True)
    """
    Tolerate wildcards that are not the complete left-most label of a DNS
    pattern (e.g. ``ww*.example.com``).

    RFC 9525 only allows ``*`` as the entire left-most label, matching
    exactly one label.
    """

    allow_invalid_dns_syntax: bool = attr.ib(default=True)
    """
    Tolerate DNS patterns that violate the preferred name syntax from RFC
    1034/1123: non-ASCII bytes (only IDNA A-labels are valid), empty
    labels, or labels with leading/trailing hyphens.

    An invalid DNS SAN is never silently ignored under a strict
    configuration: its presence fails the verification, even if another
    SAN would match.
    """

    allow_trailing_dot: bool = attr.ib(default=True)
    """
    Tolerate DNS-IDs with a trailing dot (e.g. ``www.example.com.``).

    Note that even in the legacy configuration, such IDs never match a
    certificate pattern; a strict configuration rejects them up front with
    an :class:`service_identity.IdentityRuleError` that names this rule.
    """

    @classmethod
    def strict(cls) -> IdentityConfig:
        """
        Return a configuration that handles DNS-IDs according to RFC 9525:

        - wildcards only as the complete left-most label, matching exactly
          one label,
        - DNS patterns must be valid IDNA A-labels in preferred name
          syntax,
        - DNS-IDs with a trailing dot are rejected,
        - invalid SANs fail the verification instead of being skipped.
        """
        return cls(
            allow_partial_wildcards=False,
            allow_invalid_dns_syntax=False,
            allow_trailing_dot=False,
        )


def verify_service_identity(
    cert_patterns: Sequence[CertificatePattern],
    obligatory_ids: Sequence[ServiceID],
    optional_ids: Sequence[ServiceID],
    *,
    config: IdentityConfig | None = None,
) -> list[ServiceMatch]:
    """
    Verify whether *cert_patterns* are valid for *obligatory_ids* and
    *optional_ids*.

    *obligatory_ids* must be both present and match.  *optional_ids* must match
    if a pattern of the respective type is present.

    *config* optionally overrides the identity matching rules for this
    verification only.  If `None`, the backward-compatible defaults of
    :class:`IdentityConfig` are used.

    .. versionchanged:: 26.2.0
        Added the optional *config* parameter.
    """
    if config is None:
        config = IdentityConfig()

    if not cert_patterns:
        msg = "Certificate does not contain any `subjectAltName`s."
        raise CertificateError(msg)

    _enforce_identity_rules(
        cert_patterns, obligatory_ids, optional_ids, config
    )

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


def _enforce_identity_rules(
    cert_patterns: Sequence[CertificatePattern],
    obligatory_ids: Sequence[ServiceID],
    optional_ids: Sequence[ServiceID],
    config: IdentityConfig,
) -> None:
    """
    Enforce the rules of *config* on all patterns and service IDs.

    Raises an IdentityRuleError naming the violated rule, so an invalid
    SAN can never be silently ignored in favor of a more lenient
    candidate.
    """
    if (
        not config.allow_partial_wildcards
        or not config.allow_invalid_dns_syntax
    ):
        for pattern in cert_patterns:
            for dns_pattern in _dns_patterns_of(pattern):
                _verify_dns_pattern_rules(dns_pattern.pattern, config)

    if not config.allow_trailing_dot:
        for service_id in (*obligatory_ids, *optional_ids):
            _verify_service_id_rules(service_id)


def _dns_patterns_of(pattern: CertificatePattern) -> list[DNSPattern]:
    """
    Return all DNS patterns contained in *pattern*.
    """
    if isinstance(pattern, DNSPattern):
        return [pattern]
    if isinstance(pattern, URIPattern | SRVPattern):
        return [pattern.dns_pattern]
    return []


_RE_STRICT_DNS_LABEL = re.compile(rb"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _verify_dns_pattern_rules(pattern: bytes, config: IdentityConfig) -> None:
    """
    Check *pattern* against the DNS rules of *config*.
    """
    if not config.allow_partial_wildcards and b"*" in pattern:
        parts = pattern.split(b".")
        if parts[0] != b"*" or any(b"*" in part for part in parts[1:]):
            raise IdentityRuleError(
                rule="allow_partial_wildcards",
                reason=f"DNS pattern {pattern!r} uses a wildcard that is "
                "not the complete left-most label.",
            )

    if not config.allow_invalid_dns_syntax:
        try:
            pattern.decode("ascii")
        except UnicodeDecodeError:
            raise IdentityRuleError(
                rule="allow_invalid_dns_syntax",
                reason=f"DNS pattern {pattern!r} is not ASCII; "
                "only IDNA A-labels are valid.",
            ) from None

        for label in pattern.split(b"."):
            if label == b"*":
                # A full-label wildcard is governed by
                # allow_partial_wildcards, not by label syntax.
                continue
            # Tolerated partial wildcards don't take part in the syntax
            # check of the remaining characters.
            label = label.replace(b"*", b"")
            if not label or _RE_STRICT_DNS_LABEL.match(label) is None:
                raise IdentityRuleError(
                    rule="allow_invalid_dns_syntax",
                    reason=f"DNS pattern {pattern!r} violates the "
                    "preferred DNS name syntax (empty label, "
                    "leading/trailing hyphen, or invalid character).",
                )


def _verify_service_id_rules(service_id: ServiceID) -> None:
    """
    Check *service_id* against the strict DNS-ID rules.
    """
    dns_id = None
    if isinstance(service_id, DNS_ID):
        dns_id = service_id
    elif isinstance(service_id, URI_ID | SRV_ID):
        dns_id = service_id.dns_id

    if dns_id is not None and dns_id.hostname.endswith(b"."):
        raise IdentityRuleError(
            rule="allow_trailing_dot",
            reason=f"DNS-ID {dns_id.hostname!r} has a trailing dot; "
            "strip it or relax the rule.",
        )


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
