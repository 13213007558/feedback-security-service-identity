"""
`pyOpenSSL <https://github.com/pyca/pyopenssl>`_-specific code.
"""

from __future__ import annotations

import contextlib
import warnings

from collections.abc import Sequence

from .cryptography import extract_patterns as _cryptography_extract_patterns
from .hazmat import (
    DNS_ID,
    SPIFFE_ID,
    CertificatePattern,
    IPAddress_ID,
    ServiceMatch,
    verify_service_identity,
    verify_spiffe_identity,
)


with contextlib.suppress(ImportError):
    # We only use it for docstrings -- `if TYPE_CHECKING`` does not work.
    from OpenSSL.crypto import X509
    from OpenSSL.SSL import Connection


__all__ = ["verify_hostname"]


def verify_hostname(connection: Connection, hostname: str) -> None:
    r"""
    Verify whether the certificate of *connection* is valid for *hostname*.

    Args:
        connection: A pyOpenSSL connection object.

        hostname: The hostname that *connection* should be connected to.

    Raises:
        service_identity.VerificationError:
            If *connection* does not provide a certificate that is valid for
            *hostname*.

        service_identity.CertificateError:
            If certificate provided by *connection* contains invalid /
            unexpected data. This includes the case where the certificate
            contains no ``subjectAltName``\ s.

    .. versionchanged:: 24.1.0
        :exc:`~service_identity.CertificateError` is raised if the certificate
        contains no ``subjectAltName``\ s instead of
        :exc:`~service_identity.VerificationError`.
    """
    verify_service_identity(
        cert_patterns=extract_patterns(
            connection.get_peer_certificate()  # type:ignore[arg-type]
        ),
        obligatory_ids=[DNS_ID(hostname)],
        optional_ids=[],
    )


def verify_ip_address(connection: Connection, ip_address: str) -> None:
    r"""
    Verify whether the certificate of *connection* is valid for *ip_address*.

    Args:
        connection: A pyOpenSSL connection object.

        ip_address:
            The IP address that *connection* should be connected to. Can be an
            IPv4 or IPv6 address.

    Raises:
        service_identity.VerificationError:
            If *connection* does not provide a certificate that is valid for
            *ip_address*.

        service_identity.CertificateError:
            If the certificate chain of *connection* contains a certificate
            that contains invalid/unexpected data.

    .. versionadded:: 18.1.0

    .. versionchanged:: 24.1.0
        :exc:`~service_identity.CertificateError` is raised if the certificate
        contains no ``subjectAltName``\ s instead of
        :exc:`~service_identity.VerificationError`.
    """
    verify_service_identity(
        cert_patterns=extract_patterns(
            connection.get_peer_certificate()  # type:ignore[arg-type]
        ),
        obligatory_ids=[IPAddress_ID(ip_address)],
        optional_ids=[],
    )


def verify_spiffe_id(
    connection: Connection,
    spiffe_id: str,
    allowed_trust_domains: Sequence[str],
) -> list[ServiceMatch]:
    r"""
    Verify whether the certificate of *connection* contains the SPIFFE ID
    *spiffe_id* and the ID's trust domain is within *allowed_trust_domains*.

    The full identity -- trust domain and path -- must match exactly; no URL
    normalization is applied. Following the X.509-SVID policy, a certificate
    containing more than one SPIFFE ID is rejected with
    :exc:`~service_identity.CertificateError` instead of picking one by
    order.

    .. note::
        Only the *identity* is verified here. Nothing is verified about the
        *authority* of the certificate; the caller must verify that the
        certificate chains to an appropriate trust root themselves.

    Args:
        connection: A pyOpenSSL connection object.

        spiffe_id: The SPIFFE ID that the peer's certificate should contain,
            e.g. ``spiffe://example.com/ns/default/sa/web``.

        allowed_trust_domains: Trust domains the caller trusts. The
            certificate's contents can never widen this set.

    Returns:
        The list of matches, including the full matched identity.

    Raises:
        service_identity.VerificationError:
            If *connection* does not provide a certificate that contains
            *spiffe_id*, or its trust domain is not allowed.

        service_identity.CertificateError:
            If the certificate provided by *connection* contains invalid /
            unexpected data. This includes the case where the certificate
            contains no ``subjectAltName``\ s or more than one SPIFFE ID.

    .. versionadded:: 26.2.0
    """
    return verify_spiffe_identity(
        cert_patterns=extract_patterns(
            connection.get_peer_certificate()  # type:ignore[arg-type]
        ),
        spiffe_id=SPIFFE_ID(spiffe_id),
        allowed_trust_domains=allowed_trust_domains,
    )


def extract_patterns(cert: X509) -> Sequence[CertificatePattern]:
    r"""
    Extract all valid ID patterns from a certificate for service verification.

    Args:
        cert: The certificate to be dissected.

    Returns:
        List of IDs.

    .. versionchanged:: 23.1.0
       ``commonName`` is not used as a fallback anymore.

    .. versionchanged:: 26.2.0
       URI SANs with the ``spiffe`` scheme are extracted as
       ``SPIFFEPattern``\ s instead of ``URIPattern``\ s.
    """
    return _cryptography_extract_patterns(cert.to_cryptography())


def extract_ids(cert: X509) -> Sequence[CertificatePattern]:
    """
    Deprecated and never public API.  Use :func:`extract_patterns` instead.

    .. deprecated:: 23.1.0
    """
    warnings.warn(
        category=DeprecationWarning,
        message="`extract_ids()` is deprecated, please use `extract_patterns()`.",
        stacklevel=2,
    )
    return extract_patterns(cert)
