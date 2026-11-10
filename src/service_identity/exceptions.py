"""
All exceptions and warnings thrown by ``service-identity``.

Separated into an own package for nicer tracebacks, you should still import
them from __init__.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .hazmat import ServiceID

import attr


class SubjectAltNameWarning(DeprecationWarning):
    """
    This warning is not used anymore and will be removed in a future version.

    Formerly:

    Server Certificate does not contain a ``SubjectAltName``.

    Hostname matching is performed on the ``CommonName`` which is deprecated.

    .. deprecated:: 23.1.0
    """


@attr.s(slots=True)
class Mismatch:
    mismatched_id: ServiceID = attr.ib()


class DNSMismatch(Mismatch):
    """
    No matching DNSPattern could be found.
    """


class SRVMismatch(Mismatch):
    """
    No matching SRVPattern could be found.
    """


class URIMismatch(Mismatch):
    """
    No matching URIPattern could be found.
    """


class IPAddressMismatch(Mismatch):
    """
    No matching IPAddressPattern could be found.
    """


@attr.s(auto_exc=True)
class VerificationError(Exception):
    """
    Service identity verification failed.
    """

    errors: Sequence[Mismatch] = attr.ib()

    def __str__(self) -> str:
        return self.__repr__()


class CertificateError(Exception):
    r"""
    Certificate contains invalid or unexpected data.

    This includes the case where s certificate contains no
    ``subjectAltName``\ s.
    """


@attr.s(auto_exc=True)
class IdentityRuleError(CertificateError):
    """
    A certificate pattern or service ID violates a rule of the active
    identity configuration.

    The *rule* attribute names the
    :class:`service_identity.hazmat.IdentityConfig` field that governs the
    violated rule, so migrating callers can tell exactly which rule they
    need to adjust (or temporarily relax).

    .. versionadded:: 26.2.0
    """

    rule: str = attr.ib()
    reason: str = attr.ib()

    def __str__(self) -> str:
        return f"identity rule {self.rule!r} violated: {self.reason}"
