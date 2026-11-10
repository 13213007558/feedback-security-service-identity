"""
Tests for the reusable compiled certificate pattern index.
"""

import ipaddress
import random

import pytest
from service_identity.exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    SRVMismatch,
    URIMismatch,
    VerificationError,
)
from service_identity.hazmat import (
    CompiledPatterns,
    DNS_ID,
    IPAddress_ID,
    SRV_ID,
    URI_ID,
    DNSPattern,
    IPAddressPattern,
    SRVPattern,
    URIPattern,
    ServiceMatch,
    _contains_instance_of,
    _find_matches,
    verify_service_identity,
)


SEED = 20261110


# ---------------------------------------------------------------------------
# Deterministic generators for medium-sized, always-valid inputs.
# ---------------------------------------------------------------------------


def _make_patterns(rng):
    """
    Build a medium-sized list of valid patterns of every supported type.

    Some SANs are repeated on purpose: duplicates must not change whether a
    service ID matches.
    """
    domains = [f"domain{i}.example{i % 7}.invalid" for i in range(24)]
    patterns: list = []

    for domain in domains:
        patterns.append(DNSPattern.from_bytes(domain.encode("ascii")))

    # Wildcards must keep at least three DNS labels.
    for i in range(8):
        patterns.append(
            DNSPattern.from_bytes(f"*.wild{i}.example.invalid".encode())
        )
    # A partial-label wildcard, still legal per the existing rules.
    patterns.append(DNSPattern.from_bytes(b"f*.partial.example.invalid"))

    protocols = ["sip", "xmpp", "ldap", "http"]
    for i, domain in enumerate(domains[:16]):
        patterns.append(
            URIPattern.from_bytes(
                f"{protocols[i % len(protocols)]}:{domain}".encode()
            )
        )

    services = ["mail", "xmpp-client", "xmpp-server", "ldap"]
    for i, domain in enumerate(domains[:16]):
        patterns.append(
            SRVPattern.from_bytes(
                f"_{services[i % len(services)]}.{domain}".encode()
            )
        )

    for i in range(8):
        patterns.append(
            IPAddressPattern(ipaddress.ip_address(f"10.10.{i // 16}.{i % 16}"))
        )
    for i in range(4):
        patterns.append(
            IPAddressPattern(ipaddress.ip_address(f"2001:db8::{i:x}"))
        )

    # Deliberate duplicates of different types.
    patterns.append(DNSPattern.from_bytes(domains[0].encode("ascii")))
    patterns.append(URIPattern.from_bytes(f"sip:{domains[0]}".encode("ascii")))
    patterns.append(
        SRVPattern.from_bytes(f"_mail.{domains[0]}".encode("ascii"))
    )
    patterns.append(IPAddressPattern(ipaddress.ip_address("10.10.0.0")))

    rng.shuffle(patterns)

    return patterns, domains


def _make_service_ids(rng, domains):
    """
    Build service IDs that match or deliberately miss the generated
    patterns, in a random order and with random duplicates.
    """
    ids: list = []

    for domain in rng.sample(domains, k=12):
        ids.append(DNS_ID(domain))
    # Hostnames that can only match a wildcard pattern.
    for i in range(6):
        ids.append(DNS_ID(f"host{i}.wild{i}.example.invalid"))
    # Non-matching DNS IDs.
    for i in range(6):
        ids.append(DNS_ID(f"missing{i}.nowhere.invalid"))

    for i in range(6):
        ids.append(URI_ID(f"sip:{domains[i]}"))
    ids.append(URI_ID("xmpp:domain0.example0.invalid"))
    ids.append(URI_ID("sip:missing.nowhere.invalid"))

    for i in range(6):
        ids.append(SRV_ID(f"_mail.{domains[i]}"))
    ids.append(SRV_ID("_xmpp-client.domain1.example1.invalid"))
    ids.append(SRV_ID("_mail.missing.nowhere.invalid"))

    for i in range(6):
        ids.append(IPAddress_ID(f"10.10.0.{i}"))
    ids.append(IPAddress_ID("2001:db8::1"))
    ids.append(IPAddress_ID("192.0.2.7"))

    # Repeat some IDs, like a gateway verifying overlapping services.
    ids.extend(rng.sample(ids, k=8))
    rng.shuffle(ids)

    return ids


def _reference_verify(cert_patterns, obligatory_ids, optional_ids):
    """
    A faithful copy of the pre-indexing verification algorithm.
    """
    if not cert_patterns:
        raise CertificateError(
            "Certificate does not contain any `subjectAltName`s."
        )

    matches = _find_matches(cert_patterns, obligatory_ids) + _find_matches(
        cert_patterns, optional_ids
    )

    matched_ids = [match.service_id for match in matches]
    errors = []
    for service_id in obligatory_ids:
        if service_id not in matched_ids:
            errors.append(
                service_id.error_on_mismatch(mismatched_id=service_id)
            )
    for service_id in optional_ids:
        if service_id not in matched_ids and _contains_instance_of(
            cert_patterns, service_id.pattern_class
        ):
            errors.append(
                service_id.error_on_mismatch(mismatched_id=service_id)
            )

    if errors:
        raise VerificationError(errors=errors)

    return matches


def _reference_outcome(cert_patterns, obligatory, optional):
    try:
        return (
            True,
            _reference_verify(cert_patterns, obligatory, optional),
        )
    except VerificationError as error:
        return False, error


def _compiled_outcome(compiled, obligatory, optional):
    try:
        return True, compiled.verify(obligatory, optional)
    except VerificationError as error:
        return False, error


# ---------------------------------------------------------------------------
# Equivalence against the unindexed scan.
# ---------------------------------------------------------------------------


class TestCompiledEquivalence:
    """
    The compiled index must behave exactly like the original linear scan.
    """

    def test_matches_match_reference_item_by_item(self):
        """
        Successful verifications return the same ServiceMatch objects in the
        same stable order as the reference scan, across many fixed-seed
        inputs and obligatory/optional splits.
        """
        rng = random.Random(SEED)
        patterns, domains = _make_patterns(rng)
        compiled = CompiledPatterns.compile(patterns)

        assert compiled.patterns == tuple(patterns)

        for _ in range(30):
            ids = _make_service_ids(
                random.Random(rng.getrandbits(64)), domains
            )
            cut = rng.randrange(len(ids))
            obligatory = ids[:cut]
            optional = ids[cut:]

            ok_ref, ref = _reference_outcome(patterns, obligatory, optional)
            ok_new, new = _compiled_outcome(compiled, obligatory, optional)

            assert ok_ref is ok_new
            if ok_ref:
                assert ref == new
                assert [m.service_id for m in ref] == [
                    m.service_id for m in new
                ]
                assert [m.cert_pattern for m in ref] == [
                    m.cert_pattern for m in new
                ]
            else:
                assert ref.errors == new.errors
                assert [error.__class__ for error in ref.errors] == [
                    error.__class__ for error in new.errors
                ]

    @pytest.mark.parametrize(
        "mismatch",
        [
            (DNS_ID, "nope.example.invalid", DNSMismatch),
            (URI_ID, "sip:nope.example.invalid", URIMismatch),
            (SRV_ID, "_mail.nope.example.invalid", SRVMismatch),
            (IPAddress_ID, "192.0.2.10", IPAddressMismatch),
        ],
    )
    def test_error_categories_are_equivalent(self, mismatch):
        """
        Every identity type raises the same mismatch category through both
        code paths.
        """
        rng = random.Random(SEED)
        patterns, _ = _make_patterns(rng)
        compiled = CompiledPatterns.compile(patterns)
        constructor, value, expected = mismatch
        service_id = constructor(value)

        ok_ref, ref = _reference_outcome(patterns, [service_id], [])
        ok_new, new = _compiled_outcome(compiled, [service_id], [])

        assert ok_ref is False and ok_new is False
        assert ref.errors == new.errors
        assert isinstance(ref.errors[0], expected)

    def test_duplicate_sans_do_not_change_outcome(self):
        """
        Repeating SANs leaves both matching decisions and match order
        identical between the scan and the index.
        """
        rng = random.Random(SEED + 1)
        patterns, domains = _make_patterns(rng)
        duplicated = patterns + patterns
        compiled = CompiledPatterns.compile(duplicated)
        ids = _make_service_ids(random.Random(SEED + 2), domains)

        ok_ref, ref = _reference_outcome(duplicated, ids, [])
        ok_new, new = _compiled_outcome(compiled, ids, [])

        assert ok_ref is ok_new
        if ok_ref:
            assert ref == new
        else:
            assert ref.errors == new.errors

        # Duplicates never flip a matching decision: every service ID gets
        # exactly twice as many matches against the doubled certificate, in
        # the same relative order as against the single one.
        single = CompiledPatterns.compile(patterns)
        single_matches = single._find_matches(ids)
        duplicated_matches = compiled._find_matches(ids)

        for service_id in ids:
            single_for_id = [
                match
                for match in single_matches
                if match.service_id == service_id
            ]
            duplicated_for_id = [
                match
                for match in duplicated_matches
                if match.service_id == service_id
            ]

            assert duplicated_for_id == single_for_id + single_for_id

    def test_optional_semantics_without_matching_type(self):
        """
        An optional ID whose pattern type is absent stays optional and does
        not raise, just like the scan.
        """
        dns_pattern = DNSPattern.from_bytes(b"mail.example.invalid")
        compiled = CompiledPatterns.compile([dns_pattern])
        optional = URI_ID("sip:mail.example.invalid")

        assert compiled.verify([], [optional]) == []
        assert _reference_verify([dns_pattern], [], [optional]) == []

    def test_optional_mismatch_still_errors(self):
        """
        An optional ID conflicting with a present pattern of the same type
        still fails through the index.
        """
        rng = random.Random(SEED + 3)
        patterns, _ = _make_patterns(rng)
        compiled = CompiledPatterns.compile(patterns)
        optional = SRV_ID("_unknown.missing.invalid")

        with pytest.raises(VerificationError) as new:
            compiled.verify([], [optional])
        with pytest.raises(VerificationError) as ref:
            _reference_verify(patterns, [], [optional])

        assert new.value.errors == ref.value.errors
        assert isinstance(new.value.errors[0], SRVMismatch)

    def test_empty_patterns_raise_certificate_error(self):
        """
        An empty certificate keeps raising the same CertificateError.
        """
        with pytest.raises(
            CertificateError,
            match="Certificate does not contain any `subjectAltName`s",
        ):
            CompiledPatterns.compile([]).verify([DNS_ID("a.b.c")])


# ---------------------------------------------------------------------------
# Candidate narrowing and the work it saves.
# ---------------------------------------------------------------------------


class CountingID:
    """
    Delegating service ID wrapper that counts candidate verify() calls.
    """

    def __init__(self, wrapped):
        self._wrapped = wrapped
        self.calls = 0

    @property
    def pattern_class(self):
        return self._wrapped.pattern_class

    @property
    def error_on_mismatch(self):
        return self._wrapped.error_on_mismatch

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def verify(self, pattern):
        self.calls += 1

        return self._wrapped.verify(pattern)

    def __eq__(self, other):
        if isinstance(other, CountingID):
            return self._wrapped == other._wrapped

        return self._wrapped == other

    def __hash__(self):
        return hash(self._wrapped)


def _scan_calls(patterns, ids):
    counters = [CountingID(service_id) for service_id in ids]
    _find_matches(patterns, counters)

    return sum(counter.calls for counter in counters)


def _compiled_calls(compiled, ids):
    counters = [CountingID(service_id) for service_id in ids]
    compiled._find_matches(counters)

    return sum(counter.calls for counter in counters)


class TestCandidateNarrowing:
    def test_fewer_candidates_than_full_scan(self):
        """
        The index only invokes verify() on narrowed candidates, so it
        performs strictly fewer candidate checks than the linear scan while
        producing identical matches.
        """
        rng = random.Random(SEED)
        patterns, domains = _make_patterns(rng)
        compiled = CompiledPatterns.compile(patterns)
        ids = _make_service_ids(random.Random(SEED + 4), domains)

        scan_calls = _scan_calls(patterns, ids)
        compiled_calls = _compiled_calls(compiled, ids)

        assert scan_calls == len(ids) * len(patterns)
        assert compiled_calls < scan_calls
        assert _find_matches(patterns, ids) == compiled._find_matches(ids)

    def test_dns_skips_unrelated_types_and_wildcard_tails(self):
        """
        A DNS ID is never checked against URI/SRV/IP patterns, and wildcard
        patterns with a different tail are skipped entirely.
        """
        patterns = [
            DNSPattern.from_bytes(b"exact.example.invalid"),
            DNSPattern.from_bytes(b"*.other.example.invalid"),
            DNSPattern.from_bytes(b"*.example.invalid"),
            URIPattern.from_bytes(b"sip:exact.example.invalid"),
            SRVPattern.from_bytes(b"_mail.example.invalid"),
            IPAddressPattern(ipaddress.ip_address("10.0.0.1")),
        ]
        compiled = CompiledPatterns.compile(patterns)
        counter = CountingID(DNS_ID("host.example.invalid"))

        matches = compiled._find_matches([counter])

        # Only the exact-bucket miss and the same-tail wildcard are checked;
        # the other wildcard, URI, SRV and IP patterns are skipped.
        assert counter.calls == 1
        assert matches == [
            ServiceMatch(
                service_id=counter._wrapped,
                cert_pattern=DNSPattern.from_bytes(b"*.example.invalid"),
            )
        ]

    def test_single_label_hostname_skips_wildcards(self):
        """
        A single-label hostname cannot match a wildcard and gets no
        wildcard candidates.
        """
        compiled = CompiledPatterns.compile(
            [DNSPattern.from_bytes(b"*.example.invalid")]
        )
        counter = CountingID(DNS_ID("localhost"))

        assert compiled._find_matches([counter]) == []
        assert counter.calls == 0

    def test_repeated_verification_pays_indexing_only_once(self):
        """
        Demonstrate the work saved on repeated gateway verification with
        deterministic candidate counts instead of wall-clock timings.
        """
        rng = random.Random(SEED)
        patterns, domains = _make_patterns(rng)
        rounds = 12
        id_sets = [
            _make_service_ids(random.Random(SEED + 100 + round_), domains)
            for round_ in range(rounds)
        ]

        scan_total = 0
        for ids in id_sets:
            scan_total += _scan_calls(patterns, ids)

        compiled = CompiledPatterns.compile(patterns)
        compiled_total = 0
        for ids in id_sets:
            compiled_total += _compiled_calls(compiled, ids)

        # The reference work grows with every round times every SAN; the
        # compiled index is built once and only re-runs narrowed checks.
        assert scan_total == sum(len(ids) * len(patterns) for ids in id_sets)
        assert compiled_total < scan_total
        assert compiled_total <= scan_total // 2

        # Parsing/validation happens once: compiling again is not required,
        # and the same object keeps returning equal, stable results.
        assert compiled._find_matches(id_sets[0]) == compiled._find_matches(
            id_sets[0]
        )


# ---------------------------------------------------------------------------
# Encapsulation: the index cannot be corrupted from outside.
# ---------------------------------------------------------------------------


class TestCompilationEncapsulation:
    def test_mutating_input_list_does_not_affect_index(self):
        """
        Appending, removing or reordering the caller's list after compiling
        leaves the compiled result untouched.
        """
        original = [
            DNSPattern.from_bytes(b"one.example.invalid"),
            DNSPattern.from_bytes(b"two.example.invalid"),
        ]
        compiled = CompiledPatterns.compile(original)

        original.append(DNSPattern.from_bytes(b"three.example.invalid"))
        original.reverse()
        original.clear()

        assert [
            DNSPattern.from_bytes(b"one.example.invalid"),
            DNSPattern.from_bytes(b"two.example.invalid"),
        ] == list(compiled.patterns)
        assert compiled.verify([DNS_ID("one.example.invalid")])

    def test_compiled_patterns_preserve_object_identity(self):
        """
        The index stores the caller's validated pattern objects rather than
        replacing them with copies, so identity-based matching keeps working
        and returned ServiceMatch objects reference the same patterns.
        """
        dns = DNSPattern.from_bytes(b"one.example.invalid")
        compiled = CompiledPatterns.compile([dns])

        assert compiled.patterns[0] is dns
        match = compiled.verify([DNS_ID("one.example.invalid")])[0]
        assert match.cert_pattern is dns

    def test_indexes_are_not_shared_between_certificates(self):
        """
        A second certificate gets an independent index; matches from one
        certificate can never leak into another one.
        """
        first = [DNSPattern.from_bytes(b"shared.example.invalid")]
        second = [DNSPattern.from_bytes(b"other.example.invalid")]

        compiled_first = CompiledPatterns.compile(first)
        compiled_second = CompiledPatterns.compile(second)

        assert compiled_first.verify([DNS_ID("shared.example.invalid")])
        with pytest.raises(VerificationError):
            compiled_second.verify([DNS_ID("shared.example.invalid")])
        assert compiled_first.patterns is not compiled_second.patterns

    def test_invalid_san_is_rejected_not_indexed(self):
        """
        Validation remains owned by the pattern constructors: an invalid SAN
        raises CertificateError when the pattern is built, and compiling
        never silently drops a pattern.
        """
        with pytest.raises(CertificateError):
            DNSPattern.from_bytes(b"*.foo.*")

        valid = [DNSPattern.from_bytes(b"good.example.invalid")]
        compiled = CompiledPatterns.compile(valid)

        assert len(compiled.patterns) == len(valid)

    def test_accepts_compiled_object_and_plain_list_equivalently(self):
        """
        verify_service_identity accepts both the legacy list input and a
        compiled object and returns equivalent matches and errors.
        """
        rng = random.Random(SEED + 5)
        patterns, domains = _make_patterns(rng)
        ids = _make_service_ids(random.Random(SEED + 6), domains)
        compiled = CompiledPatterns.compile(patterns)

        list_result = _public_outcome(patterns, ids)
        compiled_result = _public_outcome(compiled, ids)

        assert list_result[0] is compiled_result[0]
        if list_result[0]:
            assert list_result[1] == compiled_result[1]
        else:
            assert list_result[1].errors == compiled_result[1].errors

        # A guaranteed-matching call succeeds through both input shapes.
        good = [DNS_ID(domains[0])]
        assert verify_service_identity(patterns, good, []) == (
            verify_service_identity(compiled, good, [])
        )

    def test_unknown_pattern_type_is_scanned_but_not_duplicated(self):
        """
        Patterns of a type the index does not know stay in the "other"
        bucket: unknown IDs scan them once, known IDs still consider them,
        and no candidate index is ever visited twice.
        """

        class OtherPattern:
            def __init__(self, marker):
                self.marker = marker

        class OtherID:
            pattern_class = OtherPattern

            class error_on_mismatch:
                def __init__(self, mismatched_id):
                    self.mismatched_id = mismatched_id

            def __init__(self):
                self.calls = 0

            def verify(self, pattern):
                self.calls += 1

                return isinstance(pattern, OtherPattern)

        known = DNSPattern.from_bytes(b"known.example.invalid")
        others = [OtherPattern("a"), OtherPattern("b")]
        compiled = CompiledPatterns.compile([known, *others])

        other_id = OtherID()
        other_matches = compiled._find_matches([other_id])

        # Each of the three patterns is evaluated exactly once.
        assert other_id.calls == 3
        assert len(other_matches) == 2

        dns_id = DNS_ID("known.example.invalid")
        dns_matches = compiled.verify([dns_id])

        assert [match.cert_pattern for match in dns_matches] == [known]
        assert compiled._contains_pattern_type(OtherPattern) is True
        assert compiled._contains_pattern_type(URIPattern) is False


def _public_outcome(cert_patterns, ids):
    try:
        return True, verify_service_identity(cert_patterns, ids, [])
    except VerificationError as error:
        return False, error
