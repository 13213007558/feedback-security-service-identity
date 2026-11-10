"""
Deterministic demonstration of the work saved by CompiledPatterns.

It does not rely on wall-clock timings: instead it counts how many
``ServiceID.verify`` candidate checks the linear scan and the compiled index
actually perform on fixed-seed, valid inputs.

Run from the repository root with the test suite importable, e.g.::

    PYTHONPATH=src .venv/bin/python docs/examples/compiled_patterns_demo.py
"""

from __future__ import annotations

import random

from service_identity.hazmat import CompiledPatterns

from tests.test_compiled import (
    SEED,
    _compiled_calls,
    _make_patterns,
    _make_service_ids,
    _scan_calls,
)


def main() -> None:
    rng = random.Random(SEED)
    patterns, domains = _make_patterns(rng)
    ids = _make_service_ids(random.Random(SEED + 4), domains)
    compiled = CompiledPatterns.compile(patterns)

    scan = _scan_calls(patterns, ids)
    compiled_calls = _compiled_calls(compiled, ids)

    print(f"patterns (SANs, incl. duplicates): {len(patterns)}")
    print(f"service IDs verified per round:    {len(ids)}")
    print(f"reference scan verify() calls:     {scan}")
    print(f"compiled index verify() calls:     {compiled_calls}")
    print(f"candidate checks avoided/round:    {scan - compiled_calls}")
    print(
        f"reduction:                         {1 - compiled_calls / scan:.1%}"
    )

    rounds = 25
    scan_total = 0
    compiled_total = 0
    for round_ in range(rounds):
        round_ids = _make_service_ids(
            random.Random(SEED + 100 + round_), domains
        )
        scan_total += _scan_calls(patterns, round_ids)
        compiled_total += _compiled_calls(compiled, round_ids)

    print()
    print(f"over {rounds} repeated verifications of the same certificate:")
    print(f"  reference scan total:            {scan_total}")
    print(f"  compiled total (parsed once):    {compiled_total}")
    print(f"  checks avoided:                  {scan_total - compiled_total}")
    print(
        "  reduction:                       "
        f"{1 - compiled_total / scan_total:.1%}"
    )


if __name__ == "__main__":
    main()
