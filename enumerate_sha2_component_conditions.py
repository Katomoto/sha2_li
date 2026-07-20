#!/usr/bin/env python3
"""Inspect SHA-256 Sigma/sigma and full-adder double-bit condition tables."""

from __future__ import annotations

import argparse

from sha256_reduced.component_conditions import (
    SIGMA_SPECS,
    enumerate_addition_profiles,
    profile_for_addition_pattern,
    profile_for_sigma_pattern,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=("addition", *SIGMA_SPECS), required=True)
    parser.add_argument("--pattern", help="Five symbols for addition or four symbols for Sigma/sigma.")
    parser.add_argument("--output-bit", type=int, default=0, help="Sigma/sigma output bit index.")
    parser.add_argument("--include-unsat", action="store_true")
    return parser.parse_args()


def _conditions(profile) -> str:
    rendered = ", ".join(str(condition) for condition in profile.pair_conditions)
    return rendered or "-"


def main() -> int:
    args = _parse_args()
    if args.component == "addition":
        if args.pattern:
            profiles = (profile_for_addition_pattern(args.pattern),)
        else:
            profiles = enumerate_addition_profiles()
        print("component pattern sat assignments double-bit-conditions")
        for profile in profiles:
            if not args.include_unsat and not profile.satisfiable:
                continue
            print(
                f"addition {profile.pattern} "
                f"{'yes' if profile.satisfiable else 'no'} {len(profile.assignments)} {_conditions(profile)}"
            )
        return 0

    if not args.pattern:
        raise SystemExit("--pattern is required for Sigma/sigma lookup")
    if len(args.pattern) != 4:
        raise SystemExit("Sigma/sigma patterns must contain three input symbols and one output symbol")
    profile = profile_for_sigma_pattern(
        args.component,
        args.output_bit,
        args.pattern[:3],
        args.pattern[3],
    )
    print(f"component: {profile.component}")
    print(f"output_bit: {profile.output_bit}")
    print(f"input_bits: {profile.input_bits}")
    print(f"pattern: {profile.pattern}")
    print(f"satisfiable: {profile.boolean_profile.satisfiable}")
    print(f"double_bit_conditions: {_conditions(profile)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
