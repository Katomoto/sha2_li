#!/usr/bin/env python3
"""Query SHA-2 Boolean signed-difference transitions and their double-bit conditions."""

from __future__ import annotations

import argparse
import json
from typing import Iterable

from sha256_reduced.boolean_conditions import (
    BOOLEAN_FUNCTION_NAMES,
    BooleanConditionProfile,
    enumerate_profiles,
    profile_for_pattern,
)


def _profile_to_dict(profile: BooleanConditionProfile) -> dict[str, object]:
    return {
        "function": profile.function,
        "pattern": profile.pattern,
        "satisfiable": profile.satisfiable,
        "num_assignments": profile.num_assignments,
        "double_bit_conditions": [str(condition) for condition in profile.pair_conditions],
        "fixed_values": [str(value) for value in profile.fixed_values],
        "assignments": [
            {"x": x, "y": y, "z": z, "out": out}
            for x, y, z, out in profile.assignments
        ],
    }


def _join_or_dash(values: Iterable[str]) -> str:
    rendered = ", ".join(values)
    return rendered if rendered else "-"


def _render_single_profile(profile: BooleanConditionProfile) -> str:
    lines = [
        f"function: {profile.function}",
        f"pattern: {profile.pattern}  (Delta x, Delta y, Delta z, Delta out)",
        f"satisfiable: {'yes' if profile.satisfiable else 'no'}",
        f"double-bit conditions: {_join_or_dash(str(condition) for condition in profile.pair_conditions)}",
        f"fixed values: {_join_or_dash(str(value) for value in profile.fixed_values)}",
        f"num assignments: {profile.num_assignments}",
    ]
    if profile.assignments:
        lines.append("left-side assignments:")
        for x, y, z, out in profile.assignments:
            lines.append(f"  x={x} y={y} z={z} out={out}")
    return "\n".join(lines)


def _render_table(profiles: Iterable[BooleanConditionProfile]) -> str:
    rows = [
        "function pattern sat count double-bit-conditions fixed-values",
    ]
    for profile in profiles:
        rows.append(
            " ".join(
                (
                    f"{profile.function:4s}",
                    f"{profile.pattern:7s}",
                    f"{'yes' if profile.satisfiable else 'no ':3s}",
                    f"{profile.num_assignments:5d}",
                    f"{_join_or_dash(str(condition) for condition in profile.pair_conditions):36s}",
                    _join_or_dash(str(value) for value in profile.fixed_values),
                )
            )
        )
    return "\n".join(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate SHA-2 Boolean-function signed-difference transitions and "
            "the implied double-bit conditions. All SHA-2 variants share the same "
            "per-bit Ch/Maj/Xor3 catalog."
        )
    )
    parser.add_argument(
        "--function",
        choices=("all", "if", "ch", "maj", "xor3"),
        default="all",
        help="Boolean function to inspect. 'ch' is an alias for 'if'.",
    )
    parser.add_argument(
        "--pattern",
        help="Optional 4-symbol Delta x Delta y Delta z Delta out pattern, using only '=', 'n', and 'u'.",
    )
    parser.add_argument(
        "--include-unsat",
        action="store_true",
        help="Include impossible signed-difference patterns in table output.",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format.",
    )
    return parser


def _selected_functions(name: str) -> tuple[str, ...]:
    if name == "all":
        return BOOLEAN_FUNCTION_NAMES
    return (name,)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    functions = _selected_functions(args.function)

    if args.pattern:
        profiles = tuple(profile_for_pattern(function, args.pattern) for function in functions)
        if args.format == "json":
            print(json.dumps([_profile_to_dict(profile) for profile in profiles], indent=2, sort_keys=True))
            return 0
        for index, profile in enumerate(profiles):
            if index:
                print()
            print(_render_single_profile(profile))
        return 0

    profiles = [
        profile
        for function in functions
        for profile in enumerate_profiles(function)
        if args.include_unsat or profile.satisfiable
    ]
    if args.format == "json":
        print(json.dumps([_profile_to_dict(profile) for profile in profiles], indent=2, sort_keys=True))
        return 0
    print(_render_table(profiles))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
