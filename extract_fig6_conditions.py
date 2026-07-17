#!/usr/bin/env python3
"""Extract Fig. 6 conditions from signed symbols without a collision witness."""

from __future__ import annotations

import argparse

from sha256_reduced.fig6 import FIG6_CONDITIONS
from sha256_reduced.fig6_analysis import (
    condition_key,
    symbolic_boolean_sources,
    symbolic_component_transitions,
)


COMPONENTS = ("IF", "MAJ", "Sigma0", "Sigma1", "sigma0", "sigma1")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Propagate the Fig. 6 signed-difference characteristic through "
            "SHA-256 Boolean components and extract table conditions."
        )
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Print every Fig. 6 condition and its branch-qualified table source.",
    )
    parser.add_argument(
        "--show-components",
        action="store_true",
        help="Print component transitions instead of only the condition summary.",
    )
    parser.add_argument(
        "--component",
        choices=COMPONENTS,
        help="Optional component filter for --show-components.",
    )
    parser.add_argument("--round", type=int, help="Optional round/index filter for --show-components.")
    return parser.parse_args()


def _component_matches(source: str, component: str | None, index: int | None) -> bool:
    if component is not None and not source.startswith(component):
        return False
    if index is None:
        return True
    if component in ("IF", "MAJ"):
        return source.startswith(f"{component}@{index}[")
    if component is not None:
        return source.startswith(f"{component}(") and f"{index})[" in source
    return f"@{index}[" in source or f"{index})[" in source


def main() -> int:
    args = _parse_args()
    transitions = symbolic_component_transitions()

    if args.show_components:
        selected = tuple(
            transition
            for transition in transitions
            if _component_matches(transition.source, args.component, args.round)
        )
        print(f"component_transitions: {len(selected)}")
        for transition in selected:
            print(
                f"{transition.source}: input={transition.input_pattern}, "
                f"outputs={','.join(transition.output_symbols)}"
            )
        return 0

    sources = symbolic_boolean_sources()
    recovered = {
        condition_key(condition)
        for condition in FIG6_CONDITIONS
        if condition_key(condition) in sources
    }
    print(f"component_transitions: {len(transitions)}")
    print(f"fig6_conditions: {len(FIG6_CONDITIONS)}")
    print(f"boolean_table_candidates: {len(recovered)}")
    print(f"not_recovered_by_local_boolean_tables: {len(FIG6_CONDITIONS) - len(recovered)}")

    for condition in FIG6_CONDITIONS:
        key = condition_key(condition)
        if not args.show_all and key in sources:
            continue
        if key in sources:
            detail = " | ".join(sources[key])
            print(f"{condition}: {detail}")
        else:
            print(f"{condition}: no local Boolean-table source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
