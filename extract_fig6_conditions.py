#!/usr/bin/env python3
"""Extract Fig. 6 conditions from signed symbols without a collision witness."""

from __future__ import annotations

import argparse

from sha256_reduced.equation_resolver import Sha256EquationResolver
from sha256_reduced.fig6 import FIG6_CONDITIONS, FIG6_PATTERNS, FIG6_ROUNDS
from sha256_reduced.fig6_analysis import (
    condition_key,
    equation_resolved_component_sources,
    modular_addition_sources,
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
        "--show-additions",
        action="store_true",
        help="Show equation-compatible full-adder table rows for one bit.",
    )
    parser.add_argument("--equation", choices=("W", "E", "A"), help="Equation kind for --show-additions.")
    parser.add_argument("--bit", type=int, default=0, help="Bit index for --show-additions.")
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

    if args.show_additions:
        if args.equation is None or args.round is None:
            raise SystemExit("--show-additions requires --equation and --round")
        resolver = Sha256EquationResolver(FIG6_PATTERNS, FIG6_ROUNDS, prefix="fig6_add_cli")
        equation = resolver.equation(args.equation, args.round)
        print(f"equation: {equation.name}")
        print(f"bit: {args.bit}")
        for stage in equation.additions:
            patterns = equation.possible_addition_patterns(stage.name, args.bit)
            conditions = equation.addition_conditions(stage.name, args.bit)
            rendered = ", ".join(str(condition) for condition in conditions) or "-"
            print(
                f"{stage.name}: patterns=[{','.join(patterns)}], "
                f"double_bit_conditions={rendered}"
            )
        return 0

    if args.show_components:
        selected = tuple(
            transition
            for transition in transitions
            if _component_matches(transition.source, args.component, args.round)
        )
        resolver = Sha256EquationResolver(FIG6_PATTERNS, FIG6_ROUNDS, prefix="fig6_cli")
        print(f"component_transitions: {len(selected)}")
        for transition in selected:
            status, equation_outputs = resolver.resolve_component(
                transition.equation_kind,
                transition.equation_index,
                transition.component,
                transition.bit,
                transition.output_symbols,
            )
            print(
                f"{transition.source}: input={transition.input_pattern}, "
                f"local_outputs={','.join(transition.output_symbols)}, "
                f"equation={transition.equation_kind}{transition.equation_index}, "
                f"equation_status={status}, resolved_outputs={','.join(equation_outputs)}"
            )
        return 0

    component_sources = equation_resolved_component_sources()
    addition_sources = modular_addition_sources()
    sources = {**addition_sources, **component_sources}
    recovered = {
        condition_key(condition)
        for condition in FIG6_CONDITIONS
        if condition_key(condition) in sources
    }
    print(f"component_transitions: {len(transitions)}")
    print(f"fig6_conditions: {len(FIG6_CONDITIONS)}")
    print(f"generated_component_conditions: {len(component_sources)}")
    print(f"generated_modular_addition_conditions: {len(addition_sources)}")
    print(f"recovered_fig6_conditions: {len(recovered)}")
    print(f"not_recovered_by_generated_tables: {len(FIG6_CONDITIONS) - len(recovered)}")

    for condition in FIG6_CONDITIONS:
        key = condition_key(condition)
        if not args.show_all and key in sources:
            continue
        if key in sources:
            detail = " | ".join(sources[key])
            print(f"{condition}: {detail}")
        else:
            print(f"{condition}: no equation-resolved component/addition-table source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
