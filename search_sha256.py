#!/usr/bin/env python3
"""SAT/SMT search entry points for Li et al.'s reduced SHA-256 attacks."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from sha256_reduced.conditions import TABLE14_15_CONDITIONS, failing_conditions
from sha256_reduced.core import digest_blocks, expand_message, format_words
from sha256_reduced.differential import trace_collision_second_block
from sha256_reduced.smt_characteristic import Algorithm1Options, CharacteristicSearch
from sha256_reduced.smt_value import Sha256ValueModel
from sha256_reduced.solver import MissingSolverError
from sha256_reduced.vectors import TABLE_13_31_STEP_COLLISION

SECTION_4_1_W_INDICES = frozenset({8, 9, 10, 11, 12, 16, 17, 24, 26})
SECTION_4_1_DELTA_A_ZERO_RANGE = range(19, 39)
SECTION_4_1_DELTA_E_ZERO_RANGE = range(23, 39)


def _table13_second_block_values() -> dict[tuple[str, int], int]:
    vector = TABLE_13_31_STEP_COLLISION
    cv = digest_blocks(vector.blocks[:1], vector.rounds, iv=vector.iv)
    rows = trace_collision_second_block(vector)
    # Recompute concrete left-side words for Table 14/15 conditions.
    block = vector.blocks[1]
    w = expand_message(block, vector.rounds)

    from sha256_reduced.core import compress

    _, states = compress(cv, block, vector.rounds, trace=True)
    values: dict[tuple[str, int], int] = {("W", i): word for i, word in enumerate(w)}
    values.update({("A", -1): cv[0], ("A", -2): cv[1], ("A", -3): cv[2], ("A", -4): cv[3]})
    values.update({("E", -1): cv[4], ("E", -2): cv[5], ("E", -3): cv[6], ("E", -4): cv[7]})
    values.update({("A", state.step): state.a for state in states})
    values.update({("E", state.step): state.e for state in states})
    return values


def cmd_check_table13_conditions(_args: argparse.Namespace) -> int:
    failures = failing_conditions(TABLE14_15_CONDITIONS, _table13_second_block_values())
    if failures:
        print(f"FAIL: {len(failures)} Table 14/15 conditions did not hold")
        for condition in failures:
            print(f"  {condition}")
        return 1
    print(f"PASS: all {len(TABLE14_15_CONDITIONS)} Table 14/15 message-modification conditions hold")
    return 0


def _print_characteristic_result(label: str, result: Any) -> None:
    print(label)
    print("nonzero W rows:")
    for i, word in enumerate(result.w):
        if "u" in word or "n" in word:
            print(f"W{i:02d} {word}")
    print("nonzero A rows:")
    for i in range(-4, 39):
        word = result.a[i]
        if "u" in word or "n" in word:
            print(f"A{i:02d} {word}")
    print("nonzero E rows:")
    for i in range(-4, 39):
        word = result.e[i]
        if "u" in word or "n" in word:
            print(f"E{i:02d} {word}")


def cmd_char_search(args: argparse.Namespace) -> int:
    options = Algorithm1Options(
        op1=bool(args.op1),
        op2=bool(args.op2),
        op3=bool(args.op3),
        op4=bool(args.op4),
        op5=bool(args.op5),
        op6=bool(args.op6),
        op7=bool(args.op7),
        op8=bool(args.op8),
        value_transition_steps=frozenset(args.value_transition_steps) if args.value_transition_steps else None,
    )
    search = CharacteristicSearch(args.rounds, options=options)
    if args.shape == "31":
        search.constrain_message_shape({5, 6, 7, 8, 9, 16, 18})
    elif args.shape == "39":
        search.constrain_message_shape({8, 9, 10, 11, 12, 16, 17, 24, 26})
    elif args.shape == "single":
        search.constrain_message_shape({args.single_word})
    search.constrain_final_state_zero()
    search.require_nonzero_message_difference()
    search.minimize_weight(search.w[: args.rounds])
    if args.paper_objective:
        search.minimize_weight([search.a_rows[i] for i in range(args.rounds)])
        search.minimize_weight([search.e_rows[i] for i in range(args.rounds)])
    result = search.solve(
        timeout_ms=args.timeout_ms,
        random_seed=args.seed,
        solver_threads=args.solver_threads,
    )
    if result is None:
        print("UNSAT/UNKNOWN: no characteristic found within the configured timeout")
        return 2
    print("SAT: signed differential characteristic")
    for i, word in enumerate(result.w):
        if "u" in word or "n" in word:
            print(f"W{i:02d} {word}")
    return 0


def _section_4_1_options(args: argparse.Namespace) -> Algorithm1Options:
    return Algorithm1Options(
        op1=bool(args.op1),
        op2=bool(args.op2),
        op3=bool(args.op3),
        op4=bool(args.op4),
        op5=bool(args.op5),
        op6=bool(args.op6),
        op7=bool(args.op7),
        op8=bool(args.op8),
        value_transition_steps=frozenset(args.value_transition_steps) if args.value_transition_steps else None,
    )


def _build_section_4_1_search(options: Algorithm1Options) -> CharacteristicSearch:
    search = CharacteristicSearch(39, options=options)
    search.require_nonzero_message_difference()
    for i in range(39):
        if i not in SECTION_4_1_W_INDICES:
            search.constrain_modular_zero("W", i, method1=options.op7)
    return search


def _solve_section_4_1_phase1(
    seed: int,
    timeout_ms: int,
    solver_threads: int | None,
    options: Algorithm1Options,
) -> int | None:
    phase1 = _build_section_4_1_search(options)
    weight_w_words = [phase1.w[i] for i in range(39)]
    phase1.minimize_weight(weight_w_words)
    model1 = phase1.solve_model(timeout_ms=timeout_ms, random_seed=seed, solver_threads=solver_threads)
    if model1 is None:
        return None
    return phase1.model_weight(model1, weight_w_words)


def _solve_section_4_1_phase2(
    seed: int,
    timeout_ms: int,
    solver_threads: int | None,
    options: Algorithm1Options,
    tw: int,
) -> int | None:
    phase2 = _build_section_4_1_search(options)
    phase2.optimizer.add(phase2.weight_expr([phase2.w[i] for i in range(39)]) == tw)
    phase2.constrain_modular_zero_range("A", 19, 38, method1=options.op6)
    phase2.constrain_modular_zero_range("E", 23, 38, method1=options.op3)
    weight_a_words = [phase2.a_rows[i] for i in range(39)]
    phase2.minimize_weight(weight_a_words)
    model2 = phase2.solve_model(timeout_ms=timeout_ms, random_seed=seed, solver_threads=solver_threads)
    if model2 is None:
        return None
    return phase2.model_weight(model2, weight_a_words)


def _solve_section_4_1_phase3(
    seed: int,
    timeout_ms: int,
    solver_threads: int | None,
    options: Algorithm1Options,
    tw: int,
    ta: int,
) -> tuple[int, Any] | None:
    phase3 = _build_section_4_1_search(options)
    phase3.optimizer.add(phase3.weight_expr([phase3.w[i] for i in range(39)]) == tw)
    phase3.constrain_modular_zero_range("A", 19, 38, method1=options.op6)
    phase3.constrain_modular_zero_range("E", 23, 38, method1=options.op3)
    phase3.optimizer.add(phase3.weight_expr([phase3.a_rows[i] for i in range(39)]) == ta)
    weight_e_words = [phase3.e_rows[i] for i in range(39)]
    phase3.minimize_weight(weight_e_words)
    model3 = phase3.solve_model(timeout_ms=timeout_ms, random_seed=seed, solver_threads=solver_threads)
    if model3 is None:
        return None
    return phase3.model_weight(model3, weight_e_words), phase3.result_from_model(model3)


def _solve_msgmod_table13(
    seed: int,
    timeout_ms: int,
    solver_threads: int | None,
) -> dict[str, tuple[int, ...]] | None:
    vector = TABLE_13_31_STEP_COLLISION
    cv = digest_blocks(vector.blocks[:1], vector.rounds, iv=vector.iv)
    model = Sha256ValueModel(vector.rounds, prefix=f"table13_{seed}")
    model.fix_cv(cv)
    model.require_collision_output()
    model.require_messages_differ()
    model.require_same_words_outside({5, 6, 7, 8, 9})
    model.add_bit_conditions(TABLE14_15_CONDITIONS)

    rows = trace_collision_second_block(vector)
    for row in rows:
        if row.step >= 0 and row.w:
            model.add_signed_pattern("W", row.step, row.w)
        if row.a:
            model.add_signed_pattern("A", row.step, row.a)
        if row.e:
            model.add_signed_pattern("E", row.step, row.e)

    return model.solve(timeout_ms=timeout_ms, random_seed=seed, solver_threads=solver_threads)


def cmd_section_4_1_search(args: argparse.Namespace) -> int:
    options = _section_4_1_options(args)
    tw = _solve_section_4_1_phase1(args.seed, args.timeout_ms, args.solver_threads, options)
    if tw is None:
        print("UNSAT/UNKNOWN at Section 4.1 phase 1 (minimize ΔW)")
        return 2
    ta = _solve_section_4_1_phase2(args.seed, args.timeout_ms, args.solver_threads, options, tw)
    if ta is None:
        print("UNSAT/UNKNOWN at Section 4.1 phase 2 (minimize ΔA)")
        return 2
    phase3_result = _solve_section_4_1_phase3(args.seed, args.timeout_ms, args.solver_threads, options, tw, ta)
    if phase3_result is None:
        print("UNSAT/UNKNOWN at Section 4.1 phase 3 (minimize ΔE)")
        return 2
    weight_e, result = phase3_result

    print("SAT: Section 4.1 39-step characteristic search")
    print(f"phase1 tw = {tw}")
    print(f"phase2 tA = {ta}")
    print(f"phase3 tE = {weight_e}")
    _print_characteristic_result("characteristic:", result)
    return 0


def cmd_msgmod_solve_table13(args: argparse.Namespace) -> int:
    solution = _solve_msgmod_table13(args.seed, args.timeout_ms, args.solver_threads)
    if solution is None:
        print("UNSAT/UNKNOWN: no conforming message pair found within the configured timeout")
        return 2
    print("SAT: conforming Table 13-style message pair")
    print(f"cv: {format_words(solution['cv'])}")
    print(f"M:  {format_words(solution['message'])}")
    print(f"M': {format_words(solution['message_prime'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reproduce SHA-256 signed-difference SAT/SMT searches.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check-table13-conditions",
        help="Check journal-extension Table 14/15 constraints on the published Table 13 pair.",
    )
    check.set_defaults(func=cmd_check_table13_conditions)

    char = sub.add_parser("char-search", help="Run pure signed-difference characteristic search.")
    char.add_argument("--rounds", type=int, default=12)
    char.add_argument("--shape", choices=("31", "39", "single", "free"), default="free")
    char.add_argument("--single-word", type=int, default=0)
    char.add_argument("--timeout-ms", type=int, default=30_000)
    char.add_argument("--seed", type=int, default=1, help="Base random seed for the solver.")
    char.add_argument("--solver-threads", type=int, default=1, help="Best-effort internal Z3 thread hint.")
    char.add_argument("--op1", type=int, choices=(0, 1), default=1, help="1=fast XOR in SHA2-E, 0=full.")
    char.add_argument("--op2", type=int, choices=(0, 1), default=1, help="1=fast IF in SHA2-E, 0=full.")
    char.add_argument("--op3", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-E, 0=Method-2.")
    char.add_argument("--op4", type=int, choices=(0, 1), default=1, help="1=fast XOR in SHA2-A, 0=full.")
    char.add_argument("--op5", type=int, choices=(0, 1), default=1, help="1=fast MAJ in SHA2-A, 0=full.")
    char.add_argument("--op6", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-A, 0=Method-2.")
    char.add_argument("--op7", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-W, 0=Method-2.")
    char.add_argument("--op8", type=int, choices=(0, 1), default=0, help="1=enable value-transition constraints at every step, 0=disable.")
    char.add_argument(
        "--value-transition-steps",
        type=int,
        nargs="*",
        default=None,
        help="Use value-transition constraints only on the listed steps.",
    )
    char.add_argument(
        "--paper-objective",
        action="store_true",
        help="Lexicographically minimize W, then A, then E Hamming weights as in the paper.",
    )
    char.set_defaults(func=cmd_char_search)

    s41 = sub.add_parser(
        "search-4-1-39",
        help="Run the three-phase 39-step SHA-256 characteristic search from Section 4.1 of the 2024 paper.",
    )
    s41.add_argument("--timeout-ms", type=int, default=600_000)
    s41.add_argument("--seed", type=int, default=1, help="Base random seed for the solver.")
    s41.add_argument("--solver-threads", type=int, default=1, help="Best-effort internal Z3 thread hint per worker.")
    s41.add_argument("--op1", type=int, choices=(0, 1), default=1, help="1=fast XOR in SHA2-E, 0=full.")
    s41.add_argument("--op2", type=int, choices=(0, 1), default=1, help="1=fast IF in SHA2-E, 0=full.")
    s41.add_argument("--op3", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-E, 0=Method-2.")
    s41.add_argument("--op4", type=int, choices=(0, 1), default=1, help="1=fast XOR in SHA2-A, 0=full.")
    s41.add_argument("--op5", type=int, choices=(0, 1), default=1, help="1=fast MAJ in SHA2-A, 0=full.")
    s41.add_argument("--op6", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-A, 0=Method-2.")
    s41.add_argument("--op7", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-W, 0=Method-2.")
    s41.add_argument("--op8", type=int, choices=(0, 1), default=0, help="1=enable value-transition constraints at every step, 0=disable.")
    s41.add_argument(
        "--value-transition-steps",
        type=int,
        nargs="*",
        default=None,
        help="Optionally add value-transition constraints only on these steps.",
    )
    s41.set_defaults(func=cmd_section_4_1_search)

    msgmod = sub.add_parser(
        "msgmod-solve-table13",
        help="Run the journal-extension Table 13 value-transition message-modification search.",
    )
    msgmod.add_argument("--timeout-ms", type=int, default=30_000)
    msgmod.add_argument("--seed", type=int, default=1, help="Base random seed for the solver.")
    msgmod.add_argument("--solver-threads", type=int, default=1, help="Best-effort internal Z3 thread hint per worker.")
    msgmod.set_defaults(func=cmd_msgmod_solve_table13)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except MissingSolverError as exc:
        print(str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
