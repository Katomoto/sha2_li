#!/usr/bin/env python3
"""SAT/SMT search entry points for Li et al.'s reduced SHA-256 attacks."""

from __future__ import annotations

import argparse
import sys

from sha256_reduced.conditions import TABLE14_15_CONDITIONS, failing_conditions
from sha256_reduced.core import digest_blocks, expand_message, format_words
from sha256_reduced.differential import signed_diff_word, trace_collision_second_block
from sha256_reduced.smt_characteristic import Algorithm1Options, CharacteristicSearch
from sha256_reduced.smt_value import Sha256ValueModel
from sha256_reduced.solver import MissingSolverError
from sha256_reduced.vectors import TABLE_13_31_STEP_COLLISION


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
        include_value_transitions=not args.no_value_transitions,
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
    result = search.solve(timeout_ms=args.timeout_ms)
    if result is None:
        print("UNSAT/UNKNOWN: no characteristic found within the configured timeout")
        return 2
    print("SAT: signed differential characteristic")
    for i, word in enumerate(result.w):
        if "u" in word or "n" in word:
            print(f"W{i:02d} {word}")
    return 0


def cmd_msgmod_solve_table13(args: argparse.Namespace) -> int:
    vector = TABLE_13_31_STEP_COLLISION
    cv = digest_blocks(vector.blocks[:1], vector.rounds, iv=vector.iv)
    model = Sha256ValueModel(vector.rounds, prefix="table13")
    model.fix_cv(cv)
    model.require_collision_output()
    model.require_messages_differ()
    model.require_same_words_outside({5, 6, 7, 8, 9})
    model.add_bit_conditions(TABLE14_15_CONDITIONS)

    # Use the published second-block pair as a characteristic template. This
    # keeps the value-transition search tied to the paper's Table 6/Table 14/15
    # lane while still letting Z3 choose the actual message words.
    rows = trace_collision_second_block(vector)
    for row in rows:
        if row.step >= 0 and row.w:
            model.add_signed_pattern("W", row.step, row.w)
        if row.a:
            model.add_signed_pattern("A", row.step, row.a)
        if row.e:
            model.add_signed_pattern("E", row.step, row.e)

    solution = model.solve(timeout_ms=args.timeout_ms)
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
    char.add_argument("--op1", type=int, choices=(0, 1), default=1, help="1=fast XOR in SHA2-E, 0=full.")
    char.add_argument("--op2", type=int, choices=(0, 1), default=1, help="1=fast IF in SHA2-E, 0=full.")
    char.add_argument("--op3", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-E, 0=Method-2.")
    char.add_argument("--op4", type=int, choices=(0, 1), default=1, help="1=fast XOR in SHA2-A, 0=full.")
    char.add_argument("--op5", type=int, choices=(0, 1), default=1, help="1=fast MAJ in SHA2-A, 0=full.")
    char.add_argument("--op6", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-A, 0=Method-2.")
    char.add_argument("--op7", type=int, choices=(0, 1), default=1, help="1=expansion Method-1 in SHA2-W, 0=Method-2.")
    char.add_argument("--op8", type=int, choices=(0, 1), default=1, help="1=build SHA2-W as in Algorithm 1, 0=skip it.")
    char.add_argument(
        "--no-value-transitions",
        action="store_true",
        help="Disable the optional value-transition constraints used alongside full Boolean models.",
    )
    char.add_argument(
        "--paper-objective",
        action="store_true",
        help="Lexicographically minimize W, then A, then E Hamming weights as in the paper.",
    )
    char.set_defaults(func=cmd_char_search)

    msgmod = sub.add_parser(
        "msgmod-solve-table13",
        help="Run the journal-extension Table 13 value-transition message-modification search.",
    )
    msgmod.add_argument("--timeout-ms", type=int, default=30_000)
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
