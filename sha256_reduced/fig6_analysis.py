"""Reproduce and classify the double-bit conditions printed under Fig. 6."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping, Sequence

from .boolean_conditions import possible_output_symbols, profile_for_pattern
from .conditions import BitCondition, BitRef
from .core import SHA256_IV, compress, expand_message
from .fig6 import (
    FIG6_CONDITIONS,
    FIG6_HASH,
    FIG6_M0,
    FIG6_MESSAGE,
    FIG6_MESSAGE_PRIME,
    FIG6_PATTERNS,
    FIG6_ROUNDS,
)
from .smt_value import Sha256ValueModel
from .solver import MissingSolverError, bit, configure_solver_instance, require_z3

ConditionKey = tuple[tuple[str, int, int], str, tuple[str, int, int]]


@dataclass(frozen=True)
class Fig6Witness:
    cv: tuple[int, ...]
    left: Mapping[tuple[str, int], int]
    right: Mapping[tuple[str, int], int]
    collision_hash: tuple[int, ...]


@dataclass(frozen=True)
class Fig6ConditionResult:
    condition: BitCondition
    source: str
    detail: str
    full_model_status: str
    witness_holds: bool


@dataclass(frozen=True)
class Fig6AnalysisReport:
    witness_matches_characteristic: bool
    witness_is_collision: bool
    conditions: tuple[Fig6ConditionResult, ...]
    full_model_satisfiable: str

    def count(self, source: str) -> int:
        return sum(result.source == source for result in self.conditions)


@dataclass(frozen=True)
class ComponentTransition:
    """One bit-level component transition derived only from Fig. 6 symbols."""

    source: str
    function: str
    bit: int
    input_refs: tuple[BitRef | None, ...]
    input_pattern: str
    output_symbols: tuple[str, ...]

    @property
    def patterns(self) -> tuple[str, ...]:
        return tuple(self.input_pattern + output for output in self.output_symbols)


@dataclass(frozen=True)
class ComponentConditionBranch:
    """Table conditions associated with one possible component output symbol."""

    transition: ComponentTransition
    output_symbol: str
    conditions: tuple[BitCondition, ...]

    @property
    def pattern(self) -> str:
        return self.transition.input_pattern + self.output_symbol


def _ref_key(reference: BitRef) -> tuple[str, int, int]:
    return reference.kind, reference.index, reference.bit


def condition_key(condition: BitCondition) -> ConditionKey:
    left = _ref_key(condition.left)
    right = _ref_key(condition.right)
    if right < left:
        left, right = right, left
    return left, condition.op, right


def _pattern_symbol(kind: str, index: int, bit_index: int) -> str:
    return FIG6_PATTERNS[(kind, index)][31 - bit_index]


def _left_value_from_symbol(symbol: str) -> int | None:
    if symbol in ("n", "0"):
        return 0
    if symbol in ("u", "1"):
        return 1
    return None


def _condition_from_symbols(condition: BitCondition) -> bool:
    left = _left_value_from_symbol(_pattern_symbol(*_ref_key(condition.left)))
    right = _left_value_from_symbol(_pattern_symbol(*_ref_key(condition.right)))
    if left is None or right is None:
        return False
    return (left == right) if condition.op == "==" else (left != right)


def _condition_holds(mapping: Mapping[tuple[str, int], int], condition: BitCondition) -> bool:
    left_word = mapping[(condition.left.kind, condition.left.index)]
    right_word = mapping[(condition.right.kind, condition.right.index)]
    left_bit = (left_word >> condition.left.bit) & 1
    right_bit = (right_word >> condition.right.bit) & 1
    return (left_bit == right_bit) if condition.op == "==" else (left_bit != right_bit)


def fig6_witness() -> Fig6Witness:
    cv = compress(SHA256_IV, FIG6_M0, FIG6_ROUNDS)
    _, left_trace = compress(cv, FIG6_MESSAGE_PRIME, FIG6_ROUNDS, feed_forward=False, trace=True)
    _, right_trace = compress(cv, FIG6_MESSAGE, FIG6_ROUNDS, feed_forward=False, trace=True)
    left_w = expand_message(FIG6_MESSAGE_PRIME, FIG6_ROUNDS)
    right_w = expand_message(FIG6_MESSAGE, FIG6_ROUNDS)

    left: dict[tuple[str, int], int] = {
        ("A", -1): cv[0],
        ("A", -2): cv[1],
        ("A", -3): cv[2],
        ("A", -4): cv[3],
        ("E", -1): cv[4],
        ("E", -2): cv[5],
        ("E", -3): cv[6],
        ("E", -4): cv[7],
    }
    right = dict(left)
    for i, (left_state, right_state) in enumerate(zip(left_trace, right_trace)):
        left[("A", i)] = left_state.a
        left[("E", i)] = left_state.e
        right[("A", i)] = right_state.a
        right[("E", i)] = right_state.e
    for i, (left_word, right_word) in enumerate(zip(left_w, right_w)):
        left[("W", i)] = left_word
        right[("W", i)] = right_word

    left_hash = compress(cv, FIG6_MESSAGE_PRIME, FIG6_ROUNDS)
    right_hash = compress(cv, FIG6_MESSAGE, FIG6_ROUNDS)
    if left_hash != right_hash:
        raise AssertionError("Table 3 messages do not collide in the local SHA-256 implementation")
    return Fig6Witness(tuple(cv), left, right, tuple(left_hash))


def _word_matches_pattern(left: int, right: int, pattern: str) -> bool:
    for offset, symbol in enumerate(pattern):
        bit_index = 31 - offset
        left_bit = (left >> bit_index) & 1
        right_bit = (right >> bit_index) & 1
        if symbol == "=" and left_bit != right_bit:
            return False
        if symbol == "0" and (left_bit, right_bit) != (0, 0):
            return False
        if symbol == "1" and (left_bit, right_bit) != (1, 1):
            return False
        if symbol == "n" and (left_bit, right_bit) != (0, 1):
            return False
        if symbol == "u" and (left_bit, right_bit) != (1, 0):
            return False
    return True


def witness_matches_characteristic(witness: Fig6Witness | None = None) -> bool:
    witness = witness or fig6_witness()
    return all(
        _word_matches_pattern(witness.left[key], witness.right[key], pattern)#真实消息对产生的真实值，差分特征
        for key, pattern in FIG6_PATTERNS.items()
    )


def _instantiate_profile_conditions(
    function: str,
    pattern: str,
    bindings: Mapping[str, BitRef | None],
) -> tuple[BitCondition, ...]:
    profile = profile_for_pattern(function, pattern)
    if not profile.satisfiable:
        raise AssertionError(f"symbolic propagation generated impossible transition {function}:{pattern}")
    conditions: list[BitCondition] = []
    for local in profile.pair_conditions:
        left = bindings.get(local.left)
        right = bindings.get(local.right)
        if left is None or right is None:
            continue
        conditions.append(BitCondition(left, local.op, right))
    return tuple(conditions)


def _make_component_transition(
    source: str,
    function: str,
    bit: int,
    input_refs: tuple[BitRef | None, ...],
    input_pattern: str,
) -> ComponentTransition:
    return ComponentTransition(
        source=source,
        function=function,
        bit=bit,
        input_refs=input_refs,
        input_pattern=input_pattern,
        output_symbols=possible_output_symbols(function, input_pattern),
    )


@lru_cache(maxsize=1)
def symbolic_component_transitions() -> tuple[ComponentTransition, ...]:
    """Build all SHA-256 component transitions from the Fig. 6 characteristic.

    No concrete state, message, or collision witness is read here.  For each
    component bit, the function enumerates the output symbols compatible with
    the three input symbols.  Multiple output symbols are intentional: ``=``
    does not reveal the common bit value, so a Boolean component can have two
    possible signed output directions.
    """

    transitions: list[ComponentTransition] = []

    for round_index in range(FIG6_ROUNDS):
        for name, kind, function in (("IF", "E", "if"), ("MAJ", "A", "maj")):
            for bit_index in range(32):
                refs = tuple(
                    BitRef(kind, round_index - offset, bit_index) for offset in (1, 2, 3)
                )
                pattern = "".join(
                    _pattern_symbol(reference.kind, reference.index, reference.bit)
                    for reference in refs
                )
                transitions.append(
                    _make_component_transition(
                        f"{name}@{round_index}[{bit_index}]",
                        function,
                        bit_index,
                        refs,
                        pattern,
                    )
                )

    for index in range(-1, FIG6_ROUNDS - 1):
        for name, kind, rotations in (
            ("Sigma0", "A", (2, 13, 22)),
            ("Sigma1", "E", (6, 11, 25)),
        ):
            for bit_index in range(32):
                source_bits = tuple((bit_index + rotation) % 32 for rotation in rotations)
                refs = tuple(BitRef(kind, index, source_bit) for source_bit in source_bits)
                pattern = "".join(
                    _pattern_symbol(kind, index, source_bit) for source_bit in source_bits
                )
                transitions.append(
                    _make_component_transition(
                        f"{name}({kind}{index})[{bit_index}]",
                        "xor3",
                        bit_index,
                        refs,
                        pattern,
                    )
                )

    for index in range(1, 20):
        for bit_index in range(32):
            source_bits: tuple[int | None, ...] = (
                (bit_index + 7) % 32,
                (bit_index + 18) % 32,
                bit_index + 3 if bit_index + 3 < 32 else None,
            )
            refs = tuple(
                BitRef("W", index, source_bit) if source_bit is not None else None
                for source_bit in source_bits
            )
            pattern = "".join(
                "0"
                if source_bit is None
                else _pattern_symbol("W", index, source_bit)
                for source_bit in source_bits
            )
            transitions.append(
                _make_component_transition(
                    f"sigma0(W{index})[{bit_index}]",
                    "xor3",
                    bit_index,
                    refs,
                    pattern,
                )
            )

    for index in range(14, 33):
        for bit_index in range(32):
            source_bits = (
                (bit_index + 17) % 32,
                (bit_index + 19) % 32,
                bit_index + 10 if bit_index + 10 < 32 else None,
            )
            refs = tuple(
                BitRef("W", index, source_bit) if source_bit is not None else None
                for source_bit in source_bits
            )
            pattern = "".join(
                "0"
                if source_bit is None
                else _pattern_symbol("W", index, source_bit)
                for source_bit in source_bits
            )
            transitions.append(
                _make_component_transition(
                    f"sigma1(W{index})[{bit_index}]",
                    "xor3",
                    bit_index,
                    refs,
                    pattern,
                )
            )

    return tuple(transitions)


def symbolic_boolean_sources() -> Mapping[ConditionKey, tuple[str, ...]]:
    """Return candidate conditions from every symbolic component branch.

    A source is recorded for each possible output symbol.  Therefore a
    condition in this mapping is branch-qualified evidence, not automatically
    an unconditional condition.  The source text includes the local pattern
    so callers can preserve the branch when translating it to an SMT model.
    """

    sources: dict[ConditionKey, set[str]] = defaultdict(set)

    for branch in symbolic_condition_branches():
        for condition in branch.conditions:
            sources[condition_key(condition)].add(f"{branch.transition.source}: {branch.pattern}")

    return {key: tuple(sorted(value)) for key, value in sources.items()}


@lru_cache(maxsize=1)
def symbolic_condition_branches() -> tuple[ComponentConditionBranch, ...]:
    """Return table-derived conditions grouped by component output branch."""

    branches: list[ComponentConditionBranch] = []
    for transition in symbolic_component_transitions():
        bindings = {
            local: reference
            for local, reference in zip(("x", "y", "z"), transition.input_refs)
        }
        for output_symbol in transition.output_symbols:
            pattern = transition.input_pattern + output_symbol
            branches.append(
                ComponentConditionBranch(
                    transition=transition,
                    output_symbol=output_symbol,
                    conditions=_instantiate_profile_conditions(
                        transition.function,
                        pattern,
                        bindings,
                    ),
                )
            )
    return tuple(branches)


def branches_for_condition(condition: BitCondition) -> tuple[ComponentConditionBranch, ...]:
    """Find the symbolic component branches that produce one condition."""

    key = condition_key(condition)
    return tuple(
        branch
        for branch in symbolic_condition_branches()
        if any(condition_key(candidate) == key for candidate in branch.conditions)
    )


def add_component_condition_branch(model: Sha256ValueModel, branch: ComponentConditionBranch) -> None:
    """Add one output-symbol/table branch to a value-transition model."""

    transition = branch.transition
    model.add_component_signed_symbol(
        transition.function,
        transition.input_refs,
        transition.bit,
        branch.output_symbol,
    )
    model.add_bit_conditions(branch.conditions)


def direct_boolean_sources() -> Mapping[ConditionKey, tuple[str, ...]]:
    """Backward-compatible name for the pure symbolic Boolean extraction."""

    return symbolic_boolean_sources()


def _add_characteristic(model: Sha256ValueModel) -> None:
    for (kind, index), pattern in FIG6_PATTERNS.items():
        model.add_signed_pattern(kind, index, pattern)


def _condition_expression(model: Sha256ValueModel, condition: BitCondition):
    left_word = model._word_pair(condition.left.kind, condition.left.index)[0]
    right_word = model._word_pair(condition.right.kind, condition.right.index)[0]
    left_bit = bit(left_word, condition.left.bit)
    right_bit = bit(right_word, condition.right.bit)
    return left_bit == right_bit if condition.op == "==" else left_bit != right_bit


def full_model_implications(
    conditions: Sequence[BitCondition] = FIG6_CONDITIONS,
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> tuple[str, tuple[str, ...]]:
    z3 = require_z3()
    model = Sha256ValueModel(FIG6_ROUNDS, prefix="fig6_check")
    _add_characteristic(model)
    configure_solver_instance(model.solver, timeout_ms=timeout_ms, threads=solver_threads)
    satisfiable = str(model.solver.check())
    if satisfiable != "sat":
        return satisfiable, tuple("not-checked" for _ in conditions)

    statuses: list[str] = []
    for condition in conditions:
        model.solver.push()
        model.solver.add(z3.Not(_condition_expression(model, condition)))
        result = model.solver.check()
        model.solver.pop()
        if result == z3.unsat:
            statuses.append("implied")
        elif result == z3.sat:
            statuses.append("not-implied")
        else:
            statuses.append("unknown")
    return satisfiable, tuple(statuses)


def analyze_fig6(
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
    run_full_model: bool = True,
) -> Fig6AnalysisReport:
    witness = fig6_witness()
    boolean_sources = symbolic_boolean_sources()
    if run_full_model:
        try:
            full_satisfiable, full_statuses = full_model_implications(
                timeout_ms=timeout_ms,
                solver_threads=solver_threads,
            )
        except MissingSolverError:
            full_satisfiable = "unavailable"
            full_statuses = tuple("not-checked" for _ in FIG6_CONDITIONS)
    else:
        full_satisfiable = "skipped"
        full_statuses = tuple("not-checked" for _ in FIG6_CONDITIONS)
    results: list[Fig6ConditionResult] = []
    for condition, full_status in zip(FIG6_CONDITIONS, full_statuses):
        key = condition_key(condition)
        witness_holds = _condition_holds(witness.left, condition)
        if _condition_from_symbols(condition):
            source = "symbols"
            detail = "fixed by n/u/0/1 symbols"
        elif key in boolean_sources:
            source = "boolean"
            detail = "branch-qualified table evidence: " + ", ".join(boolean_sources[key])
        elif full_status == "implied":
            source = "mod-add"
            detail = "requires the complete SHA-256 equations, including modular-addition carries"
        else:
            source = "missing"
            detail = "not recovered from the local Boolean tables or the tested full model"
            if not witness_holds:
                detail += "; Table 3 is only an independent validation witness and contradicts it"
        results.append(Fig6ConditionResult(condition, source, detail, full_status, witness_holds))

    return Fig6AnalysisReport(
        witness_matches_characteristic=witness_matches_characteristic(witness),
        witness_is_collision=witness.collision_hash == FIG6_HASH,
        conditions=tuple(results),
        full_model_satisfiable=full_satisfiable,
    )
