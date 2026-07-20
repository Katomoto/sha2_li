"""Reproduce and classify the double-bit conditions printed under Fig. 6."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping, Sequence

from .boolean_conditions import possible_output_symbols, profile_for_pattern
from .component_conditions import SIGMA_SPECS, profile_for_sigma_pattern
from .conditions import BitCondition, BitRef
from .equation_resolver import Sha256EquationResolver
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
    component: str
    function: str
    equation_kind: str
    equation_index: int
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


@dataclass(frozen=True)
class ComponentResolution:
    transition: ComponentTransition
    equation_status: str
    output_symbols: tuple[str, ...]


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


def _instantiate_transition_conditions(
    transition: ComponentTransition,
    output_symbol: str,
) -> tuple[BitCondition, ...]:
    if transition.component in SIGMA_SPECS:
        profile = profile_for_sigma_pattern(
            transition.component,
            transition.bit,
            transition.input_pattern,
            output_symbol,
        )
        reference = next((item for item in transition.input_refs if item is not None), None)
        if reference is None:
            return ()
        return profile.instantiate_input_conditions(reference.kind, reference.index)
    bindings = {
        local: reference
        for local, reference in zip(("x", "y", "z"), transition.input_refs)
    }
    return _instantiate_profile_conditions(
        transition.function,
        transition.input_pattern + output_symbol,
        bindings,
    )


def _make_component_transition(
    source: str,
    component: str,
    function: str,
    equation_kind: str,
    equation_index: int,
    bit: int,
    input_refs: tuple[BitRef | None, ...],
    input_pattern: str,
) -> ComponentTransition:
    return ComponentTransition(
        source=source,
        component=component,
        function=function,
        equation_kind=equation_kind,
        equation_index=equation_index,
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
                        name,
                        function,
                        "E" if name == "IF" else "A",
                        round_index,
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
                        name,
                        "xor3",
                        "A" if name == "Sigma0" else "E",
                        index + 1,
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
                    "sigma0",
                    "xor3",
                    "W",
                    index + 15,
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
                    "sigma1",
                    "xor3",
                    "W",
                    index + 2,
                    bit_index,
                    refs,
                    pattern,
                )
            )

    return tuple(transitions)


@lru_cache(maxsize=1)
def local_condition_branches() -> tuple[ComponentConditionBranch, ...]:
    """Return every locally legal table branch before update-equation filtering."""

    branches: list[ComponentConditionBranch] = []
    for transition in symbolic_component_transitions():
        for output_symbol in transition.output_symbols:
            branches.append(
                ComponentConditionBranch(
                    transition=transition,
                    output_symbol=output_symbol,
                    conditions=_instantiate_transition_conditions(transition, output_symbol),
                )
            )
    return tuple(branches)


@lru_cache(maxsize=None)
def resolved_component_resolutions(
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> tuple[ComponentResolution, ...]:
    """Resolve component outputs through their complete W/E/A equations."""

    resolver = Sha256EquationResolver(
        FIG6_PATTERNS,
        FIG6_ROUNDS,
        timeout_ms=timeout_ms,
        solver_threads=solver_threads,
        prefix="fig6_resolve",
    )
    resolutions: list[ComponentResolution] = []
    for transition in symbolic_component_transitions():
        if not any(
            _instantiate_transition_conditions(transition, output)
            for output in transition.output_symbols
        ):
            continue
        status, outputs = resolver.resolve_component(
            transition.equation_kind,
            transition.equation_index,
            transition.component,
            transition.bit,
            transition.output_symbols,
        )
        resolutions.append(ComponentResolution(transition, status, outputs))
    return tuple(resolutions)


@lru_cache(maxsize=None)
def symbolic_condition_branches(
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> tuple[ComponentConditionBranch, ...]:
    """Return only component branches allowed by complete update equations."""

    branches: list[ComponentConditionBranch] = []
    for resolution in resolved_component_resolutions(timeout_ms, solver_threads):
        transition = resolution.transition
        local_conditions = {
            output: _instantiate_transition_conditions(transition, output)
            for output in transition.output_symbols
        }
        if not any(local_conditions.values()):
            continue
        for output_symbol in resolution.output_symbols:
            branches.append(
                ComponentConditionBranch(
                    transition=transition,
                    output_symbol=output_symbol,
                    conditions=local_conditions[output_symbol],
                )
            )
    return tuple(branches)


def equation_resolved_component_sources(
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> Mapping[ConditionKey, tuple[str, ...]]:
    """Return conditions common to every equation-compatible output branch."""

    grouped: dict[str, list[ComponentConditionBranch]] = defaultdict(list)
    for branch in symbolic_condition_branches(timeout_ms, solver_threads):
        grouped[branch.transition.source].append(branch)

    sources: dict[ConditionKey, set[str]] = defaultdict(set)
    for branches in grouped.values():
        condition_maps = [
            {condition_key(condition): condition for condition in branch.conditions}
            for branch in branches
        ]
        if not condition_maps:
            continue
        common = set(condition_maps[0])
        for condition_map in condition_maps[1:]:
            common.intersection_update(condition_map)
        outputs = ",".join(branch.output_symbol for branch in branches)
        transition = branches[0].transition
        for key in common:
            patterns = ",".join(
                branch.pattern for branch in branches if key in {condition_key(c) for c in branch.conditions}
            )
            sources[key].add(
                f"{transition.source} via {transition.equation_kind}{transition.equation_index}: "
                f"outputs={outputs}, tables={patterns}"
            )

    return {key: tuple(sorted(value)) for key, value in sources.items()}


def symbolic_boolean_sources(
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> Mapping[ConditionKey, tuple[str, ...]]:
    """Backward-compatible alias for equation-resolved component extraction."""

    return equation_resolved_component_sources(
        timeout_ms=timeout_ms,
        solver_threads=solver_threads,
    )


@lru_cache(maxsize=1)
def modular_addition_sources() -> Mapping[ConditionKey, tuple[str, ...]]:
    """Extract direct word-bit conditions from all full-adder lookup stages."""

    resolver = Sha256EquationResolver(
        FIG6_PATTERNS,
        FIG6_ROUNDS,
        timeout_ms=None,
        prefix="fig6_add_table",
    )
    sources: dict[ConditionKey, set[str]] = defaultdict(set)
    equation_keys = (
        *(("W", index) for index in range(16, FIG6_ROUNDS)),
        *(("E", index) for index in range(FIG6_ROUNDS)),
        *(("A", index) for index in range(FIG6_ROUNDS)),
    )
    for kind, index in equation_keys:
        equation = resolver.equation(kind, index)
        for stage in equation.additions:
            for bit_index in range(32):
                for condition in equation.table_addition_conditions(
                    stage.name,
                    bit_index,
                    FIG6_PATTERNS,
                ):
                    sources[condition_key(condition)].add(
                        f"{equation.name}.{stage.name}[{bit_index}]"
                    )
    return {key: tuple(sorted(value)) for key, value in sources.items()}


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


def validate_condition_implications(
    conditions: Sequence[BitCondition] = FIG6_CONDITIONS,
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Validate already supplied conditions; this function does not extract them."""

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


def full_model_implications(
    conditions: Sequence[BitCondition] = FIG6_CONDITIONS,
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Backward-compatible alias for condition validation only."""

    return validate_condition_implications(
        conditions,
        timeout_ms=timeout_ms,
        solver_threads=solver_threads,
    )


def analyze_fig6(
    *,
    timeout_ms: int | None = 10_000,
    solver_threads: int | None = None,
    run_full_model: bool = True,
) -> Fig6AnalysisReport:
    witness = fig6_witness()
    component_sources = equation_resolved_component_sources()
    addition_sources = modular_addition_sources()
    if run_full_model:
        try:
            full_satisfiable, full_statuses = validate_condition_implications(
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
        elif key in component_sources:
            source = "component"
            detail = "forced by complete update equation and component table: " + ", ".join(component_sources[key])
        elif key in addition_sources:
            source = "mod-add"
            detail = "extracted from equation-bound full-adder table: " + ", ".join(addition_sources[key])
        else:
            source = "missing"
            detail = "not extracted from the equation-resolved component or modular-addition tables"
            if full_status == "implied":
                detail += "; separately validated as implied by the whole value model"
            if not witness_holds:
                detail += "; Table 3 is only an independent validation witness and contradicts it"
        results.append(Fig6ConditionResult(condition, source, detail, full_status, witness_holds))

    return Fig6AnalysisReport(
        witness_matches_characteristic=witness_matches_characteristic(witness),
        witness_is_collision=witness.collision_hash == FIG6_HASH,
        conditions=tuple(results),
        full_model_satisfiable=full_satisfiable,
    )
