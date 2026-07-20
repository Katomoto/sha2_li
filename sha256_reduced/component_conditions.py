"""Double-bit lookup tables for SHA-256 Sigma functions and modular addition."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations, product
from typing import Mapping

from .boolean_conditions import (
    GENERALIZED_SYMBOLS,
    SYMBOLS,
    SYMBOL_PAIRS,
    BooleanConditionProfile,
    LocalBitCondition,
    LocalBitValue,
    possible_output_symbols,
    profile_for_pattern,
)
from .conditions import BitCondition, BitRef

WORD_BITS = 32
ADDITION_VARIABLES = ("x", "y", "carry_in", "sum", "carry_out")


@dataclass(frozen=True)
class SigmaSpec:
    name: str
    rotations: tuple[int, int]
    third_rotation: int | None = None
    shift: int | None = None

    def input_bits(self, output_bit: int) -> tuple[int | None, int | None, int | None]:
        if not 0 <= output_bit < WORD_BITS:
            raise ValueError(f"output bit must be between 0 and {WORD_BITS - 1}")
        first = (output_bit + self.rotations[0]) % WORD_BITS
        second = (output_bit + self.rotations[1]) % WORD_BITS
        if self.third_rotation is not None:
            third = (output_bit + self.third_rotation) % WORD_BITS
        elif self.shift is not None:
            source = output_bit + self.shift
            third = source if source < WORD_BITS else None
        else:
            raise AssertionError(f"invalid Sigma specification: {self.name}")
        return first, second, third


SIGMA_SPECS: Mapping[str, SigmaSpec] = {
    "Sigma0": SigmaSpec("Sigma0", (2, 13), third_rotation=22),
    "Sigma1": SigmaSpec("Sigma1", (6, 11), third_rotation=25),
    "sigma0": SigmaSpec("sigma0", (7, 18), shift=3),
    "sigma1": SigmaSpec("sigma1", (17, 19), shift=10),
}


def sigma_spec(name: str) -> SigmaSpec:
    try:
        return SIGMA_SPECS[name]
    except KeyError as exc:
        raise ValueError(f"unknown SHA-256 Sigma component: {name!r}") from exc


@dataclass(frozen=True)
class SigmaBitConditionProfile:
    component: str
    output_bit: int
    input_bits: tuple[int | None, int | None, int | None]
    boolean_profile: BooleanConditionProfile

    @property
    def pattern(self) -> str:
        return self.boolean_profile.pattern

    @property
    def pair_conditions(self) -> tuple[LocalBitCondition, ...]:
        return self.boolean_profile.pair_conditions

    def instantiate_input_conditions(self, kind: str, index: int) -> tuple[BitCondition, ...]:
        bindings = {
            local: BitRef(kind, index, bit_index) if bit_index is not None else None
            for local, bit_index in zip(("x", "y", "z"), self.input_bits)
        }
        conditions: list[BitCondition] = []
        for local in self.pair_conditions:
            left = bindings.get(local.left)
            right = bindings.get(local.right)
            if left is None or right is None:
                continue
            conditions.append(BitCondition(left, local.op, right))
        return tuple(conditions)


def sigma_input_pattern(component: str, word_pattern: str, output_bit: int) -> str:
    if len(word_pattern) != WORD_BITS:
        raise ValueError(f"Sigma input words must contain {WORD_BITS} symbols")
    symbols: list[str] = []
    for bit_index in sigma_spec(component).input_bits(output_bit):
        symbols.append("0" if bit_index is None else word_pattern[WORD_BITS - 1 - bit_index])
    return "".join(symbols)


def possible_sigma_output_symbols(component: str, word_pattern: str, output_bit: int) -> tuple[str, ...]:
    return possible_output_symbols("xor3", sigma_input_pattern(component, word_pattern, output_bit))


@lru_cache(maxsize=None)
def profile_for_sigma_pattern(
    component: str,
    output_bit: int,
    input_pattern: str,
    output_symbol: str,
) -> SigmaBitConditionProfile:
    spec = sigma_spec(component)
    if len(input_pattern) != 3:
        raise ValueError("Sigma input patterns must contain exactly 3 symbols")
    return SigmaBitConditionProfile(
        component=component,
        output_bit=output_bit,
        input_bits=spec.input_bits(output_bit),
        boolean_profile=profile_for_pattern("xor3", input_pattern + output_symbol),
    )


def profile_for_sigma_word(
    component: str,
    word_pattern: str,
    output_bit: int,
    output_symbol: str,
) -> SigmaBitConditionProfile:
    return profile_for_sigma_pattern(
        component,
        output_bit,
        sigma_input_pattern(component, word_pattern, output_bit),
        output_symbol,
    )


@dataclass(frozen=True)
class AdditionConditionProfile:
    x_symbol: str
    y_symbol: str
    carry_in_symbol: str
    sum_symbol: str
    carry_out_symbol: str
    assignments: tuple[tuple[int, int, int, int, int], ...]
    pair_conditions: tuple[LocalBitCondition, ...]
    fixed_values: tuple[LocalBitValue, ...]

    @property
    def pattern(self) -> str:
        return (
            self.x_symbol
            + self.y_symbol
            + self.carry_in_symbol
            + self.sum_symbol
            + self.carry_out_symbol
        )

    @property
    def satisfiable(self) -> bool:
        return bool(self.assignments)


def _validate_addition_pattern(pattern: str) -> str:
    if len(pattern) != 5:
        raise ValueError("full-adder patterns must contain exactly 5 symbols")
    if any(symbol not in GENERALIZED_SYMBOLS for symbol in pattern):
        raise ValueError("full-adder patterns must use only '=', 'n', 'u', '0', and '1'")
    return pattern


def _pair_matches_symbol(pair: tuple[int, int], symbol: str) -> bool:
    return pair in SYMBOL_PAIRS[symbol]


def _enumerate_addition_assignments(pattern: str) -> tuple[tuple[int, int, int, int, int], ...]:
    x_symbol, y_symbol, carry_in_symbol, sum_symbol, carry_out_symbol = pattern
    assignments: list[tuple[int, int, int, int, int]] = []
    for x_pair, y_pair, carry_pair in product(
        SYMBOL_PAIRS[x_symbol],
        SYMBOL_PAIRS[y_symbol],
        SYMBOL_PAIRS[carry_in_symbol],
    ):
        left_total = x_pair[0] + y_pair[0] + carry_pair[0]
        right_total = x_pair[1] + y_pair[1] + carry_pair[1]
        sum_pair = (left_total & 1, right_total & 1)
        carry_out_pair = (left_total >> 1, right_total >> 1)
        if not _pair_matches_symbol(sum_pair, sum_symbol):
            continue
        if not _pair_matches_symbol(carry_out_pair, carry_out_symbol):
            continue
        assignments.append(
            (x_pair[0], y_pair[0], carry_pair[0], sum_pair[0], carry_out_pair[0])
        )
    return tuple(sorted(set(assignments)))


def _infer_pair_conditions(
    assignments: tuple[tuple[int, ...], ...],
    variables: tuple[str, ...],
) -> tuple[LocalBitCondition, ...]:
    if not assignments:
        return ()
    conditions: list[LocalBitCondition] = []
    for left_index, right_index in combinations(range(len(variables)), 2):
        relations = {row[left_index] == row[right_index] for row in assignments}
        if relations == {True}:
            conditions.append(LocalBitCondition(variables[left_index], "==", variables[right_index]))
        elif relations == {False}:
            conditions.append(LocalBitCondition(variables[left_index], "!=", variables[right_index]))
    return tuple(conditions)


def _infer_fixed_values(
    assignments: tuple[tuple[int, ...], ...],
    variables: tuple[str, ...],
) -> tuple[LocalBitValue, ...]:
    if not assignments:
        return ()
    values: list[LocalBitValue] = []
    for index, variable in enumerate(variables):
        column = {row[index] for row in assignments}
        if len(column) == 1:
            values.append(LocalBitValue(variable, next(iter(column))))
    return tuple(values)


@lru_cache(maxsize=None)
def profile_for_addition_pattern(pattern: str) -> AdditionConditionProfile:
    normalized = _validate_addition_pattern(pattern)
    assignments = _enumerate_addition_assignments(normalized)
    return AdditionConditionProfile(
        x_symbol=normalized[0],
        y_symbol=normalized[1],
        carry_in_symbol=normalized[2],
        sum_symbol=normalized[3],
        carry_out_symbol=normalized[4],
        assignments=assignments,
        pair_conditions=_infer_pair_conditions(assignments, ADDITION_VARIABLES),
        fixed_values=_infer_fixed_values(assignments, ADDITION_VARIABLES),
    )


@lru_cache(maxsize=1)
def enumerate_addition_profiles() -> tuple[AdditionConditionProfile, ...]:
    return tuple(
        profile_for_addition_pattern("".join(pattern))
        for pattern in product(SYMBOLS, repeat=5)
    )


@lru_cache(maxsize=1)
def enumerate_generalized_addition_profiles() -> tuple[AdditionConditionProfile, ...]:
    return tuple(
        profile_for_addition_pattern("".join(pattern))
        for pattern in product(GENERALIZED_SYMBOLS, repeat=5)
    )


def satisfiable_addition_patterns() -> tuple[str, ...]:
    return tuple(profile.pattern for profile in enumerate_addition_profiles() if profile.satisfiable)


@lru_cache(maxsize=None)
def matching_addition_profiles(partial_pattern: str) -> tuple[AdditionConditionProfile, ...]:
    """Return legal full-adder rows matching a pattern with ``?`` wildcards."""

    if len(partial_pattern) != 5:
        raise ValueError("partial full-adder patterns must contain exactly 5 symbols")
    if any(symbol != "?" and symbol not in GENERALIZED_SYMBOLS for symbol in partial_pattern):
        raise ValueError("partial patterns may use '?', '=', 'n', 'u', '0', and '1'")
    choices = tuple(SYMBOLS if symbol == "?" else (symbol,) for symbol in partial_pattern)
    return tuple(
        profile
        for symbols in product(*choices)
        if (profile := profile_for_addition_pattern("".join(symbols))).satisfiable
    )


def common_addition_pair_conditions(partial_pattern: str) -> tuple[LocalBitCondition, ...]:
    profiles = matching_addition_profiles(partial_pattern)
    if not profiles:
        return ()
    common = set(profiles[0].pair_conditions)
    for profile in profiles[1:]:
        common.intersection_update(profile.pair_conditions)
    return tuple(
        condition
        for condition in profiles[0].pair_conditions
        if condition in common
    )
