"""Enumerate double-bit conditions implied by SHA-2 Boolean signed differences."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations, product
from typing import Callable, Mapping

from .conditions import BitCondition, BitRef

SYMBOLS = ("=", "n", "u")
GENERALIZED_SYMBOLS = ("=", "n", "u", "0", "1")
SYMBOL_PAIRS = {
    "=": ((0, 0), (1, 1)),
    "n": ((0, 1),),
    "u": ((1, 0),),
    "0": ((0, 0),),
    "1": ((1, 1),),
}
BOOLEAN_FUNCTION_NAMES = ("if", "maj", "xor3")
BOOLEAN_FUNCTION_ALIASES = {
    "ch": "if",
    "choose": "if",
    "xor": "xor3",
}
LOCAL_VARIABLES = ("x", "y", "z", "out")


def _normalize_function_name(name: str) -> str:
    normalized = BOOLEAN_FUNCTION_ALIASES.get(name.lower(), name.lower())
    if normalized not in BOOLEAN_FUNCTION_NAMES:
        raise ValueError(f"unknown SHA-2 Boolean function: {name!r}")
    return normalized


def _symbol(left: int, right: int) -> str:
    if left == right:
        return "="
    return "u" if left == 1 else "n"


def _apply_symbol(left: int, symbol: str) -> int | None:
    if symbol == "=":
        return left
    if symbol == "n":
        return 1 if left == 0 else None
    if symbol == "u":
        return 0 if left == 1 else None
    if symbol == "0":
        return 0 if left == 0 else None
    if symbol == "1":
        return 1 if left == 1 else None
    raise ValueError(f"unsupported signed-difference symbol: {symbol!r}")


def _boolean_function(name: str) -> Callable[[int, int, int], int]:
    normalized = _normalize_function_name(name)
    if normalized == "xor3":
        return lambda x, y, z: x ^ y ^ z
    if normalized == "if":
        return lambda x, y, z: (x & y) ^ ((1 ^ x) & z)
    if normalized == "maj":
        return lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)
    raise AssertionError(f"unsupported Boolean function after normalization: {normalized}")


@dataclass(frozen=True)
class LocalBitCondition:
    left: str
    op: str
    right: str

    def bind(self, mapping: Mapping[str, BitRef]) -> BitCondition:
        try:
            left = mapping[self.left]
            right = mapping[self.right]
        except KeyError as exc:
            raise ValueError(f"missing binding for local variable {exc.args[0]!r}") from exc
        return BitCondition(left, self.op, right)

    def __str__(self) -> str:
        return f"{self.left} {self.op} {self.right}"


@dataclass(frozen=True)
class LocalBitValue:
    name: str
    value: int

    def __str__(self) -> str:
        return f"{self.name}={self.value}"


@dataclass(frozen=True)
class BooleanConditionProfile:
    function: str
    x_symbol: str
    y_symbol: str
    z_symbol: str
    out_symbol: str
    assignments: tuple[tuple[int, int, int, int], ...]
    pair_conditions: tuple[LocalBitCondition, ...]
    fixed_values: tuple[LocalBitValue, ...]

    @property
    def pattern(self) -> str:
        return f"{self.x_symbol}{self.y_symbol}{self.z_symbol}{self.out_symbol}"

    @property
    def satisfiable(self) -> bool:
        return bool(self.assignments)

    @property
    def num_assignments(self) -> int:
        return len(self.assignments)

    def instantiate_pair_conditions(self, mapping: Mapping[str, BitRef]) -> tuple[BitCondition, ...]:
        return tuple(condition.bind(mapping) for condition in self.pair_conditions)


def _validate_pattern(pattern: str) -> str:
    if len(pattern) != 4:
        raise ValueError("signed-difference patterns must contain exactly 4 symbols")
    if any(symbol not in GENERALIZED_SYMBOLS for symbol in pattern):
        raise ValueError("signed-difference patterns must use only '=', 'n', 'u', '0', and '1'")
    return pattern


def _validate_input_symbols(input_symbols: str) -> str:
    if len(input_symbols) != 3:
        raise ValueError("Boolean-function input patterns must contain exactly 3 symbols")
    if any(symbol not in GENERALIZED_SYMBOLS for symbol in input_symbols):
        raise ValueError("input patterns must use only '=', 'n', 'u', '0', and '1'")
    return input_symbols


def possible_output_symbols(function: str, input_symbols: str) -> tuple[str, ...]:
    """Return every exact signed symbol possible for a Boolean-function output.

    The input symbols constrain both sides of the transition, but an ``=``
    input does not reveal its common bit value.  Enumerating both sides keeps
    that uncertainty explicit and avoids using a concrete message pair to
    choose an output direction.
    """

    normalized = _normalize_function_name(function)
    normalized_inputs = _validate_input_symbols(input_symbols)
    fn = _boolean_function(normalized)
    output_symbols: set[str] = set()
    for input_pairs in product(*(SYMBOL_PAIRS[symbol] for symbol in normalized_inputs)):
        left_output = fn(*(pair[0] for pair in input_pairs))
        right_output = fn(*(pair[1] for pair in input_pairs))
        if left_output == right_output:
            output_symbols.add("0" if left_output == 0 else "1")
        elif (left_output, right_output) == (0, 1):
            output_symbols.add("n")
        else:
            output_symbols.add("u")
    return tuple(symbol for symbol in GENERALIZED_SYMBOLS if symbol in output_symbols)


def _enumerate_assignments(function: str, pattern: str) -> tuple[tuple[int, int, int, int], ...]:
    fn = _boolean_function(function)
    x_symbol, y_symbol, z_symbol, out_symbol = pattern
    assignments: list[tuple[int, int, int, int]] = []
    for x, y, z in product((0, 1), repeat=3):
        xp = _apply_symbol(x, x_symbol)
        yp = _apply_symbol(y, y_symbol)
        zp = _apply_symbol(z, z_symbol)
        if xp is None or yp is None or zp is None:
            continue
        out = fn(x, y, z)
        out_prime = fn(xp, yp, zp)
        if _apply_symbol(out, out_symbol) != out_prime:
            continue
        assignments.append((x, y, z, out))
    return tuple(assignments)


def _infer_fixed_values(assignments: tuple[tuple[int, int, int, int], ...]) -> tuple[LocalBitValue, ...]:
    if not assignments:
        return ()
    values: list[LocalBitValue] = []
    for index, variable in enumerate(LOCAL_VARIABLES):
        bits = {assignment[index] for assignment in assignments}
        if len(bits) == 1:
            values.append(LocalBitValue(variable, bits.pop()))
    return tuple(values)


def _infer_pair_conditions(assignments: tuple[tuple[int, int, int, int], ...]) -> tuple[LocalBitCondition, ...]:
    if not assignments:
        return ()
    conditions: list[LocalBitCondition] = []
    for left_index, right_index in combinations(range(len(LOCAL_VARIABLES)), 2):
        relation = {assignment[left_index] == assignment[right_index] for assignment in assignments}
        if relation == {True}:
            conditions.append(LocalBitCondition(LOCAL_VARIABLES[left_index], "==", LOCAL_VARIABLES[right_index]))
        elif relation == {False}:
            conditions.append(LocalBitCondition(LOCAL_VARIABLES[left_index], "!=", LOCAL_VARIABLES[right_index]))
    return tuple(conditions)


@lru_cache(maxsize=None)
def profile_for_pattern(function: str, pattern: str) -> BooleanConditionProfile:
    normalized = _normalize_function_name(function)
    normalized_pattern = _validate_pattern(pattern)
    assignments = _enumerate_assignments(normalized, normalized_pattern)
    return BooleanConditionProfile(
        function=normalized,
        x_symbol=normalized_pattern[0],
        y_symbol=normalized_pattern[1],
        z_symbol=normalized_pattern[2],
        out_symbol=normalized_pattern[3],
        assignments=assignments,
        pair_conditions=_infer_pair_conditions(assignments),
        fixed_values=_infer_fixed_values(assignments),
    )


@lru_cache(maxsize=None)
def enumerate_profiles(function: str) -> tuple[BooleanConditionProfile, ...]:
    normalized = _normalize_function_name(function)
    return tuple(profile_for_pattern(normalized, "".join(pattern)) for pattern in product(SYMBOLS, repeat=4))


def satisfiable_patterns(function: str) -> tuple[str, ...]:
    return tuple(profile.pattern for profile in enumerate_profiles(function) if profile.satisfiable)


def instantiate_pair_conditions(
    function: str,
    pattern: str,
    mapping: Mapping[str, BitRef],
) -> tuple[BitCondition, ...]:
    return profile_for_pattern(function, pattern).instantiate_pair_conditions(mapping)
