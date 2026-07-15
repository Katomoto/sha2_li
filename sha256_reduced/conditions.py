"""Message-modification bit conditions from Li et al.'s Table 14 and Table 15."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class BitRef:
    kind: str
    index: int
    bit: int

    def key(self) -> tuple[str, int]:
        return self.kind, self.index

    def __str__(self) -> str:
        return f"{self.kind}{self.index}[{self.bit}]"


@dataclass(frozen=True)
class BitCondition:
    left: BitRef
    op: str
    right: BitRef

    def __str__(self) -> str:
        return f"{self.left} {self.op} {self.right}"


def ref(kind: str, index: int, bit: int) -> BitRef:
    return BitRef(kind, index, bit)


def eq(kind_l: str, index_l: int, bit_l: int, kind_r: str, index_r: int, bit_r: int) -> BitCondition:
    return BitCondition(ref(kind_l, index_l, bit_l), "==", ref(kind_r, index_r, bit_r))


def ne(kind_l: str, index_l: int, bit_l: int, kind_r: str, index_r: int, bit_r: int) -> BitCondition:
    return BitCondition(ref(kind_l, index_l, bit_l), "!=", ref(kind_r, index_r, bit_r))


TABLE14_W_CONDITIONS: tuple[BitCondition, ...] = (
    ne("W", 5, 3, "W", 5, 31),
    eq("W", 5, 23, "W", 5, 19),
    eq("W", 5, 22, "W", 5, 18),
    ne("W", 5, 19, "W", 5, 30),
    ne("W", 5, 23, "W", 5, 8),
    ne("W", 5, 17, "W", 5, 28),
    ne("W", 5, 16, "W", 5, 27),
    eq("W", 5, 26, "W", 5, 11),
    ne("W", 5, 24, "W", 5, 9),
    ne("W", 5, 18, "W", 5, 29),
    ne("W", 5, 25, "W", 5, 10),
    eq("W", 6, 19, "W", 6, 30),
    ne("W", 6, 22, "W", 6, 7),
    eq("W", 6, 10, "W", 6, 6),
    ne("W", 6, 8, "W", 6, 19),
    ne("W", 7, 7, "W", 7, 24),
    ne("W", 7, 23, "W", 7, 19),
    ne("W", 7, 22, "W", 7, 18),
    eq("W", 7, 31, "W", 7, 16),
    eq("W", 7, 23, "W", 7, 8),
    ne("W", 7, 18, "W", 7, 29),
    eq("W", 7, 17, "W", 7, 13),
    eq("W", 7, 16, "W", 7, 27),
    ne("W", 7, 22, "W", 7, 7),
    eq("W", 7, 25, "W", 7, 10),
    eq("W", 7, 13, "W", 7, 24),
    ne("W", 7, 15, "W", 7, 26),
    eq("W", 7, 7, "W", 7, 18),
    eq("W", 7, 19, "W", 7, 15),
    eq("W", 8, 19, "W", 8, 4),
    ne("W", 8, 2, "W", 8, 13),
    ne("W", 8, 9, "W", 8, 26),
    eq("W", 8, 17, "W", 8, 13),
    eq("W", 8, 31, "W", 8, 10),
    ne("W", 8, 1, "W", 8, 29),
    ne("W", 8, 29, "W", 8, 25),
    eq("W", 8, 7, "W", 8, 24),
    eq("W", 8, 6, "W", 8, 23),
    ne("W", 8, 20, "W", 8, 31),
    ne("W", 8, 19, "W", 8, 15),
    eq("W", 8, 0, "W", 8, 11),
    ne("W", 9, 13, "W", 9, 30),
    ne("W", 9, 23, "W", 9, 19),
    ne("W", 9, 26, "W", 9, 11),
    ne("W", 9, 9, "W", 9, 20),
    eq("W", 16, 1, "W", 16, 26),
    ne("W", 16, 23, "W", 16, 25),
    ne("W", 16, 25, "W", 16, 27),
    ne("W", 16, 24, "W", 16, 26),
    ne("W", 16, 0, "W", 16, 25),
    ne("W", 16, 22, "W", 16, 24),
    eq("W", 16, 21, "W", 16, 23),
    ne("W", 16, 20, "W", 16, 22),
    ne("W", 16, 19, "W", 16, 21),
    eq("W", 18, 4, "W", 18, 27),
    ne("W", 18, 2, "W", 18, 25),
    eq("W", 18, 22, "W", 18, 24),
)


TABLE15_AE_CONDITIONS: tuple[BitCondition, ...] = (
    eq("A", 3, 1, "A", 4, 1),
    eq("A", 3, 3, "A", 4, 3),
    ne("A", 3, 4, "A", 4, 4),
    ne("A", 3, 12, "A", 4, 12),
    ne("A", 3, 7, "A", 4, 7),
    eq("A", 3, 8, "A", 4, 8),
    ne("A", 3, 9, "A", 4, 9),
    eq("A", 3, 10, "A", 4, 10),
    ne("A", 3, 6, "A", 4, 6),
    eq("A", 3, 5, "A", 4, 5),
    eq("A", 4, 1, "A", 6, 1),
    ne("A", 4, 3, "A", 6, 3),
    eq("A", 4, 4, "A", 6, 4),
    ne("A", 4, 23, "A", 5, 23),
    ne("A", 4, 7, "A", 6, 7),
    ne("A", 4, 8, "A", 6, 8),
    ne("A", 4, 9, "A", 6, 9),
    eq("A", 4, 10, "A", 6, 10),
    eq("A", 4, 0, "A", 5, 0),
    eq("A", 4, 5, "A", 6, 5),
    eq("A", 4, 6, "A", 6, 6),
    ne("A", 4, 12, "A", 6, 12),
    ne("A", 5, 31, "A", 5, 19),
    ne("A", 5, 30, "A", 5, 18),
    ne("A", 5, 29, "A", 5, 17),
    ne("A", 5, 28, "A", 5, 16),
    ne("A", 5, 26, "A", 5, 14),
    ne("A", 5, 25, "A", 5, 13),
    ne("A", 5, 21, "A", 5, 0),
    eq("A", 5, 20, "A", 5, 31),
    ne("A", 5, 18, "A", 5, 29),
    ne("A", 5, 17, "A", 5, 28),
    ne("A", 5, 16, "A", 5, 27),
    eq("A", 5, 17, "A", 5, 26),
    eq("A", 5, 15, "A", 5, 26),
    eq("A", 5, 13, "A", 5, 24),
    eq("A", 5, 23, "A", 5, 0),
    ne("A", 5, 21, "A", 5, 30),
    ne("A", 5, 19, "A", 5, 28),
    ne("A", 5, 18, "A", 5, 27),
    eq("A", 5, 15, "A", 5, 24),
    eq("A", 5, 14, "A", 5, 23),
    ne("A", 5, 19, "A", 5, 30),
    ne("A", 5, 16, "A", 5, 25),
    ne("A", 5, 27, "A", 5, 15),
    eq("A", 5, 20, "A", 5, 29),
    ne("A", 5, 2, "A", 6, 2),
    ne("A", 5, 21, "A", 6, 21),
    ne("A", 5, 24, "A", 6, 24),
    eq("A", 5, 28, "A", 6, 28),
    eq("A", 6, 2, "A", 6, 11),
    ne("A", 6, 21, "A", 6, 9),
    ne("A", 6, 11, "A", 6, 20),
    eq("A", 6, 3, "A", 6, 14),
    eq("A", 7, 4, "A", 7, 15),
    ne("A", 7, 11, "A", 7, 20),
    ne("A", 7, 7, "A", 7, 16),
    ne("A", 7, 23, "A", 7, 11),
    ne("A", 7, 14, "A", 7, 25),
    eq("A", 7, 13, "A", 7, 1),
    eq("A", 7, 10, "A", 7, 30),
    eq("A", 7, 8, "A", 7, 19),
    ne("A", 7, 13, "A", 7, 22),
    eq("A", 7, 4, "A", 7, 15),
    eq("A", 7, 5, "A", 7, 17),
    ne("A", 7, 13, "A", 7, 22),
    eq("A", 5, 23, "A", 7, 23),
    ne("A", 8, 23, "A", 8, 11),
    eq("A", 8, 14, "A", 8, 25),
    ne("A", 8, 13, "A", 8, 22),
    eq("A", 6, 12, "A", 8, 12),
    eq("A", 6, 24, "A", 8, 24),
    eq("A", 6, 28, "A", 8, 28),
    ne("A", 6, 21, "A", 8, 21),
    eq("A", 7, 23, "A", 8, 23),
    ne("A", 8, 0, "A", 9, 0),
    eq("A", 8, 12, "A", 9, 12),
    eq("A", 8, 21, "A", 9, 21),
    eq("A", 8, 24, "A", 9, 24),
    ne("A", 8, 28, "A", 9, 28),
    eq("A", 8, 15, "A", 9, 15),
    eq("A", 10, 4, "A", 10, 24),
    eq("A", 10, 23, "A", 10, 11),
    ne("A", 10, 26, "A", 10, 3),
    ne("A", 10, 27, "A", 10, 6),
    eq("A", 10, 25, "A", 10, 14),
    eq("A", 10, 13, "A", 10, 22),
    ne("A", 9, 15, "A", 11, 15),
    ne("A", 9, 2, "A", 11, 2),
    eq("A", 11, 15, "A", 12, 15),
    eq("A", 11, 2, "A", 12, 2),
    eq("E", 3, 1, "E", 4, 1),
    eq("E", 3, 2, "E", 4, 2),
    eq("E", 3, 3, "E", 4, 3),
    eq("E", 3, 12, "E", 4, 12),
    eq("E", 3, 13, "E", 4, 13),
    ne("E", 7, 8, "E", 7, 22),
    ne("E", 8, 9, "E", 8, 22),
    eq("E", 8, 0, "E", 8, 14),
    ne("E", 10, 31, "E", 10, 18),
    ne("E", 10, 31, "E", 10, 13),
    ne("E", 12, 30, "E", 12, 17),
    ne("E", 12, 20, "E", 12, 2),
    eq("E", 14, 29, "E", 14, 10),
    ne("E", 14, 28, "E", 14, 1),
    ne("E", 14, 29, "E", 14, 16),
    ne("E", 14, 7, "E", 14, 21),
)


TABLE14_15_CONDITIONS: tuple[BitCondition, ...] = TABLE14_W_CONDITIONS + TABLE15_AE_CONDITIONS


def bit_value(word: int, bit: int) -> int:
    return (word >> bit) & 1


def evaluate_condition(condition: BitCondition, values: Mapping[tuple[str, int], int]) -> bool:
    left = bit_value(values[condition.left.key()], condition.left.bit)
    right = bit_value(values[condition.right.key()], condition.right.bit)
    return left == right if condition.op == "==" else left != right


def failing_conditions(
    conditions: Sequence[BitCondition], values: Mapping[tuple[str, int], int]
) -> tuple[BitCondition, ...]:
    return tuple(condition for condition in conditions if not evaluate_condition(condition, values))


def add_conditions_to_solver(conditions: Sequence[BitCondition], values: Mapping[tuple[str, int], object]) -> None:
    from .solver import bit, require_z3

    z3 = require_z3()
    solver = values.get(("__solver__", 0))
    if solver is None:
        raise ValueError("values must contain a ('__solver__', 0) solver entry")
    for condition in conditions:
        left = bit(values[condition.left.key()], condition.left.bit)
        right = bit(values[condition.right.key()], condition.right.bit)
        constraint = left == right if condition.op == "==" else left != right
        solver.add(constraint)  # type: ignore[attr-defined]


def format_conditions(conditions: Sequence[BitCondition]) -> str:
    return "\n".join(str(condition) for condition in conditions)
