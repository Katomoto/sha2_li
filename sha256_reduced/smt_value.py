"""Value-transition SMT model for SHA-256 message modification searches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .conditions import BitCondition, BitRef, add_conditions_to_solver
from .core import K, WORD_MASK
from .solver import MissingSolverError, bit, configure_solver_instance, require_z3


def _bv32(value: int) -> Any:
    z3 = require_z3()
    return z3.BitVecVal(value & WORD_MASK, 32)


def _rotr(value: Any, amount: int) -> Any:
    z3 = require_z3()
    return z3.RotateRight(value, amount)


def _shr(value: Any, amount: int) -> Any:
    z3 = require_z3()
    return z3.LShR(value, amount)


def _big_sigma0(value: Any) -> Any:
    return _rotr(value, 2) ^ _rotr(value, 13) ^ _rotr(value, 22)


def _big_sigma1(value: Any) -> Any:
    return _rotr(value, 6) ^ _rotr(value, 11) ^ _rotr(value, 25)


def _small_sigma0(value: Any) -> Any:
    return _rotr(value, 7) ^ _rotr(value, 18) ^ _shr(value, 3)


def _small_sigma1(value: Any) -> Any:
    return _rotr(value, 17) ^ _rotr(value, 19) ^ _shr(value, 10)


def _ch(x: Any, y: Any, z: Any) -> Any:
    return (x & y) ^ (~x & z)


def _maj(x: Any, y: Any, z: Any) -> Any:
    return (x & y) ^ (x & z) ^ (y & z)


@dataclass(frozen=True)
class ValueTrace:
    w: tuple[Any, ...]
    a: Mapping[int, Any]
    e: Mapping[int, Any]
    final_state: tuple[Any, ...]
    output: tuple[Any, ...]


class Sha256ValueModel:
    """Two parallel SHA-256 computations with constraints on values and differences."""

    def __init__(self, rounds: int, *, prefix: str = "sha256") -> None:
        z3 = require_z3()
        if not 0 <= rounds <= len(K):
            raise ValueError(f"rounds must be between 0 and {len(K)}")
        self.z3 = z3
        self.rounds = rounds
        self.solver = z3.Solver()
        self.left_block = tuple(z3.BitVec(f"{prefix}_m_{i}", 32) for i in range(16))
        self.right_block = tuple(z3.BitVec(f"{prefix}_mp_{i}", 32) for i in range(16))
        self.cv = tuple(z3.BitVec(f"{prefix}_cv_{i}", 32) for i in range(8))
        self.left = self._trace(self.cv, self.left_block)
        self.right = self._trace(self.cv, self.right_block)

    def _expand(self, block: Sequence[Any]) -> tuple[Any, ...]:
        schedule = list(block)
        for i in range(16, self.rounds):
            schedule.append(
                _small_sigma1(schedule[i - 2])
                + schedule[i - 7]
                + _small_sigma0(schedule[i - 15])
                + schedule[i - 16]
            )
        return tuple(schedule[: self.rounds])

    def _trace(self, cv: Sequence[Any], block: Sequence[Any]) -> ValueTrace:
        schedule = self._expand(block)
        a, b, c, d, e, f, g, h = cv
        a_rows: dict[int, Any] = {-1: a, -2: b, -3: c, -4: d}
        e_rows: dict[int, Any] = {-1: e, -2: f, -3: g, -4: h}
        for i, word in enumerate(schedule):
            t1 = h + _big_sigma1(e) + _ch(e, f, g) + _bv32(K[i]) + word
            t2 = _big_sigma0(a) + _maj(a, b, c)
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
            a_rows[i] = a
            e_rows[i] = e
        final_state = (a, b, c, d, e, f, g, h)
        output = tuple(word + cv_word for word, cv_word in zip(final_state, cv))
        return ValueTrace(schedule, a_rows, e_rows, final_state, output)

    def fix_cv(self, cv: Sequence[int]) -> None:
        if len(cv) != 8:
            raise ValueError("cv must contain 8 words")
        for var, value in zip(self.cv, cv):
            self.solver.add(var == _bv32(value))

    def fix_left_block(self, block: Sequence[int]) -> None:
        if len(block) != 16:
            raise ValueError("block must contain 16 words")
        for var, value in zip(self.left_block, block):
            self.solver.add(var == _bv32(value))

    def fix_right_block(self, block: Sequence[int]) -> None:
        if len(block) != 16:
            raise ValueError("block must contain 16 words")
        for var, value in zip(self.right_block, block):
            self.solver.add(var == _bv32(value))

    def require_collision_output(self) -> None:
        for left, right in zip(self.left.output, self.right.output):
            self.solver.add(left == right)

    def require_messages_differ(self) -> None:
        self.solver.add(self.z3.Or(*(left != right for left, right in zip(self.left_block, self.right_block))))

    def require_same_words_outside(self, allowed_difference_indices: set[int]) -> None:
        for i, (left, right) in enumerate(zip(self.left_block, self.right_block)):
            if i not in allowed_difference_indices:
                self.solver.add(left == right)

    def add_signed_pattern(self, kind: str, index: int, pattern: str) -> None:
        left, right = self._word_pair(kind, index)
        if len(pattern) != 32:
            raise ValueError(f"expected 32 pattern characters for {kind}{index}")
        for offset, char in enumerate(pattern):
            bit_index = 31 - offset
            lbit = bit(left, bit_index)
            rbit = bit(right, bit_index)
            if char == "=":
                self.solver.add(lbit == rbit)
            elif char == "0":
                self.solver.add(lbit == 0, rbit == 0)
            elif char == "1":
                self.solver.add(lbit == 1, rbit == 1)
            elif char == "u":
                self.solver.add(lbit == 1, rbit == 0)
            elif char == "n":
                self.solver.add(lbit == 0, rbit == 1)
            else:
                raise ValueError(f"unsupported signed-difference character: {char!r}")

    def add_component_signed_symbol(
        self,
        function: str,
        input_refs: Sequence[BitRef | None],
        bit_index: int,
        symbol: str,
    ) -> None:
        """Constrain one Boolean/rotation component output symbol.

        ``input_refs`` contains the word bits used by the component.  A
        ``None`` reference denotes the zero introduced by a logical shift in
        the small-sigma functions.
        """

        if len(input_refs) != 3:
            raise ValueError("component transitions must contain exactly three inputs")
        left_inputs: list[Any] = []
        right_inputs: list[Any] = []
        for reference in input_refs:
            if reference is None:
                left_inputs.append(self.z3.BoolVal(False))
                right_inputs.append(self.z3.BoolVal(False))
            else:
                left_word, right_word = self._word_pair(reference.kind, reference.index)
                left_inputs.append(bit(left_word, reference.bit) == 1)
                right_inputs.append(bit(right_word, reference.bit) == 1)

        def apply_component(inputs: Sequence[Any]) -> Any:
            def xor3(left: Any, middle: Any, right: Any) -> Any:
                return self.z3.Xor(self.z3.Xor(left, middle), right)

            if function == "if":
                return self.z3.Xor(
                    self.z3.And(inputs[0], inputs[1]),
                    self.z3.And(self.z3.Not(inputs[0]), inputs[2]),
                )
            if function == "maj":
                return xor3(
                    self.z3.And(inputs[0], inputs[1]),
                    self.z3.And(inputs[0], inputs[2]),
                    self.z3.And(inputs[1], inputs[2]),
                )
            if function == "xor3":
                return xor3(inputs[0], inputs[1], inputs[2])
            raise ValueError(f"unknown component function: {function!r}")

        if not 0 <= bit_index < 32:
            raise ValueError(f"component bit index must be between 0 and 31, got {bit_index}")
        left_bit = apply_component(left_inputs)
        right_bit = apply_component(right_inputs)
        if symbol == "=":
            self.solver.add(left_bit == right_bit)
        elif symbol == "0":
            self.solver.add(self.z3.Not(left_bit), self.z3.Not(right_bit))
        elif symbol == "1":
            self.solver.add(left_bit, right_bit)
        elif symbol == "n":
            self.solver.add(self.z3.Not(left_bit), right_bit)
        elif symbol == "u":
            self.solver.add(left_bit, self.z3.Not(right_bit))
        else:
            raise ValueError(f"unsupported component output symbol: {symbol!r}")

    def add_bit_conditions(self, conditions: Sequence[BitCondition]) -> None:
        values: dict[tuple[str, int], object] = {("__solver__", 0): self.solver}
        for i, word in enumerate(self.left.w):
            values[("W", i)] = word
        values.update({("A", i): word for i, word in self.left.a.items()})
        values.update({("E", i): word for i, word in self.left.e.items()})
        add_conditions_to_solver(conditions, values)

    def solve(
        self,
        *,
        timeout_ms: int | None = None,
        random_seed: int | None = None,
        solver_threads: int | None = None,
    ) -> Mapping[str, tuple[int, ...]] | None:
        configure_solver_instance(
            self.solver,
            timeout_ms=timeout_ms,
            random_seed=random_seed,
            threads=solver_threads,
        )
        result = self.solver.check()
        if result != self.z3.sat:
            return None
        model = self.solver.model()
        return {
            "cv": tuple(model.eval(word).as_long() for word in self.cv),
            "message": tuple(model.eval(word).as_long() for word in self.left_block),
            "message_prime": tuple(model.eval(word).as_long() for word in self.right_block),
        }

    def _word_pair(self, kind: str, index: int) -> tuple[Any, Any]:
        if kind == "W":
            return self.left.w[index], self.right.w[index]
        if kind == "A":
            return self.left.a[index], self.right.a[index]
        if kind == "E":
            return self.left.e[index], self.right.e[index]
        raise ValueError(f"unknown word kind: {kind}")


def z3_available() -> bool:
    try:
        require_z3()
    except MissingSolverError:
        return False
    return True
