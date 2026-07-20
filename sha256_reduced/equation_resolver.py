"""Resolve SHA-256 component outputs from complete local update equations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .component_conditions import (
    common_addition_pair_conditions,
    profile_for_addition_pattern,
    satisfiable_addition_patterns,
)
from .conditions import BitCondition, BitRef
from .core import K
from .solver import bit, configure_solver_instance, require_z3

WordKey = tuple[str, int]
WordPair = tuple[Any, Any]
BitRefRow = tuple[BitRef | None, ...]


def _rotr(value: Any, amount: int) -> Any:
    return require_z3().RotateRight(value, amount)


def _shr(value: Any, amount: int) -> Any:
    return require_z3().LShR(value, amount)


def _big_sigma0(value: Any) -> Any:
    return _rotr(value, 2) ^ _rotr(value, 13) ^ _rotr(value, 22)


def _big_sigma1(value: Any) -> Any:
    return _rotr(value, 6) ^ _rotr(value, 11) ^ _rotr(value, 25)


def _small_sigma0(value: Any) -> Any:
    return _rotr(value, 7) ^ _rotr(value, 18) ^ _shr(value, 3)


def _small_sigma1(value: Any) -> Any:
    return _rotr(value, 17) ^ _rotr(value, 19) ^ _shr(value, 10)


def _if(value: Any, when_true: Any, when_false: Any) -> Any:
    return (value & when_true) ^ (~value & when_false)


def _maj(x: Any, y: Any, z: Any) -> Any:
    return (x & y) ^ (x & z) ^ (y & z)


def _add_pattern(solver: Any, left: Any, right: Any, pattern: str) -> None:
    if len(pattern) != 32:
        raise ValueError("word patterns must contain exactly 32 symbols")
    for offset, symbol in enumerate(pattern):
        bit_index = 31 - offset
        left_bit = bit(left, bit_index)
        right_bit = bit(right, bit_index)
        if symbol == "=":
            solver.add(left_bit == right_bit)
        elif symbol == "0":
            solver.add(left_bit == 0, right_bit == 0)
        elif symbol == "1":
            solver.add(left_bit == 1, right_bit == 1)
        elif symbol == "n":
            solver.add(left_bit == 0, right_bit == 1)
        elif symbol == "u":
            solver.add(left_bit == 1, right_bit == 0)
        else:
            raise ValueError(f"unsupported signed-difference symbol: {symbol!r}")


def _symbol_constraint(z3: Any, left_bit: Any, right_bit: Any, symbol: str) -> Any:
    if symbol == "=":
        return left_bit == right_bit
    if symbol == "0":
        return z3.And(left_bit == 0, right_bit == 0)
    if symbol == "1":
        return z3.And(left_bit == 1, right_bit == 1)
    if symbol == "n":
        return z3.And(left_bit == 0, right_bit == 1)
    if symbol == "u":
        return z3.And(left_bit == 1, right_bit == 0)
    raise ValueError(f"unsupported signed-difference symbol: {symbol!r}")

#计算bit_index位的进位值
def _carry_into(left: Any, right: Any, bit_index: int) -> Any:
    z3 = require_z3()
    if bit_index == 0:
        return z3.BitVecVal(0, 1)
    low_left = z3.Extract(bit_index - 1, 0, left)
    low_right = z3.Extract(bit_index - 1, 0, right)
    extended_sum = z3.ZeroExt(1, low_left) + z3.ZeroExt(1, low_right)
    return z3.Extract(bit_index, bit_index, extended_sum)


@dataclass(frozen=True)
class AdditionStage:
    name: str
    left: WordPair
    right: WordPair
    output: WordPair
    left_refs: BitRefRow
    right_refs: BitRefRow
    output_refs: BitRefRow

    def variable_pairs(self, bit_index: int) -> Mapping[str, WordPair]:
        if not 0 <= bit_index < 32:
            raise ValueError("addition bit index must be between 0 and 31")
        return {
            "x": (bit(self.left[0], bit_index), bit(self.left[1], bit_index)),
            "y": (bit(self.right[0], bit_index), bit(self.right[1], bit_index)),
            "carry_in": (
                _carry_into(self.left[0], self.right[0], bit_index),
                _carry_into(self.left[1], self.right[1], bit_index),
            ),
            "sum": (bit(self.output[0], bit_index), bit(self.output[1], bit_index)),
            "carry_out": (
                _carry_into(self.left[0], self.right[0], bit_index + 1),
                _carry_into(self.left[1], self.right[1], bit_index + 1),
            ),
        }

    def reference_bindings(self, bit_index: int) -> Mapping[str, BitRef | None]:
        return {
            "x": self.left_refs[bit_index],
            "y": self.right_refs[bit_index],
            "carry_in": None,
            "sum": self.output_refs[bit_index],
            "carry_out": None,
        }


@dataclass
class LocalEquation:
    name: str
    solver: Any
    words: Mapping[WordKey, WordPair]
    components: Mapping[str, WordPair]
    additions: list[AdditionStage]

    def configure(self, *, timeout_ms: int | None, solver_threads: int | None) -> None:
        configure_solver_instance(self.solver, timeout_ms=timeout_ms, threads=solver_threads)

    def satisfiable(self) -> str:
        return str(self.solver.check())

    def possible_component_symbols(
        self,
        component: str,
        bit_index: int,
        candidates: Sequence[str] = ("0", "1", "n", "u"),
    ) -> tuple[str, ...]:
        try:
            left, right = self.components[component]
        except KeyError as exc:
            raise ValueError(f"component {component!r} is not present in equation {self.name}") from exc
        z3 = require_z3()
        left_bit = bit(left, bit_index)
        right_bit = bit(right, bit_index)
        possible: list[str] = []
        for symbol in candidates:
            self.solver.push()
            self.solver.add(_symbol_constraint(z3, left_bit, right_bit, symbol))
            result = self.solver.check()
            self.solver.pop()
            if result == z3.sat:
                possible.append(symbol)
        return tuple(possible)

    def condition_status(self, condition: BitCondition) -> str:
        z3 = require_z3()
        try:
            left_word = self.words[condition.left.key()][0]
            right_word = self.words[condition.right.key()][0]
        except KeyError:
            return "out-of-scope"
        left_bit = bit(left_word, condition.left.bit)
        right_bit = bit(right_word, condition.right.bit)
        expression = left_bit == right_bit if condition.op == "==" else left_bit != right_bit
        self.solver.push()
        self.solver.add(z3.Not(expression))
        result = self.solver.check()
        self.solver.pop()
        if result == z3.unsat:
            return "implied"
        if result == z3.sat:
            return "not-implied"
        return "unknown"

    def possible_addition_patterns(self, stage_name: str, bit_index: int) -> tuple[str, ...]:
        try:
            stage = next(stage for stage in self.additions if stage.name == stage_name)
        except StopIteration as exc:
            raise ValueError(f"addition stage {stage_name!r} is not present in equation {self.name}") from exc
        z3 = require_z3()
        variables = stage.variable_pairs(bit_index)
        names = ("x", "y", "carry_in", "sum", "carry_out")
        possible: set[str] = set()
        self.solver.push()
        while True:
            result = self.solver.check()
            if result != z3.sat:
                break
            model = self.solver.model()
            symbols: list[str] = []
            for name in names:
                left, right = variables[name]
                left_value = model.eval(left, model_completion=True).as_long()
                right_value = model.eval(right, model_completion=True).as_long()
                if left_value == right_value:
                    symbols.append("=")
                elif left_value == 0:
                    symbols.append("n")
                else:
                    symbols.append("u")
            pattern = "".join(symbols)
            possible.add(pattern)
            block = z3.And(
                *(
                    _symbol_constraint(z3, *variables[name], symbol)
                    for name, symbol in zip(names, pattern)
                )
            )
            self.solver.add(z3.Not(block))
        self.solver.pop()
        order = {pattern: index for index, pattern in enumerate(satisfiable_addition_patterns())}
        return tuple(sorted(possible, key=order.__getitem__))

    def addition_conditions(self, stage_name: str, bit_index: int) -> tuple[BitCondition, ...]:
        stage = next(stage for stage in self.additions if stage.name == stage_name)
        bindings = stage.reference_bindings(bit_index)
        condition_maps: list[dict[tuple[str, str, str], BitCondition]] = []
        for pattern in self.possible_addition_patterns(stage_name, bit_index):
            profile = profile_for_addition_pattern(pattern)
            conditions: dict[tuple[str, str, str], BitCondition] = {}
            for local in profile.pair_conditions:
                left = bindings.get(local.left)
                right = bindings.get(local.right)
                if left is None or right is None:
                    continue
                condition = BitCondition(left, local.op, right)
                key = tuple(sorted((str(left), str(right)))) + (local.op,)
                conditions[key] = condition
            condition_maps.append(conditions)
        if not condition_maps:
            return ()
        common = set(condition_maps[0])
        for condition_map in condition_maps[1:]:
            common.intersection_update(condition_map)
        return tuple(condition_maps[0][key] for key in sorted(common))

    def table_addition_conditions(
        self,
        stage_name: str,
        bit_index: int,
        patterns: Mapping[WordKey, str],
    ) -> tuple[BitCondition, ...]:
        """Extract conditions from known word symbols and the full-adder table."""

        stage = next(stage for stage in self.additions if stage.name == stage_name)
        bindings = stage.reference_bindings(bit_index)
        variables = ("x", "y", "carry_in", "sum", "carry_out")
        partial: list[str] = []
        for variable in variables:
            reference = bindings[variable]
            if reference is None:
                partial.append("?")
            else:
                partial.append(patterns[reference.key()][31 - reference.bit])
        conditions: list[BitCondition] = []
        for local in common_addition_pair_conditions("".join(partial)):
            left = bindings.get(local.left)
            right = bindings.get(local.right)
            if left is None or right is None:
                continue
            conditions.append(BitCondition(left, local.op, right))
        return tuple(conditions)


class Sha256EquationResolver:
    """Build independent two-lane equations for each SHA-256 W/E/A update."""

    def __init__(
        self,
        patterns: Mapping[WordKey, str],
        rounds: int,
        *,
        timeout_ms: int | None = 10_000,
        solver_threads: int | None = None,
        prefix: str = "equation",
    ) -> None:
        self.patterns = patterns
        self.rounds = rounds
        self.timeout_ms = timeout_ms
        self.solver_threads = solver_threads
        self.prefix = prefix
        self._cache: dict[tuple[str, int], LocalEquation] = {}

    def equation(self, kind: str, index: int) -> LocalEquation:
        key = kind, index
        if key not in self._cache:
            if kind == "W":
                equation = self._build_w(index)
            elif kind == "E":
                equation = self._build_e(index)
            elif kind == "A":
                equation = self._build_a(index)
            else:
                raise ValueError(f"unknown equation kind: {kind!r}")
            equation.configure(timeout_ms=self.timeout_ms, solver_threads=self.solver_threads)
            self._cache[key] = equation
        return self._cache[key]

    def _new_equation(self, kind: str, index: int, keys: Sequence[WordKey]) -> LocalEquation:
        z3 = require_z3()
        solver = z3.Solver()
        words: dict[WordKey, WordPair] = {}
        for word_kind, word_index in dict.fromkeys(keys):
            try:
                pattern = self.patterns[(word_kind, word_index)]
            except KeyError as exc:
                raise ValueError(f"missing characteristic pattern for {word_kind}{word_index}") from exc
            stem = f"{self.prefix}_{kind}{index}_{word_kind}{word_index}"
            pair = z3.BitVec(f"{stem}_left", 32), z3.BitVec(f"{stem}_right", 32)
            words[(word_kind, word_index)] = pair
            _add_pattern(solver, pair[0], pair[1], pattern)
        return LocalEquation(f"{kind}{index}", solver, words, {}, [])

    @staticmethod
    def _word_refs(kind: str, index: int) -> BitRefRow:
        return tuple(BitRef(kind, index, bit_index) for bit_index in range(32))

    @staticmethod
    def _no_refs() -> BitRefRow:
        return (None,) * 32

    def _append_addition(
        self,
        equation: LocalEquation,
        name: str,
        left: WordPair,
        left_refs: BitRefRow,
        right: WordPair,
        right_refs: BitRefRow,
        *,
        target: WordPair | None = None,
        target_refs: BitRefRow | None = None,
    ) -> tuple[WordPair, BitRefRow]:
        computed = left[0] + right[0], left[1] + right[1]
        if target is None:
            output = computed
            output_refs = self._no_refs()
        else:
            equation.solver.add(target[0] == computed[0], target[1] == computed[1])
            output = target
            output_refs = target_refs or self._no_refs()
        equation.additions.append(
            AdditionStage(
                name=name,
                left=left,
                right=right,
                output=output,
                left_refs=left_refs,
                right_refs=right_refs,
                output_refs=output_refs,
            )
        )
        return output, output_refs

    def _build_w(self, index: int) -> LocalEquation:
        if not 16 <= index < self.rounds:
            raise ValueError(f"message expansion equation requires 16 <= index < {self.rounds}")
        keys = (("W", index), ("W", index - 2), ("W", index - 7), ("W", index - 15), ("W", index - 16))
        equation = self._new_equation("W", index, keys)
        word = lambda i: equation.words[("W", i)]
        sigma1 = (_small_sigma1(word(index - 2)[0]), _small_sigma1(word(index - 2)[1]))
        sigma0 = (_small_sigma0(word(index - 15)[0]), _small_sigma0(word(index - 15)[1]))
        no_refs = self._no_refs()
        stage0, refs0 = self._append_addition(
            equation,
            "sigma1_plus_wm7",
            sigma1,
            no_refs,
            word(index - 7),
            self._word_refs("W", index - 7),
        )
        stage1, refs1 = self._append_addition(
            equation,
            "plus_sigma0",
            stage0,
            refs0,
            sigma0,
            no_refs,
        )
        self._append_addition(
            equation,
            "plus_wm16",
            stage1,
            refs1,
            word(index - 16),
            self._word_refs("W", index - 16),
            target=word(index),
            target_refs=self._word_refs("W", index),
        )
        equation.components = {"sigma1": sigma1, "sigma0": sigma0}
        return equation

    def _build_e(self, index: int) -> LocalEquation:
        if not 0 <= index < self.rounds:
            raise ValueError(f"state equation requires 0 <= index < {self.rounds}")
        keys = (
            ("E", index),
            ("A", index - 4),
            ("E", index - 4),
            ("E", index - 1),
            ("E", index - 2),
            ("E", index - 3),
            ("W", index),
        )
        equation = self._new_equation("E", index, keys)
        word = lambda kind, i: equation.words[(kind, i)]
        sigma1 = (
            _big_sigma1(word("E", index - 1)[0]),
            _big_sigma1(word("E", index - 1)[1]),
        )
        choose = (
            _if(word("E", index - 1)[0], word("E", index - 2)[0], word("E", index - 3)[0]),
            _if(word("E", index - 1)[1], word("E", index - 2)[1], word("E", index - 3)[1]),
        )
        no_refs = self._no_refs()
        stage0, refs0 = self._append_addition(
            equation,
            "a_plus_em4",
            word("A", index - 4),
            self._word_refs("A", index - 4),
            word("E", index - 4),
            self._word_refs("E", index - 4),
        )
        stage1, refs1 = self._append_addition(
            equation,
            "plus_Sigma1",
            stage0,
            refs0,
            sigma1,
            no_refs,
        )
        stage2, refs2 = self._append_addition(
            equation,
            "plus_IF",
            stage1,
            refs1,
            choose,
            no_refs,
        )
        constant = require_z3().BitVecVal(K[index], 32)
        stage3, refs3 = self._append_addition(
            equation,
            "plus_K",
            stage2,
            refs2,
            (constant, constant),
            no_refs,
        )
        self._append_addition(
            equation,
            "plus_W",
            stage3,
            refs3,
            word("W", index),
            self._word_refs("W", index),
            target=word("E", index),
            target_refs=self._word_refs("E", index),
        )
        equation.components = {"Sigma1": sigma1, "IF": choose}
        return equation

    def _build_a(self, index: int) -> LocalEquation:
        if not 0 <= index < self.rounds:
            raise ValueError(f"state equation requires 0 <= index < {self.rounds}")
        keys = (
            ("A", index),
            ("A", index - 4),
            ("A", index - 1),
            ("A", index - 2),
            ("A", index - 3),
            ("E", index),
        )
        equation = self._new_equation("A", index, keys)
        word = lambda kind, i: equation.words[(kind, i)]
        sigma0 = (
            _big_sigma0(word("A", index - 1)[0]),
            _big_sigma0(word("A", index - 1)[1]),
        )
        majority = (
            _maj(word("A", index - 1)[0], word("A", index - 2)[0], word("A", index - 3)[0]),
            _maj(word("A", index - 1)[1], word("A", index - 2)[1], word("A", index - 3)[1]),
        )
        no_refs = self._no_refs()
        left_sum, _ = self._append_addition(
            equation,
            "a_plus_am4",
            word("A", index),
            self._word_refs("A", index),
            word("A", index - 4),
            self._word_refs("A", index - 4),
        )
        right0, refs0 = self._append_addition(
            equation,
            "e_plus_Sigma0",
            word("E", index),
            self._word_refs("E", index),
            sigma0,
            no_refs,
        )
        right_sum, _ = self._append_addition(
            equation,
            "plus_MAJ",
            right0,
            refs0,
            majority,
            no_refs,
        )
        equation.solver.add(left_sum[0] == right_sum[0], left_sum[1] == right_sum[1])
        equation.components = {"Sigma0": sigma0, "MAJ": majority}
        return equation

    def resolve_component(
        self,
        equation_kind: str,
        equation_index: int,
        component: str,
        bit_index: int,
        candidates: Sequence[str] = ("0", "1", "n", "u"),
    ) -> tuple[str, tuple[str, ...]]:
        equation = self.equation(equation_kind, equation_index)
        status = equation.satisfiable()
        if status != "sat":
            return status, ()
        return status, equation.possible_component_symbols(component, bit_index, candidates)
