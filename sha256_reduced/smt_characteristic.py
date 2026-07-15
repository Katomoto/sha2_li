"""Signed-difference SHA-256 characteristic model with Algorithm 1 options.

This module follows the structure of Algorithm 1 in Li et al., letting each
round choose between fast/full Boolean models and Method-1/Method-2 expansion
models via OP1..OP8-style switches.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Mapping, Sequence

from .cnf import CNF, rows_to_cnf, symbol_rules_to_cnf
from .core import K
from .solver import require_z3

BITS = 32
SYMBOL_TO_BITS = {"=": (False, False), "n": (False, True), "u": (True, True)}


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
    raise ValueError(f"unknown symbol: {symbol}")


@lru_cache(maxsize=1)
def add_rules() -> tuple[tuple[str, str, str, str, str], ...]:
    raw_rules = (
        ("===", "=="),
        ("==n", "n="),
        ("==u", "u="),
        ("=n=", "n="),
        ("=u=", "u="),
        ("=nn", "=n"),
        ("=un", "=="),
        ("=nu", "=="),
        ("=uu", "=u"),
        ("n==", "n="),
        ("u==", "u="),
        ("n=n", "=n"),
        ("u=n", "=="),
        ("n=u", "=="),
        ("u=u", "=u"),
        ("nn=", "=n"),
        ("nu=", "=="),
        ("un=", "=="),
        ("uu=", "=u"),
        ("nnn", "nn"),
        ("nun", "n="),
        ("unn", "n="),
        ("nnu", "n="),
        ("uun", "u="),
        ("unu", "u="),
        ("nuu", "u="),
        ("uuu", "uu"),
    )
    return tuple((left[0], left[1], left[2], right[0], right[1]) for left, right in raw_rules)


@lru_cache(maxsize=1)
def expansion_rules_method1() -> tuple[tuple[str, str, str, str], ...]:
    raw_rules = (
        ("nn", "=n"),
        ("uu", "=u"),
        ("nu", "=="),
        ("un", "=="),
        ("n=", "n="),
        ("n=", "un"),
        ("u=", "u="),
        ("u=", "nu"),
        ("=n", "n="),
        ("=n", "un"),
        ("=u", "u="),
        ("=u", "nu"),
        ("==", "=="),
    )
    return tuple((left[0], left[1], right[0], right[1]) for left, right in raw_rules)


@lru_cache(maxsize=1)
def expansion_rules_method2() -> tuple[tuple[str, str, str, str], ...]:
    raw_rules = (
        ("=un", "n"),
        ("=nn", "="),
        ("=uu", "="),
        ("=nu", "u"),
        ("u=n", "="),
        ("n=n", "n"),
        ("u=u", "u"),
        ("n=u", "="),
        ("nu=", "n"),
        ("nn=", "="),
        ("uu=", "="),
        ("un=", "u"),
        ("===", "="),
    )
    return tuple((left[0], left[1], left[2], right[0]) for left, right in raw_rules)


@lru_cache(maxsize=None)
def bool_fast_rules(name: str) -> tuple[tuple[str, str, str, str], ...]:
    def fn(x: int, y: int, z: int) -> int:
        if name == "xor3":
            return x ^ y ^ z
        if name == "if":
            return (x & y) ^ ((1 ^ x) & z)
        if name == "maj":
            return (x & y) ^ (x & z) ^ (y & z)
        raise ValueError(f"unknown Boolean function: {name}")

    rules: set[tuple[str, str, str, str]] = set()
    for x in (0, 1):
        for xp in (0, 1):
            for y in (0, 1):
                for yp in (0, 1):
                    for z in (0, 1):
                        for zp in (0, 1):
                            rules.add(
                                (
                                    _symbol(x, xp),
                                    _symbol(y, yp),
                                    _symbol(z, zp),
                                    _symbol(fn(x, y, z), fn(xp, yp, zp)),
                                )
                            )
    return tuple(sorted(rules))


def bool_rules(name: str) -> tuple[tuple[str, str, str, str], ...]:
    return bool_fast_rules(name)


@lru_cache(maxsize=None)
def bool_full_rows(name: str) -> tuple[tuple[int, ...], ...]:
    def fn(x: int, y: int, z: int) -> int:
        if name == "xor3":
            return x ^ y ^ z
        if name == "if":
            return (x & y) ^ ((1 ^ x) & z)
        if name == "maj":
            return (x & y) ^ (x & z) ^ (y & z)
        raise ValueError(f"unknown Boolean function: {name}")

    rows: list[tuple[int, ...]] = []
    for sx in SYMBOL_TO_BITS:
        for sy in SYMBOL_TO_BITS:
            for sz in SYMBOL_TO_BITS:
                for sw in SYMBOL_TO_BITS:
                    for x in (0, 1):
                        for y in (0, 1):
                            for z in (0, 1):
                                xp = _apply_symbol(x, sx)
                                yp = _apply_symbol(y, sy)
                                zp = _apply_symbol(z, sz)
                                if xp is None or yp is None or zp is None:
                                    continue
                                w = fn(x, y, z)
                                wp = fn(xp, yp, zp)
                                if _symbol(w, wp) != sw:
                                    continue
                                row = (
                                    *[int(bit) for bit in SYMBOL_TO_BITS[sx]],
                                    *[int(bit) for bit in SYMBOL_TO_BITS[sy]],
                                    *[int(bit) for bit in SYMBOL_TO_BITS[sz]],
                                    *[int(bit) for bit in SYMBOL_TO_BITS[sw]],
                                    x,
                                    y,
                                    z,
                                )
                                rows.append(row)
    return tuple(sorted(set(rows)))


@dataclass(frozen=True)
class Algorithm1Options:
    op1: bool = True
    op2: bool = True
    op3: bool = True
    op4: bool = True
    op5: bool = True
    op6: bool = True
    op7: bool = True
    op8: bool = False
    value_transition_steps: frozenset[int] | None = None


@dataclass(frozen=True)
class DiffBit:
    v: Any
    d: Any


@dataclass(frozen=True)
class DiffWord:
    bits: tuple[DiffBit, ...]

    def __post_init__(self) -> None:
        if len(self.bits) != BITS:
            raise ValueError(f"DiffWord must contain {BITS} bits")

    @classmethod
    def fresh(cls, name: str, solver: Any) -> "DiffWord":
        z3 = require_z3()
        word = cls(tuple(DiffBit(z3.Bool(f"{name}_v_{i}"), z3.Bool(f"{name}_d_{i}")) for i in range(BITS)))
        for bit in word.bits:
            solver.add(bit.d | ~bit.v)
        return word

    @classmethod
    def equal(cls, solver: Any, name: str) -> "DiffWord":
        word = cls.fresh(name, solver)
        constrain_word_pattern(solver, word, "=" * BITS)
        return word


def _symbol_constraint(bit: DiffBit, symbol: str) -> Any:
    z3 = require_z3()
    v_value, d_value = SYMBOL_TO_BITS[symbol]
    return z3.And(bit.v == v_value, bit.d == d_value)

#将DiffBit类型数据展开为z3.bool的类型
def _flatten_bits(bits: Sequence[DiffBit]) -> tuple[Any, ...]:
    flattened: list[Any] = []
    for bit in bits:
        flattened.extend((bit.v, bit.d))
    return tuple(flattened)

#查看word的index比特是否是1
def _bit_bool(word: Any, index: int) -> Any:
    z3 = require_z3()
    return z3.Extract(index, index, word) == z3.BitVecVal(1, 1)

#将cnf表达式转化为约束条件
def add_cnf(solver: Any, variables: Sequence[Any], cnf: CNF) -> None:
    z3 = require_z3()
    for clause in cnf:
        literals = [variables[literal - 1] if literal > 0 else z3.Not(variables[-literal - 1]) for literal in clause]
        solver.add(z3.Or(*literals))


@lru_cache(maxsize=1)
def add_cnf_template() -> CNF:
    return symbol_rules_to_cnf(add_rules())


@lru_cache(maxsize=1)
def exp_cnf_template_method1() -> CNF:
    return symbol_rules_to_cnf(expansion_rules_method1())


@lru_cache(maxsize=1)
def exp_cnf_template_method2() -> CNF:
    return symbol_rules_to_cnf(expansion_rules_method2())


@lru_cache(maxsize=None)
def bool_fast_cnf_template(name: str) -> CNF:
    return symbol_rules_to_cnf(bool_fast_rules(name))


@lru_cache(maxsize=None)
def bool_full_cnf_template(name: str) -> CNF:
    return rows_to_cnf(bool_full_rows(name))


def constrain_word_pattern(solver: Any, word: DiffWord, pattern: str) -> None:
    if len(pattern) != BITS:
        raise ValueError("patterns must be 32 characters")
    for offset, char in enumerate(pattern):
        if char in ("0", "1"):
            char = "="
        if char not in SYMBOL_TO_BITS:
            raise ValueError(f"unsupported characteristic symbol: {char!r}")
        solver.add(_symbol_constraint(word.bits[BITS - 1 - offset], char))


def rotr(word: DiffWord, amount: int) -> DiffWord:
    return DiffWord(tuple(word.bits[(i + amount) % BITS] for i in range(BITS)))


def shr(word: DiffWord, amount: int, solver: Any, name: str) -> DiffWord:
    shifted: list[DiffBit] = []
    zero = DiffWord.equal(solver, f"{name}_zero")
    for i in range(BITS):
        shifted.append(word.bits[i + amount] if i + amount < BITS else zero.bits[i])
    return DiffWord(tuple(shifted))


def rotr_value(word: Any, amount: int) -> Any:
    z3 = require_z3()
    return z3.RotateRight(word, amount)


def shr_value(word: Any, amount: int) -> Any:
    z3 = require_z3()
    return z3.LShR(word, amount)


def add2(solver: Any, name: str, x: DiffWord, y: DiffWord) -> DiffWord:
    out = DiffWord.fresh(name, solver)
    z3 = require_z3()
    carry_bits = [DiffBit(z3.Bool(f"{name}_c_v_0"), z3.Bool(f"{name}_c_d_0"))]
    solver.add(_symbol_constraint(carry_bits[0], "="))
    cnf = add_cnf_template()
    for i in range(BITS):
        next_carry = DiffBit(z3.Bool(f"{name}_c_v_{i + 1}"), z3.Bool(f"{name}_c_d_{i + 1}"))
        solver.add(next_carry.d | ~next_carry.v)
        add_cnf(solver, (*_flatten_bits((x.bits[i], y.bits[i], carry_bits[i], out.bits[i], next_carry)),), cnf)
        carry_bits.append(next_carry)
    return out

#添加expansion的约束
def apply_expansion(solver: Any, name: str, source: DiffWord, target: DiffWord, method1: bool) -> None:
    z3 = require_z3()
    carry_bits = [DiffBit(z3.Bool(f"{name}_c_v_0"), z3.Bool(f"{name}_c_d_0"))]
    solver.add(_symbol_constraint(carry_bits[0], "="))
    cnf = exp_cnf_template_method1() if method1 else exp_cnf_template_method2()
    for i in range(BITS):
        next_carry = DiffBit(z3.Bool(f"{name}_c_v_{i + 1}"), z3.Bool(f"{name}_c_d_{i + 1}"))
        solver.add(next_carry.d | ~next_carry.v)
        if method1:
            variables = (*_flatten_bits((source.bits[i], carry_bits[i], target.bits[i], next_carry)),)
        else:
            variables = (*_flatten_bits((target.bits[i], source.bits[i], carry_bits[i], next_carry)),)
        add_cnf(solver, variables, cnf)
        carry_bits.append(next_carry)


def apply_boolean_model(
    solver: Any,
    name: str,
    fn: str,
    mode_fast: bool,
    x_diff: DiffWord,
    y_diff: DiffWord,
    z_diff: DiffWord,
    out_diff: DiffWord,
    x_value: Any | None = None,
    y_value: Any | None = None,
    z_value: Any | None = None,
) -> None:
    if mode_fast:
        cnf = bool_fast_cnf_template(fn)
        for i in range(BITS):
            add_cnf(solver, (*_flatten_bits((x_diff.bits[i], y_diff.bits[i], z_diff.bits[i], out_diff.bits[i])),), cnf)
        return

    if x_value is None or y_value is None or z_value is None:
        raise ValueError("full model requires concrete left-side value words")
    cnf = bool_full_cnf_template(fn)
    for i in range(BITS):
        variables = (
            *_flatten_bits((x_diff.bits[i], y_diff.bits[i], z_diff.bits[i], out_diff.bits[i])),
            _bit_bool(x_value, i),
            _bit_bool(y_value, i),
            _bit_bool(z_value, i),
        )
        add_cnf(solver, variables, cnf)


@dataclass(frozen=True)
class CharacteristicResult:
    w: tuple[str, ...]
    a: Mapping[int, str]
    e: Mapping[int, str]
    objective: int | None


class CharacteristicSearch:
    """Build and solve Algorithm 1-style signed-difference models for SHA-256."""

    def __init__(self, rounds: int, *, prefix: str = "dc", options: Algorithm1Options | None = None) -> None:
        z3 = require_z3()
        if not 0 <= rounds <= len(K):
            raise ValueError(f"rounds must be between 0 and {len(K)}")
        self.z3 = z3
        self.rounds = rounds
        self.prefix = prefix
        self.options = options or Algorithm1Options()
        self.optimizer = z3.Optimize()

        self.w = [DiffWord.fresh(f"{prefix}_w_{i}", self.optimizer) for i in range(max(16, rounds))]
        self.a_rows: dict[int, DiffWord] = {}
        self.e_rows: dict[int, DiffWord] = {}
        self.final_state: tuple[DiffWord, ...] = ()

        self.value_w = [z3.BitVec(f"{prefix}_Wval_{i}", 32) for i in range(max(16, rounds))]
        self.value_a: dict[int, Any] = {i: z3.BitVec(f"{prefix}_Aval_{i}", 32) for i in range(-4, rounds)}
        self.value_e: dict[int, Any] = {i: z3.BitVec(f"{prefix}_Eval_{i}", 32) for i in range(-4, rounds)}

        self._initialize_state_rows()
        self._build_algorithm1_model()

    def _initialize_state_rows(self) -> None:
        a = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_a")
        b = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_b")
        c = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_c")
        d = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_d")
        e = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_e")
        f = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_f")
        g = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_g")
        h = DiffWord.equal(self.optimizer, f"{self.prefix}_iv_h")
        self.a_rows.update({-1: a, -2: b, -3: c, -4: d})
        self.e_rows.update({-1: e, -2: f, -3: g, -4: h})

    def _build_algorithm1_model(self) -> None:
        for i in range(self.rounds):
            self._build_sha2_e(i)
            self._build_sha2_a(i)
            if self._use_value_transitions(i):
                self._build_value_transitions(i)
            if i >= 16:
                self._build_sha2_w(i)
        self.final_state = (
            self.a_rows[self.rounds - 1],
            self.a_rows[self.rounds - 2] if self.rounds >= 2 else self.a_rows[-1],
            self.a_rows[self.rounds - 3] if self.rounds >= 3 else self.a_rows[-2],
            self.a_rows[self.rounds - 4] if self.rounds >= 4 else self.a_rows[-3],
            self.e_rows[self.rounds - 1],
            self.e_rows[self.rounds - 2] if self.rounds >= 2 else self.e_rows[-1],
            self.e_rows[self.rounds - 3] if self.rounds >= 3 else self.e_rows[-2],
            self.e_rows[self.rounds - 4] if self.rounds >= 4 else self.e_rows[-3],
        )

    def _use_value_transitions(self, i: int) -> bool:
        if self.options.value_transition_steps is not None:
            return i in self.options.value_transition_steps
        return self.options.op8

    def _build_value_transitions(self, i: int) -> None:
        z3 = require_z3()
        if i >= 16:
            self.optimizer.add(
                self.value_w[i]
                == (
                    (rotr_value(self.value_w[i - 2], 17) ^ rotr_value(self.value_w[i - 2], 19) ^ shr_value(self.value_w[i - 2], 10))
                    + self.value_w[i - 7]
                    + (rotr_value(self.value_w[i - 15], 7) ^ rotr_value(self.value_w[i - 15], 18) ^ shr_value(self.value_w[i - 15], 3))
                    + self.value_w[i - 16]
                )
            )
        sigma1_e = rotr_value(self.value_e[i - 1], 6) ^ rotr_value(self.value_e[i - 1], 11) ^ rotr_value(self.value_e[i - 1], 25)
        sigma0_a = rotr_value(self.value_a[i - 1], 2) ^ rotr_value(self.value_a[i - 1], 13) ^ rotr_value(self.value_a[i - 1], 22)
        choose = (self.value_e[i - 1] & self.value_e[i - 2]) ^ (~self.value_e[i - 1] & self.value_e[i - 3])
        majority = (
            (self.value_a[i - 1] & self.value_a[i - 2])
            ^ (self.value_a[i - 1] & self.value_a[i - 3])
            ^ (self.value_a[i - 2] & self.value_a[i - 3])
        )
        self.optimizer.add(
            self.value_e[i]
            == (
                self.value_a[i - 4]
                + self.value_e[i - 4]
                + sigma1_e
                + choose
                + z3.BitVecVal(K[i], 32)
                + self.value_w[i]
            )
        )
        self.optimizer.add(
            self.value_a[i]
            == (
                self.value_e[i]
                - self.value_a[i - 4]
                + sigma0_a
                + majority
            )
        )

    def _build_sha2_e(self, i: int) -> None:
        b0 = add2(self.optimizer, f"{self.prefix}_B_{i}_0", self.a_rows[i - 4], self.w[i])
        b1 = add2(self.optimizer, f"{self.prefix}_B_{i}_1", self.e_rows[i - 4], b0)

        b2 = DiffWord.fresh(f"{self.prefix}_B_{i}_2", self.optimizer)
        apply_boolean_model(
            self.optimizer,
            f"{self.prefix}_xorE_{i}",
            "xor3",
            self.options.op1,
            rotr(self.e_rows[i - 1], 6),
            rotr(self.e_rows[i - 1], 11),
            rotr(self.e_rows[i - 1], 25),
            b2,
            rotr_value(self.value_e[i - 1], 6),
            rotr_value(self.value_e[i - 1], 11),
            rotr_value(self.value_e[i - 1], 25),
        )
        b3 = add2(self.optimizer, f"{self.prefix}_B_{i}_3", b1, b2)

        b4 = DiffWord.fresh(f"{self.prefix}_B_{i}_4", self.optimizer)
        apply_boolean_model(
            self.optimizer,
            f"{self.prefix}_if_{i}",
            "if",
            self.options.op2,
            self.e_rows[i - 1],
            self.e_rows[i - 2],
            self.e_rows[i - 3],
            b4,
            self.value_e[i - 1],
            self.value_e[i - 2],
            self.value_e[i - 3],
        )
        b5 = add2(self.optimizer, f"{self.prefix}_B_{i}_5", b3, b4)
        self.e_rows[i] = DiffWord.fresh(f"{self.prefix}_E_{i}", self.optimizer)
        apply_expansion(self.optimizer, f"{self.prefix}_ExpE_{i}", b5, self.e_rows[i], self.options.op3)

    def _build_sha2_a(self, i: int) -> None:
        b6 = DiffWord.fresh(f"{self.prefix}_B_{i}_6", self.optimizer)
        apply_boolean_model(
            self.optimizer,
            f"{self.prefix}_xorA_{i}",
            "xor3",
            self.options.op4,
            rotr(self.a_rows[i - 1], 2),
            rotr(self.a_rows[i - 1], 13),
            rotr(self.a_rows[i - 1], 22),
            b6,
            rotr_value(self.value_a[i - 1], 2),
            rotr_value(self.value_a[i - 1], 13),
            rotr_value(self.value_a[i - 1], 22),
        )
        b7 = DiffWord.fresh(f"{self.prefix}_B_{i}_7", self.optimizer)
        apply_boolean_model(
            self.optimizer,
            f"{self.prefix}_maj_{i}",
            "maj",
            self.options.op5,
            self.a_rows[i - 1],
            self.a_rows[i - 2],
            self.a_rows[i - 3],
            b7,
            self.value_a[i - 1],
            self.value_a[i - 2],
            self.value_a[i - 3],
        )
        b8 = add2(self.optimizer, f"{self.prefix}_B_{i}_8", b6, b7)
        # The state-update formula in Section 2 is:
        #   A_i = E_i - A_{i-4} + Σ0(A_{i-1}) + MAJ(...)
        # Therefore we first form E_i + b8 and then constrain
        #   A_{i-4} + b10 = E_i + b8,
        # so b10 represents the modular difference later expanded to ΔA_i.
        #
        # The pseudo-code layout in Algorithm 1 appears inconsistent here; the
        # implementation follows the algebraic state-update equation instead.
        b9 = add2(self.optimizer, f"{self.prefix}_B_{i}_9", self.e_rows[i], b8)
        b10 = DiffWord.fresh(f"{self.prefix}_B_{i}_10", self.optimizer)
        add2_target(self.optimizer, f"{self.prefix}_Aeq_{i}", self.a_rows[i - 4], b10, b9)
        self.a_rows[i] = DiffWord.fresh(f"{self.prefix}_A_{i}", self.optimizer)
        apply_expansion(self.optimizer, f"{self.prefix}_ExpA_{i}", b10, self.a_rows[i], self.options.op6)

    def _build_sha2_w(self, i: int) -> None:
        b10 = DiffWord.fresh(f"{self.prefix}_WB_{i}_10", self.optimizer)
        apply_boolean_model(
            self.optimizer,
            f"{self.prefix}_xorW1_{i}",
            "xor3",
            False,
            rotr(self.w[i - 2], 17),
            rotr(self.w[i - 2], 19),
            shr(self.w[i - 2], 10, self.optimizer, f"{self.prefix}_wshr10_{i}"),
            b10,
            rotr_value(self.value_w[i - 2], 17),
            rotr_value(self.value_w[i - 2], 19),
            shr_value(self.value_w[i - 2], 10),
        )
        b11 = DiffWord.fresh(f"{self.prefix}_WB_{i}_11", self.optimizer)
        apply_boolean_model(
            self.optimizer,
            f"{self.prefix}_xorW0_{i}",
            "xor3",
            False,
            rotr(self.w[i - 15], 7),
            rotr(self.w[i - 15], 18),
            shr(self.w[i - 15], 3, self.optimizer, f"{self.prefix}_wshr3_{i}"),
            b11,
            rotr_value(self.value_w[i - 15], 7),
            rotr_value(self.value_w[i - 15], 18),
            shr_value(self.value_w[i - 15], 3),
        )
        b12 = add2(self.optimizer, f"{self.prefix}_WB_{i}_12", b10, self.w[i - 7])
        b13 = add2(self.optimizer, f"{self.prefix}_WB_{i}_13", b11, b12)
        b14 = add2(self.optimizer, f"{self.prefix}_WB_{i}_14", b13, self.w[i - 16])
        apply_expansion(self.optimizer, f"{self.prefix}_ExpW_{i}", b14, self.w[i], self.options.op7)

    def constrain_message_shape(self, nonzero_indices: set[int]) -> None:
        for i in range(self.rounds):
            if i not in nonzero_indices:
                constrain_word_pattern(self.optimizer, self.w[i], "=" * BITS)

    def constrain_modular_zero(self, kind: str, index: int, *, method1: bool = True) -> None:
        zero = DiffWord.equal(self.optimizer, f"{self.prefix}_{kind}_{index}_zero_mod")
        apply_expansion(self.optimizer, f"{self.prefix}_{kind}_{index}_zeroexp", zero, self._word(kind, index), method1)

    def constrain_modular_zero_range(self, kind: str, start: int, end: int, *, method1: bool = True) -> None:
        for index in range(start, end + 1):
            self.constrain_modular_zero(kind, index, method1=method1)

    def constrain_final_state_zero(self) -> None:
        for word in self.final_state:
            constrain_word_pattern(self.optimizer, word, "=" * BITS)

    def require_nonzero_message_difference(self) -> None:
        self.optimizer.add(self.z3.Or(*(bit.d for word in self.w[: self.rounds] for bit in word.bits)))

    def constrain_word(self, kind: str, index: int, pattern: str) -> None:
        constrain_word_pattern(self.optimizer, self._word(kind, index), pattern)

    def minimize_weight(self, words: Sequence[DiffWord]) -> None:
        self.optimizer.minimize(self.weight_expr(words))

    def weight_expr(self, words: Sequence[DiffWord]) -> Any:
        terms = [self.z3.If(bit.d, 1, 0) for word in words for bit in word.bits]
        return self.z3.Sum(*terms)

    def model_weight(self, model: Any, words: Sequence[DiffWord]) -> int:
        return model.eval(self.weight_expr(words), model_completion=True).as_long()

    def solve_model(self, *, timeout_ms: int | None = None) -> Any | None:
        if timeout_ms is not None:
            self.optimizer.set(timeout=timeout_ms)
        if self.optimizer.check() != self.z3.sat:
            return None
        return self.optimizer.model()

    def solve(self, *, timeout_ms: int | None = None) -> CharacteristicResult | None:
        model = self.solve_model(timeout_ms=timeout_ms)
        if model is None:
            return None
        return self.result_from_model(model)

    def result_from_model(self, model: Any) -> CharacteristicResult:
        return CharacteristicResult(
            w=tuple(self._model_word(model, self.w[i]) for i in range(self.rounds)),
            a={i: self._model_word(model, word) for i, word in self.a_rows.items()},
            e={i: self._model_word(model, word) for i, word in self.e_rows.items()},
            objective=None,
        )

    def _word(self, kind: str, index: int) -> DiffWord:
        if kind == "W":
            return self.w[index]
        if kind == "A":
            return self.a_rows[index]
        if kind == "E":
            return self.e_rows[index]
        raise ValueError(f"unknown word kind: {kind}")

    def _model_word(self, model: Any, word: DiffWord) -> str:
        chars: list[str] = []
        for bit in reversed(word.bits):
            v = self.z3.is_true(model.eval(bit.v, model_completion=True))
            d = self.z3.is_true(model.eval(bit.d, model_completion=True))
            if not d:
                chars.append("=")
            else:
                chars.append("u" if v else "n")
        return "".join(chars)


def add2_target(solver: Any, name: str, x: DiffWord, y: DiffWord, target: DiffWord) -> None:
    z3 = require_z3()
    carry_bits = [DiffBit(z3.Bool(f"{name}_c_v_0"), z3.Bool(f"{name}_c_d_0"))]
    solver.add(_symbol_constraint(carry_bits[0], "="))
    cnf = add_cnf_template()
    for i in range(BITS):
        next_carry = DiffBit(z3.Bool(f"{name}_c_v_{i + 1}"), z3.Bool(f"{name}_c_d_{i + 1}"))
        solver.add(next_carry.d | ~next_carry.v)
        add_cnf(solver, (*_flatten_bits((x.bits[i], y.bits[i], carry_bits[i], target.bits[i], next_carry)),), cnf)
        carry_bits.append(next_carry)
