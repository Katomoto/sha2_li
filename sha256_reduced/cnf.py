"""Truth-table to CNF conversion for signed-difference component models.

The paper feeds legal component propagation rows into LogicFriday and adds the
resulting CNF to the SAT/SMT model. LogicFriday is not bundled with this
project, so this module reproduces that pipeline locally: build the truth table,
derive prime implicants with Quine-McCluskey, select a compact cover, and emit
CNF clauses that are tested for exact equivalence against the legal rows.
"""

from __future__ import annotations

from functools import lru_cache
from itertools import product
from typing import Iterable, Sequence

SYMBOL_TO_BITS = {"=": (0, 0), "n": (0, 1), "u": (1, 1)}
Clause = tuple[int, ...]
CNF = tuple[Clause, ...]
Implicant = tuple[int, int]  # (bits, mask), where mask bit 1 means don't-care.

#将symbols中的符号差分转化为bit代表的大元组
def symbols_to_assignment(symbols: Sequence[str]) -> tuple[int, ...]:
    bits: list[int] = []
    for symbol in symbols:
        bits.extend(SYMBOL_TO_BITS[symbol])
    return tuple(bits)

#将符号差分对应的bit转化为int
def assignment_to_int(assignment: Sequence[int]) -> int:
    value = 0
    for i, bit in enumerate(assignment):
        if bit:
            value |= 1 << i
    return value

#将编码形式的大整数转化为符号差分
def int_to_assignment(value: int, num_vars: int) -> tuple[int, ...]:
    return tuple((value >> i) & 1 for i in range(num_vars))


def rule_to_int(rule: Sequence[str]) -> int:
    return assignment_to_int(symbols_to_assignment(rule))


def row_to_int(row: Sequence[int]) -> int:
    return assignment_to_int(row)


def _normalize(bits: int, mask: int) -> Implicant:
    return bits & ~mask, mask


def _can_combine(left: Implicant, right: Implicant) -> bool:
    left_bits, left_mask = left
    right_bits, right_mask = right
    if left_mask != right_mask:
        return False
    diff = (left_bits ^ right_bits) & ~left_mask
    return diff != 0 and diff & (diff - 1) == 0


def _combine(left: Implicant, right: Implicant) -> Implicant:
    left_bits, left_mask = left
    right_bits, _ = right
    diff = (left_bits ^ right_bits) & ~left_mask
    return _normalize(left_bits & ~diff, left_mask | diff)


def _covers(implicant: Implicant, minterm: int) -> bool:
    bits, mask = implicant
    return (minterm & ~mask) == bits


def _popcount(value: int) -> int:
    return bin(value).count("1")


def _literal_count(implicant: Implicant, num_vars: int) -> int:
    return num_vars - _popcount(implicant[1])


def _prime_implicants(minterms: Iterable[int]) -> set[Implicant]:
    current = {_normalize(term, 0) for term in minterms}
    primes: set[Implicant] = set()
    while current:
        used: set[Implicant] = set()
        next_round: set[Implicant] = set()
        ordered = sorted(current)
        for i, left in enumerate(ordered):
            for right in ordered[i + 1 :]:
                if not _can_combine(left, right):
                    continue
                used.add(left)
                used.add(right)
                next_round.add(_combine(left, right))
        primes.update(term for term in current if term not in used)
        current = next_round
    return primes


def _select_cover(primes: set[Implicant], minterms: set[int], num_vars: int) -> tuple[Implicant, ...]:
    if not minterms:
        return ()

    coverage = {prime: frozenset(term for term in minterms if _covers(prime, term)) for prime in primes}
    coverage = {prime: covered for prime, covered in coverage.items() if covered}
    selected: set[Implicant] = set()
    uncovered = set(minterms)

    while True:
        essential: set[Implicant] = set()
        for term in tuple(uncovered):
            candidates = [prime for prime, covered in coverage.items() if term in covered]
            if len(candidates) == 1:
                essential.add(candidates[0])
        if not essential:
            break
        selected.update(essential)
        for prime in essential:
            uncovered.difference_update(coverage[prime])
        if not uncovered:
            return tuple(sorted(selected))

    while uncovered:
        best_prime = max(
            coverage,
            key=lambda prime: (
                len(coverage[prime] & uncovered),
                -_literal_count(prime, num_vars),
            ),
        )
        if not (coverage[best_prime] & uncovered):
            raise ValueError("could not cover all invalid minterms")
        selected.add(best_prime)
        uncovered.difference_update(coverage[best_prime])

    return tuple(sorted(selected))


def _implicant_to_clause(implicant: Implicant, num_vars: int) -> Clause:
    bits, mask = implicant
    literals: list[int] = []
    for index in range(num_vars):
        if (mask >> index) & 1:
            continue
        # The clause is the negation of the invalid cube represented by the
        # implicant. If the cube fixes x_i=0, the clause contains x_i; if the
        # cube fixes x_i=1, the clause contains not x_i.
        literals.append(-(index + 1) if (bits >> index) & 1 else index + 1)
    return tuple(literals)


@lru_cache(maxsize=None)
def cnf_from_allowed(allowed: tuple[int, ...], num_vars: int) -> CNF:
    allowed_set = set(allowed)
    universe = set(range(1 << num_vars))
    invalid = universe - allowed_set
    primes = _prime_implicants(invalid)
    cover = _select_cover(primes, invalid, num_vars)
    return tuple(_implicant_to_clause(implicant, num_vars) for implicant in cover)


def rows_to_cnf(rows: Sequence[Sequence[int]]) -> CNF:
    if not rows:
        raise ValueError("at least one legal row is required")
    num_vars = len(rows[0])
    if any(len(row) != num_vars for row in rows):
        raise ValueError("all legal rows must have the same arity")
    allowed = tuple(sorted(row_to_int(row) for row in rows))
    return cnf_from_allowed(allowed, num_vars)


def symbol_rules_to_cnf(rules: Sequence[Sequence[str]]) -> CNF:
    return rows_to_cnf(tuple(symbols_to_assignment(rule) for rule in rules))


def cnf_accepts(cnf: CNF, assignment: Sequence[int]) -> bool:
    for clause in cnf:
        clause_ok = False
        for literal in clause:
            value = assignment[abs(literal) - 1]
            if (literal > 0 and value) or (literal < 0 and not value):
                clause_ok = True
                break
        if not clause_ok:
            return False
    return True


def all_assignments(num_vars: int) -> Iterable[tuple[int, ...]]:
    return product((0, 1), repeat=num_vars)
