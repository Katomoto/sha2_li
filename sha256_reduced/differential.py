"""Signed-difference reporting for reduced SHA-256 pairs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .core import RoundState, compress, digest_blocks, expand_message
from .vectors import (
    JOURNAL_EXTENSION_COLLISION_VECTORS,
    JOURNAL_EXTENSION_SFS_VECTORS,
    SFS_VECTORS,
    TABLE_13_31_STEP_COLLISION,
    TABLE_25_39_STEP_SFS,
    TABLE_5_39_STEP_SFS,
    CollisionVector,
    SfsCollisionVector,
)


@dataclass(frozen=True)
class DifferentialRow:
    step: int
    a: str | None
    e: str | None
    w: str | None


def signed_diff_word(left: int, right: int) -> str:
    """Return the paper-style signed bit difference from ``left`` to ``right``."""

    chars: list[str] = []
    for bit in range(31, -1, -1):
        left_bit = (left >> bit) & 1
        right_bit = (right >> bit) & 1
        if left_bit == right_bit:
            chars.append("=")
        elif left_bit == 1:
            chars.append("u")
        else:
            chars.append("n")
    return "".join(chars)


def _state_lookup(
    cv: Sequence[int], states: Sequence[RoundState], attr: str
) -> dict[int, int]:
    if attr == "a":
        values = {-1: cv[0], -2: cv[1], -3: cv[2], -4: cv[3]}
    elif attr == "e":
        values = {-1: cv[4], -2: cv[5], -3: cv[6], -4: cv[7]}
    else:
        raise ValueError(f"unsupported state attribute: {attr}")
    for state in states:
        values[state.step] = getattr(state, attr)
    return values


def trace_sfs(vector: SfsCollisionVector) -> tuple[DifferentialRow, ...]:
    _, left_states = compress(vector.cv, vector.message, vector.rounds, trace=True)
    _, right_states = compress(vector.cv, vector.message_prime, vector.rounds, trace=True)
    left_a = _state_lookup(vector.cv, left_states, "a")
    right_a = _state_lookup(vector.cv, right_states, "a")
    left_e = _state_lookup(vector.cv, left_states, "e")
    right_e = _state_lookup(vector.cv, right_states, "e")
    left_w = expand_message(vector.message, vector.rounds)
    right_w = expand_message(vector.message_prime, vector.rounds)

    rows: list[DifferentialRow] = []
    for step in range(-4, vector.rounds):
        rows.append(
            DifferentialRow(
                step=step,
                a=signed_diff_word(left_a[step], right_a[step]),
                e=signed_diff_word(left_e[step], right_e[step]),
                w=signed_diff_word(left_w[step], right_w[step]) if step >= 0 else None,
            )
        )
    return tuple(rows)

#要求第一块的cv产生碰撞，并不是two block methrod
def trace_collision_second_block(vector: CollisionVector) -> tuple[DifferentialRow, ...]:
    left_cv = digest_blocks(vector.blocks[:1], vector.rounds, iv=vector.iv)
    right_cv = digest_blocks(vector.blocks_prime[:1], vector.rounds, iv=vector.iv)
    if left_cv != right_cv:
        raise ValueError("the first block must lead to the same chaining value")

    sfs_vector = SfsCollisionVector(
        name=f"{vector.name} second block",
        source=vector.source,
        rounds=vector.rounds,
        cv=left_cv,
        message=vector.blocks[1],
        message_prime=vector.blocks_prime[1],
        expected_hash=vector.expected_hash,
    )
    return trace_sfs(sfs_vector)

#只要存在un就是非零差分
def has_nonzero_diff(row: DifferentialRow) -> bool:
    return any(value is not None and ("u" in value or "n" in value) for value in (row.a, row.e, row.w))


def render_rows(rows: Sequence[DifferentialRow], *, nonzero_only: bool = True) -> str:
    rendered = [" i   A                                E                                W"]
    for row in rows:
        if nonzero_only and not has_nonzero_diff(row):
            continue
        w = row.w if row.w is not None else ""
        rendered.append(f"{row.step:2d}  {row.a or '':32s} {row.e or '':32s} {w:32s}")
    return "\n".join(rendered)


TRACE_TARGETS = {
    "table5": lambda: (TABLE_5_39_STEP_SFS.name, trace_sfs(TABLE_5_39_STEP_SFS)),
    "table13": lambda: (TABLE_13_31_STEP_COLLISION.name, trace_collision_second_block(TABLE_13_31_STEP_COLLISION)),
    "table25": lambda: (TABLE_25_39_STEP_SFS.name, trace_sfs(TABLE_25_39_STEP_SFS)),
}
