"""Reduced-step SHA-256 compression function.

The paper reports collisions for reduced versions of the SHA-256 compression
function. This module keeps the implementation intentionally small and explicit
so the test vectors can be checked against the paper tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

WORD_BITS = 32
WORD_MASK = (1 << WORD_BITS) - 1
BLOCK_WORDS = 16

SHA256_IV: tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

K: tuple[int, ...] = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


@dataclass(frozen=True)
class RoundState:
    """Working variables after one SHA-256 step."""

    step: int
    a: int
    b: int
    c: int
    d: int
    e: int
    f: int
    g: int
    h: int
    w: int


def add32(*values: int) -> int:
    return sum(values) & WORD_MASK


def rotr(value: int, amount: int) -> int:
    amount %= WORD_BITS
    return ((value >> amount) | (value << (WORD_BITS - amount))) & WORD_MASK


def shr(value: int, amount: int) -> int:
    return value >> amount


def big_sigma0(value: int) -> int:
    return rotr(value, 2) ^ rotr(value, 13) ^ rotr(value, 22)


def big_sigma1(value: int) -> int:
    return rotr(value, 6) ^ rotr(value, 11) ^ rotr(value, 25)


def small_sigma0(value: int) -> int:
    return rotr(value, 7) ^ rotr(value, 18) ^ shr(value, 3)


def small_sigma1(value: int) -> int:
    return rotr(value, 17) ^ rotr(value, 19) ^ shr(value, 10)


def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)


def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def parse_words(text: str) -> tuple[int, ...]:
    """Parse whitespace-separated 32-bit hexadecimal words."""

    words = tuple(int(part, 16) for part in text.split())
    for word in words:
        if not 0 <= word <= WORD_MASK:
            raise ValueError(f"word out of 32-bit range: {word:#x}")
    return words


def format_words(words: Sequence[int]) -> str:
    return " ".join(f"{word:08x}" for word in words)


def expand_message(block: Sequence[int], rounds: int) -> tuple[int, ...]:
    if len(block) != BLOCK_WORDS:
        raise ValueError(f"expected {BLOCK_WORDS} message words, got {len(block)}")
    if not 0 <= rounds <= len(K):
        raise ValueError(f"round count must be between 0 and {len(K)}")

    schedule = list(block)
    for i in range(BLOCK_WORDS, rounds):
        schedule.append(
            add32(
                small_sigma1(schedule[i - 2]),
                schedule[i - 7],
                small_sigma0(schedule[i - 15]),
                schedule[i - 16],
            )
        )
    return tuple(schedule[:rounds])


def compress(
    chaining_value: Sequence[int],
    block: Sequence[int],
    rounds: int,
    *,
    feed_forward: bool = True,
    trace: bool = False,
) -> tuple[int, ...] | tuple[tuple[int, ...], tuple[RoundState, ...]]:
    """Run the first ``rounds`` SHA-256 compression steps on one 512-bit block."""

    if len(chaining_value) != 8:
        raise ValueError(f"expected 8 chaining words, got {len(chaining_value)}")

    a, b, c, d, e, f, g, h = (word & WORD_MASK for word in chaining_value)
    schedule = expand_message(block, rounds)
    states: list[RoundState] = []

    for i, word in enumerate(schedule):
        t1 = add32(h, big_sigma1(e), ch(e, f, g), K[i], word)
        t2 = add32(big_sigma0(a), maj(a, b, c))
        h = g
        g = f
        f = e
        e = add32(d, t1)
        d = c
        c = b
        b = a
        a = add32(t1, t2)
        if trace:
            states.append(RoundState(i, a, b, c, d, e, f, g, h, word))

    state = (a, b, c, d, e, f, g, h)
    if feed_forward:
        state = tuple(add32(x, y) for x, y in zip(state, chaining_value))

    if trace:
        return state, tuple(states)
    return state


def digest_blocks(
    blocks: Iterable[Sequence[int]],
    rounds: int,
    *,
    iv: Sequence[int] = SHA256_IV,
) -> tuple[int, ...]:
    """Hash already-padded 512-bit blocks with a reduced-step compression."""

    state = tuple(iv)
    for block in blocks:
        state = compress(state, block, rounds)  # type: ignore[assignment]
    return state


def word_xor_diff(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return tuple((a ^ b) & WORD_MASK for a, b in zip(left, right))


def word_sub_diff(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    return tuple((a - b) & WORD_MASK for a, b in zip(left, right))
