"""Machine-readable data from Fig. 6 and Table 3 of Li et al. (2026)."""

from __future__ import annotations

from typing import Iterable

from .conditions import BitCondition, eq, ne
from .core import parse_words

FIG6_ROUNDS = 35
EQUAL_WORD = "=" * 32


def _patterns() -> dict[tuple[str, int], str]:
    patterns = {
        **{("A", i): EQUAL_WORD for i in range(-4, FIG6_ROUNDS)},
        **{("E", i): EQUAL_WORD for i in range(-4, FIG6_ROUNDS)},
        **{("W", i): EQUAL_WORD for i in range(FIG6_ROUNDS)},
    }
    patterns.update(
        {
            ("A", 4): "==n=============================",
            ("A", 5): "=====n===n===n=u====n===u==u====",
            ("A", 9): "==========u====================u",
            ("A", 11): "====n=========u=u=======u==n====",
            ("A", 12): "=un===u=n=======n===============",
            ("A", 14): "==u=============================",
            ("E", 3): "=====1=====011======0======0====",
            ("E", 4): "==n0=0=1===100=0==0=1===0==1=0=1",
            ("E", 5): "01011u001n=nuu=11000n=1=101u=100",
            ("E", 6): "101n=0=1=1=n1111==n0u===n=0n=n=u",
            ("E", 7): "10u0=1=101==00=n==0=0===0==0=0=0",
            ("E", 8): "uuu1=0=111=0=0=01=1=01==1==1=1=0",
            ("E", 9): "11=10n0nuuu00n0u101=n11=u01u=unn",
            ("E", 10): "un111111001001111=010u=u0=001100",
            ("E", 11): "1011n111100010u1u0111111u=nu1001",
            ("E", 12): "001uuu11uuuuuuuu11n1000n1uuu1001",
            ("E", 13): "=n1111uu1n00000u1u0=nnn01111010n",
            ("E", 14): "=0=100110000000=101=0000=110===0",
            ("E", 15): "=1====0011===u10001=011===0n===1",
            ("E", 16): "======u=n====1==n=====0===01====",
            ("E", 17): "======0=0====1==0==========1====",
            ("E", 18): "==u===1=0=======1====1==========",
            ("E", 19): "==0=============================",
            ("E", 20): "==1=============================",
            ("W", 4): "==n=============================",
            ("W", 5): "=====u===u==========n===========",
            ("W", 6): "==n=============================",
            ("W", 7): "=======n=======u===u====u===u=u=",
            ("W", 8): "============u=======uu==========",
            ("W", 12): "=====n===n==========u===========",
            ("W", 13): "==u=============================",
            ("W", 20): "=======nn=======u===============",
            ("W", 22): "==n=============================",
        }
    )
    for (kind, index), pattern in patterns.items():
        if len(pattern) != 32:
            raise AssertionError(f"invalid Fig. 6 pattern length for {kind}{index}: {len(pattern)}")
    return patterns


FIG6_PATTERNS = _patterns()

# In the bitmap used by the paper, E10[6] and E11[6] are printed as '+'.
# The notation section does not define '+', and Table 3 confirms both are equal
# bits, so the machine-readable characteristic normalizes both glyphs to '='.
FIG6_NORMALIZED_GLYPHS = (("E", 10, 6, "+", "="), ("E", 11, 6, "+", "="))

FIG6_M0 = parse_words(
    """
    a8850273 c0f4a504 5d3ad7b5 6e5f5026 535cc256 e92ef7a5 436f70df 7d7e236a
    cadc14e8 d59ac191 6874f1ba 6b83960d f6dfe9de 6a013df2 f856b739 237894e8
    """
)
FIG6_MESSAGE = parse_words(
    """
    c0008214 ae65f3bf e93c006a 5f195aa9 a4d6cd0f 21811cec ea897317 db9ec665
    6ec17218 5100da8a 0912e57b a96b2054 45f2222c 4d12f88a d2701ecc 140976d1
    """
)
FIG6_MESSAGE_PRIME = parse_words(
    """
    c0008214 ae65f3bf e93c006a 5f195aa9 84d6cd0f 25c114ec ca897317 da9fd6ef
    6ec97e18 5100da8a 0912e57b a96b2054 41b22a2c 6d12f88a d2701ecc 140976d1
    """
)
FIG6_HASH = parse_words(
    "c6209b2b 5e3fd4c8 96087364 046304ab bbc6dad9 403a26d1 018e351f e444451f"
)


def _vector_conditions(
    kind_l: str,
    index_l: int,
    bits_l: Iterable[int],
    op: str,
    kind_r: str,
    index_r: int,
    bits_r: Iterable[int],
) -> tuple[BitCondition, ...]:
    left = tuple(bits_l)
    right = tuple(bits_r)
    if len(left) != len(right):
        raise ValueError("Fig. 6 vector condition sides must have the same length")
    constructor = eq if op == "==" else ne
    return tuple(constructor(kind_l, index_l, lbit, kind_r, index_r, rbit) for lbit, rbit in zip(left, right))


FIG6_W_CONDITIONS = (
    *_vector_conditions("W", 4, (1, 8), "!=", "W", 4, (12, 25)),
    *_vector_conditions("W", 4, (18,), "==", "W", 4, (14,)),
    *_vector_conditions("W", 5, (0, 1, 30), "==", "W", 5, (28, 18, 9)),
    *_vector_conditions("W", 6, (1, 8), "==", "W", 6, (12, 25)),
    *_vector_conditions("W", 6, (18,), "!=", "W", 6, (14,)),
    *_vector_conditions("W", 7, (22, 13, 23), "!=", "W", 7, (18, 9, 8)),
    *_vector_conditions("W", 7, (11, 14, 20), "==", "W", 7, (22, 31, 31)),
    *_vector_conditions("W", 8, (0, 14, 21), "==", "W", 8, (28, 25, 6)),
    *_vector_conditions("W", 8, (31, 23, 30, 15, 22, 8), "!=", "W", 8, (27, 2, 15, 26, 7, 4)),
    *_vector_conditions("W", 20, (4, 31), "==", "W", 20, (6, 22)),
    *_vector_conditions("W", 20, (31, 30, 25, 21), "!=", "W", 20, (1, 0, 16, 14)),
    *_vector_conditions("W", 22, (4, 31), "==", "W", 22, (6, 22)),
    *_vector_conditions("W", 22, (27,), "!=", "W", 22, (20,)),
)

FIG6_E_CONDITIONS = (
    *_vector_conditions("E", 4, (10,), "!=", "E", 4, (15,)),
    *_vector_conditions("E", 5, (3, 21), "==", "E", 5, (8, 8)),
    *_vector_conditions("E", 6, (9, 27, 9, 8), "!=", "E", 6, (23, 14, 14, 27)),
    *_vector_conditions("E", 6, (1, 1, 23, 6), "==", "E", 6, (6, 15, 10, 25)),
    *_vector_conditions("E", 7, (21, 10), "!=", "E", 7, (3, 15)),
    *_vector_conditions("E", 16, (28, 20, 20, 6), "==", "E", 16, (1, 7, 2, 11)),
    *_vector_conditions("E", 16, (30, 28, 10), "!=", "E", 16, (12, 10, 29)),
    *_vector_conditions("E", 18, (24,), "!=", "E", 18, (11,)),
    *_vector_conditions("E", 18, (2,), "==", "E", 18, (16,)),
)

FIG6_A_CONDITIONS = (
    *_vector_conditions("A", 3, (29,), "==", "A", 2, (29,)),
    *_vector_conditions("A", 3, (29,), "!=", "A", 5, (29,)),
    *_vector_conditions("A", 3, (26, 4), "==", "A", 4, (26, 4)),
    *_vector_conditions("A", 3, (22, 18, 16, 11, 7), "!=", "A", 4, (22, 18, 16, 11, 7)),
    *_vector_conditions("A", 14, (9,), "==", "A", 14, (20,)),
    *_vector_conditions("A", 14, (18, 8), "==", "A", 14, (6, 17)),
    *_vector_conditions("A", 13, (30, 25, 23), "==", "A", 14, (30, 25, 23)),
    *_vector_conditions("A", 13, (15,), "!=", "A", 14, (15,)),
    *_vector_conditions("A", 13, (29,), "!=", "A", 15, (29,)),
    *_vector_conditions("A", 15, (29,), "==", "A", 6, (29,)),
)

FIG6_CONDITIONS = FIG6_W_CONDITIONS + FIG6_E_CONDITIONS + FIG6_A_CONDITIONS

