"""Published SHA-256 vectors from Li et al., New Records in Collision Attacks on SHA-2."""

from __future__ import annotations

from dataclasses import dataclass

from .core import SHA256_IV, parse_words


@dataclass(frozen=True)
class SfsCollisionVector:
    name: str
    source: str
    rounds: int
    cv: tuple[int, ...]
    message: tuple[int, ...]
    message_prime: tuple[int, ...]
    expected_hash: tuple[int, ...]


@dataclass(frozen=True)
class CollisionVector:
    name: str
    source: str
    rounds: int
    iv: tuple[int, ...]
    blocks: tuple[tuple[int, ...], ...]
    blocks_prime: tuple[tuple[int, ...], ...]
    expected_hash: tuple[int, ...]


TABLE_5_39_STEP_SFS = SfsCollisionVector(
    name="Table 5: 39-step SHA-256 SFS collision",
    source="conference-2024",
    rounds=39,
    cv=parse_words(
        "02b19d5a 88e1df04 5ea3c7b7 f2f7d1a4 "
        "86cb1b1f c8ee51a5 1b4d0541 651b92e7"
    ),
    message=parse_words(
        "c61d6de7 755336e8 5e61d618 18036de6 "
        "a79f2f1d f2b44c7b 4c0ef36b a85d45cf "
        "f72b8c2f 0def947c a0eab159 8021370c "
        "4b0d8011 7aad07f6 33cd6902 3bad5d64"
    ),
    message_prime=parse_words(
        "c61d6de7 755336e8 5e61d618 18036de6 "
        "a79f2f1d f2b44c7b 4c0ef36b a85d45cf "
        "e72b8c2f 0fcf907c b0eab159 81a1bfc1 "
        "4b098611 7aad07f6 33cd6902 3bad5d64"
    ),
    expected_hash=parse_words(
        "431cadcd ce6893bb d6c9689a 334854e8 "
        "3baae1ab 038a195a ccf54a19 1c40606d"
    ),
)


TABLE_13_31_STEP_COLLISION = CollisionVector(
    name="Table 13: 31-step SHA-256 two-block collision",
    source="journal-extension",
    rounds=31,
    iv=SHA256_IV,
    blocks=(
        parse_words(
            "8ce3f805 5c401aed 579e5f7f bc3116cb "
            "ca189b3c eb75f04c 958f0a0e 7760b082 "
            "dcd5027d 32260ad6 7b12b659 eee66518 "
            "ad7f88dd f8ad20bb 7ae40ffd 21609249"
        ),
        parse_words(
            "9abdeb1b 1f195f41 5a7210c1 55614f13 "
            "a2269dd1 be888a61 359257d4 adf3737b "
            "9f0484a6 eb830a58 66add94a 9669232d "
            "45271fa5 b8f69585 428bbce3 0703b904"
        ),
    ),
    blocks_prime=(
        parse_words(
            "8ce3f805 5c401aed 579e5f7f bc3116cb "
            "ca189b3c eb75f04c 958f0a0e 7760b082 "
            "dcd5027d 32260ad6 7b12b659 eee66518 "
            "ad7f88dd f8ad20bb 7ae40ffd 21609249"
        ),
        parse_words(
            "9abdeb1b 1f195f41 5a7210c1 55614f13 "
            "a2269dd1 be887a67 35b2dfc5 fde32975 "
            "c70595a6 eb838a5c 66add94a 9669232d "
            "45271fa5 b8f69585 428bbce3 0703b904"
        ),
    ),
    expected_hash=parse_words(
        "ff558659 2977dd01 54638843 35f8de84 "
        "a3336841 f4f476f2 7c571548 f7025605"
    ),
)


TABLE_25_39_STEP_SFS = SfsCollisionVector(
    name="Table 25: 39-step SHA-256 SFS collision from quantum section",
    source="journal-extension",
    rounds=39,
    cv=parse_words(
        "0fe4f3b8 15890d7f 7eed03c9 52e8693b "
        "a2d92840 f131d527 ed33261c 81667335"
    ),
    message=parse_words(
        "e4e1915d 6f676d82 4163c515 258d373a "
        "47d84dbb 7060a323 13d1cbf1 12f7b38d "
        "50eb6b7d b4592a66 2be7d70f a82bc0f1 "
        "47d24cbe f846ccf3 8253a11a 38673c57"
    ),
    message_prime=parse_words(
        "e4e1915d 6f676d82 4163c515 258d373a "
        "47d84dbb 7060a323 13d1cbf1 12f7b38d "
        "40eb6b7d b6792e66 3be7d70f a9ab483c "
        "47d646be f846ccf3 8253a11a 38673c57"
    ),
    expected_hash=parse_words(
        "5d37d605 84c1dd60 b1dcaace aca70e59 "
        "42fcae7b e701d335 b687560c 6141565a"
    ),
)


CONFERENCE_2024_SFS_VECTORS = (TABLE_5_39_STEP_SFS,)
JOURNAL_EXTENSION_SFS_VECTORS = (TABLE_25_39_STEP_SFS,)
JOURNAL_EXTENSION_COLLISION_VECTORS = (TABLE_13_31_STEP_COLLISION,)

# Default to the 2024 conference paper the user most recently selected.
SFS_VECTORS = CONFERENCE_2024_SFS_VECTORS
COLLISION_VECTORS: tuple[CollisionVector, ...] = ()
