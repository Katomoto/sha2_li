"""Verification helpers and CLI for the published SHA-256 collision vectors."""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from .differential import TRACE_TARGETS, render_rows
from .core import compress, digest_blocks, format_words, word_xor_diff
from .vectors import (
    COLLISION_VECTORS,
    CONFERENCE_2024_SFS_VECTORS,
    JOURNAL_EXTENSION_COLLISION_VECTORS,
    JOURNAL_EXTENSION_SFS_VECTORS,
    SFS_VECTORS,
    CollisionVector,
    SfsCollisionVector,
)


@dataclass(frozen=True)
class VerificationResult:
    name: str
    passed: bool
    left_hash: tuple[int, ...]
    right_hash: tuple[int, ...]
    expected_hash: tuple[int, ...]
    message_xor_diff: tuple[int, ...]


def verify_sfs(vector: SfsCollisionVector) -> VerificationResult:
    left = compress(vector.cv, vector.message, vector.rounds)
    right = compress(vector.cv, vector.message_prime, vector.rounds)
    passed = left == right == vector.expected_hash
    return VerificationResult(
        name=vector.name,
        passed=passed,
        left_hash=left,  # type: ignore[arg-type]
        right_hash=right,  # type: ignore[arg-type]
        expected_hash=vector.expected_hash,
        message_xor_diff=word_xor_diff(vector.message, vector.message_prime),
    )


def verify_collision(vector: CollisionVector) -> VerificationResult:
    left = digest_blocks(vector.blocks, vector.rounds, iv=vector.iv)
    right = digest_blocks(vector.blocks_prime, vector.rounds, iv=vector.iv)
    # Show the two-block difference as one flat sequence for compact CLI output.
    left_words = tuple(word for block in vector.blocks for word in block)
    right_words = tuple(word for block in vector.blocks_prime for word in block)
    passed = left == right == vector.expected_hash
    return VerificationResult(
        name=vector.name,
        passed=passed,
        left_hash=left,
        right_hash=right,
        expected_hash=vector.expected_hash,
        message_xor_diff=word_xor_diff(left_words, right_words),
    )


def all_results(paper: str = "2024") -> tuple[VerificationResult, ...]:
    if paper == "2024":
        sfs_vectors = CONFERENCE_2024_SFS_VECTORS
        collision_vectors = COLLISION_VECTORS
    elif paper == "journal":
        sfs_vectors = JOURNAL_EXTENSION_SFS_VECTORS
        collision_vectors = JOURNAL_EXTENSION_COLLISION_VECTORS
    elif paper == "all":
        sfs_vectors = CONFERENCE_2024_SFS_VECTORS + JOURNAL_EXTENSION_SFS_VECTORS
        collision_vectors = JOURNAL_EXTENSION_COLLISION_VECTORS
    else:
        raise ValueError(f"unknown paper selection: {paper}")

    sfs = tuple(verify_sfs(vector) for vector in sfs_vectors)
    collisions = tuple(verify_collision(vector) for vector in collision_vectors)
    return sfs + collisions


def render_result(result: VerificationResult) -> str:
    status = "PASS" if result.passed else "FAIL"
    nonzero = [
        f"W{i}={word:08x}" for i, word in enumerate(result.message_xor_diff) if word
    ]
    lines = [
        f"[{status}] {result.name}",
        f"  left:     {format_words(result.left_hash)}",
        f"  right:    {format_words(result.right_hash)}",
        f"  expected: {format_words(result.expected_hash)}",
        f"  nonzero xor message differences: {', '.join(nonzero) if nonzero else 'none'}",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Li et al.'s published reduced SHA-256 collision vectors."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print failing vectors.",
    )
    parser.add_argument(
        "--paper",
        choices=("2024", "journal", "all"),
        default="2024",
        help="Select vectors from the 2024 conference paper, the later journal-only additions, or both.",
    )
    parser.add_argument(
        "--trace",
        choices=tuple(TRACE_TARGETS) + ("all",),
        help="Print paper-style u/n/= signed-difference rows for a vector.",
    )
    args = parser.parse_args()

    results = all_results(args.paper)
    for result in results:
        if result.passed and args.quiet:
            continue
        print(render_result(result))

    if args.trace:
        targets = TRACE_TARGETS if args.trace == "all" else {args.trace: TRACE_TARGETS[args.trace]}
        for key, loader in targets.items():
            name, rows = loader()
            print(f"\nSigned-difference trace for {key} ({name})")
            print(render_rows(rows))

    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
