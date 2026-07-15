from __future__ import annotations

import unittest

from sha256_reduced.core import SHA256_IV, compress, digest_blocks, parse_words
from sha256_reduced.differential import render_rows, signed_diff_word, trace_sfs
from sha256_reduced.vectors import (
    CONFERENCE_2024_SFS_VECTORS,
    JOURNAL_EXTENSION_COLLISION_VECTORS,
    JOURNAL_EXTENSION_SFS_VECTORS,
    SFS_VECTORS,
)
from sha256_reduced.verify import all_results, verify_collision, verify_sfs


class ReducedSha256Tests(unittest.TestCase):
    def test_full_sha256_empty_block_matches_fips_compression(self) -> None:
        # This is SHA-256("") after applying the standard single padding block.
        empty_padded_block = parse_words(
            "80000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000 "
            "00000000 00000000 00000000 00000000"
        )
        digest = digest_blocks((empty_padded_block,), 64, iv=SHA256_IV)
        self.assertEqual(
            digest,
            parse_words(
                "e3b0c442 98fc1c14 9afbf4c8 996fb924 "
                "27ae41e4 649b934c a495991b 7852b855"
            ),
        )

    def test_published_sfs_vectors(self) -> None:
        for vector in CONFERENCE_2024_SFS_VECTORS:
            with self.subTest(vector=vector.name):
                result = verify_sfs(vector)
                self.assertTrue(result.passed)

    def test_journal_extension_vectors(self) -> None:
        for vector in JOURNAL_EXTENSION_SFS_VECTORS:
            with self.subTest(vector=vector.name):
                result = verify_sfs(vector)
                self.assertTrue(result.passed)

        for vector in JOURNAL_EXTENSION_COLLISION_VECTORS:
            with self.subTest(vector=vector.name):
                result = verify_collision(vector)
                self.assertTrue(result.passed)

    def test_table_13_first_block_is_common(self) -> None:
        vector = JOURNAL_EXTENSION_COLLISION_VECTORS[0]
        self.assertEqual(vector.blocks[0], vector.blocks_prime[0])
        self.assertNotEqual(vector.blocks[1], vector.blocks_prime[1])

    def test_reduced_step_hash_changes_without_published_pairing(self) -> None:
        vector = CONFERENCE_2024_SFS_VECTORS[0]
        altered = list(vector.message_prime)
        altered[-1] ^= 1
        self.assertNotEqual(
            compress(vector.cv, vector.message, vector.rounds),
            compress(vector.cv, tuple(altered), vector.rounds),
        )

    def test_signed_difference_notation(self) -> None:
        self.assertEqual(signed_diff_word(0b10, 0b01)[-2:], "un")

    def test_trace_reports_nonzero_rows(self) -> None:
        rows = trace_sfs(CONFERENCE_2024_SFS_VECTORS[0])
        report = render_rows(rows)
        self.assertIn(" 8", report)
        self.assertIn("u", report)
        self.assertIn("n", report)

    def test_default_vectors_follow_2024_paper(self) -> None:
        self.assertEqual(SFS_VECTORS, CONFERENCE_2024_SFS_VECTORS)

    def test_default_verification_runs_only_2024_vectors(self) -> None:
        results = all_results()
        self.assertEqual(len(results), 1)
        self.assertIn("Table 5", results[0].name)


if __name__ == "__main__":
    unittest.main()
