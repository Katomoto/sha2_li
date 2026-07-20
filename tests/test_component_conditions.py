from __future__ import annotations

import unittest

from sha256_reduced.component_conditions import (
    profile_for_addition_pattern,
    profile_for_sigma_pattern,
    satisfiable_addition_patterns,
    sigma_spec,
)
from sha256_reduced.conditions import BitCondition, ref


class ComponentConditionTableTests(unittest.TestCase):
    def test_sigma_bit_mappings_follow_sha256_definitions(self) -> None:
        self.assertEqual(sigma_spec("Sigma0").input_bits(9), (11, 22, 31))
        self.assertEqual(sigma_spec("Sigma1").input_bits(10), (16, 21, 3))
        self.assertEqual(sigma_spec("sigma0").input_bits(29), (4, 15, None))
        self.assertEqual(sigma_spec("sigma1").input_bits(19), (4, 6, 29))

    def test_sigma_profile_binds_local_xor_conditions_to_word_bits(self) -> None:
        profile = profile_for_sigma_pattern("sigma1", 19, "n==", "u")
        self.assertIn(
            BitCondition(ref("W", 20, 6), "!=", ref("W", 20, 29)),
            profile.instantiate_input_conditions("W", 20),
        )

    def test_exact_full_adder_has_thirty_three_signed_transitions(self) -> None:
        self.assertEqual(len(satisfiable_addition_patterns()), 33)

    def test_full_adder_profile_extracts_value_relations(self) -> None:
        profile = profile_for_addition_pattern("==nn=")
        rendered = {str(condition) for condition in profile.pair_conditions}
        self.assertTrue(profile.satisfiable)
        self.assertIn("x == y", rendered)
        self.assertIn("carry_in == sum", rendered)


if __name__ == "__main__":
    unittest.main()
