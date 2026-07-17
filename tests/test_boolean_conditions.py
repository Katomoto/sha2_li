from __future__ import annotations

import unittest

from sha256_reduced.boolean_conditions import (
    BOOLEAN_FUNCTION_NAMES,
    LocalBitCondition,
    LocalBitValue,
    enumerate_profiles,
    possible_output_symbols,
    profile_for_pattern,
)
from sha256_reduced.conditions import BitCondition, ref
from sha256_reduced.smt_characteristic import bool_rules


class BooleanConditionTests(unittest.TestCase):
    def test_satisfiable_patterns_match_existing_boolean_transition_tables(self) -> None:
        for name in BOOLEAN_FUNCTION_NAMES:
            with self.subTest(name=name):
                expected = {"".join(rule) for rule in bool_rules(name)}
                actual = {profile.pattern for profile in enumerate_profiles(name) if profile.satisfiable}
                self.assertEqual(actual, expected)

    def test_if_u_equal_equal_equal_implies_pairwise_equalities(self) -> None:
        profile = profile_for_pattern("if", "u===")
        self.assertTrue(profile.satisfiable)
        self.assertEqual(
            profile.pair_conditions,
            (
                LocalBitCondition("y", "==", "z"),
                LocalBitCondition("y", "==", "out"),
                LocalBitCondition("z", "==", "out"),
            ),
        )
        self.assertEqual(profile.fixed_values, (LocalBitValue("x", 1),))

    def test_if_u_equal_equal_u_implies_inequalities_and_fixed_values(self) -> None:
        profile = profile_for_pattern("ch", "u==u")
        self.assertTrue(profile.satisfiable)
        self.assertIn(LocalBitCondition("y", "!=", "z"), profile.pair_conditions)
        self.assertEqual(
            profile.fixed_values,
            (
                LocalBitValue("x", 1),
                LocalBitValue("y", 1),
                LocalBitValue("z", 0),
                LocalBitValue("out", 1),
            ),
        )

    def test_impossible_transition_has_no_conditions(self) -> None:
        profile = profile_for_pattern("if", "===u")
        self.assertFalse(profile.satisfiable)
        self.assertEqual(profile.pair_conditions, ())
        self.assertEqual(profile.fixed_values, ())

    def test_generalized_zero_pattern_can_fix_every_local_value(self) -> None:
        profile = profile_for_pattern("if", "0000")
        self.assertTrue(profile.satisfiable)
        self.assertEqual(
            profile.fixed_values,
            (
                LocalBitValue("x", 0),
                LocalBitValue("y", 0),
                LocalBitValue("z", 0),
                LocalBitValue("out", 0),
            ),
        )

    def test_generalized_one_pattern_is_supported_for_xor3(self) -> None:
        profile = profile_for_pattern("xor3", "1111")
        self.assertTrue(profile.satisfiable)
        self.assertEqual(
            profile.fixed_values,
            (
                LocalBitValue("x", 1),
                LocalBitValue("y", 1),
                LocalBitValue("z", 1),
                LocalBitValue("out", 1),
            ),
        )

    def test_possible_outputs_keep_the_equal_bit_value_ambiguous(self) -> None:
        self.assertEqual(
            set(possible_output_symbols("if", "n==")),
            {"n", "u", "0", "1"},
        )

    def test_local_conditions_can_bind_to_existing_bit_condition_type(self) -> None:
        profile = profile_for_pattern("if", "u===")
        bound = profile.instantiate_pair_conditions(
            {
                "x": ref("E", 5, 10),
                "y": ref("E", 4, 10),
                "z": ref("E", 3, 10),
                "out": ref("B", 0, 10),
            }
        )
        self.assertEqual(
            bound,
            (
                BitCondition(ref("E", 4, 10), "==", ref("E", 3, 10)),
                BitCondition(ref("E", 4, 10), "==", ref("B", 0, 10)),
                BitCondition(ref("E", 3, 10), "==", ref("B", 0, 10)),
            ),
        )


if __name__ == "__main__":
    unittest.main()
