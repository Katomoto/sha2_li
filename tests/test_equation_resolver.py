from __future__ import annotations

import unittest

from sha256_reduced.conditions import eq
from sha256_reduced.equation_resolver import Sha256EquationResolver
from sha256_reduced.fig6 import FIG6_PATTERNS, FIG6_ROUNDS


class EquationResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = Sha256EquationResolver(
            FIG6_PATTERNS,
            FIG6_ROUNDS,
            timeout_ms=10_000,
            prefix="resolver_test",
        )

    def test_message_expansion_resolves_sigma1_through_full_w22_equation(self) -> None:
        status, outputs = self.resolver.resolve_component("W", 22, "sigma1", 19, ("0", "1", "n", "u"))
        self.assertEqual(status, "sat")
        self.assertEqual(outputs, ("0", "1"))

    def test_state_update_can_force_a_sigma_output_direction(self) -> None:
        status, outputs = self.resolver.resolve_component("A", 15, "Sigma0", 16, ("n", "u"))
        self.assertEqual(status, "sat")
        self.assertEqual(outputs, ("n",))

    def test_w22_equation_does_not_imply_the_published_w20_pair_condition(self) -> None:
        equation = self.resolver.equation("W", 22)
        self.assertEqual(equation.condition_status(eq("W", 20, 4, "W", 20, 6)), "not-implied")

    def test_w22_full_adder_stages_use_equation_filtered_lookup_rows(self) -> None:
        equation = self.resolver.equation("W", 22)
        self.assertEqual(equation.possible_addition_patterns("plus_wm16", 19), ("=====",))
        self.assertEqual(equation.addition_conditions("plus_wm16", 19), ())


if __name__ == "__main__":
    unittest.main()
