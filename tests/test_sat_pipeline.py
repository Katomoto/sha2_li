from __future__ import annotations

import inspect
import unittest

from search_sha256 import (
    SECTION_4_1_DELTA_A_ZERO_RANGE,
    SECTION_4_1_DELTA_E_ZERO_RANGE,
    SECTION_4_1_W_INDICES,
    _table13_second_block_values,
)
from sha256_reduced.cnf import all_assignments, cnf_accepts, symbol_rules_to_cnf, symbols_to_assignment
from sha256_reduced.conditions import TABLE14_15_CONDITIONS, failing_conditions
from sha256_reduced import smt_characteristic
from sha256_reduced.smt_characteristic import (
    add_rules,
    bool_full_rows,
    bool_rules,
    expansion_rules_method1,
    expansion_rules_method2,
)
from sha256_reduced.smt_value import z3_available


class SatPipelineDataTests(unittest.TestCase):
    def test_addition_signed_difference_table_has_paper_rule_count(self) -> None:
        self.assertEqual(len(add_rules()), 27)

    def test_boolean_fast_tables_are_nonempty(self) -> None:
        self.assertGreater(len(bool_rules("xor3")), 0)
        self.assertGreater(len(bool_rules("if")), 0)
        self.assertGreater(len(bool_rules("maj")), 0)

    def test_addition_rules_are_encoded_as_cnf(self) -> None:
        rules = add_rules()
        cnf = symbol_rules_to_cnf(rules)
        allowed = {symbols_to_assignment(rule) for rule in rules}
        accepted = {assignment for assignment in all_assignments(10) if cnf_accepts(cnf, assignment)}
        self.assertEqual(accepted, allowed)

    def test_boolean_rules_are_encoded_as_cnf(self) -> None:
        for name in ("xor3", "if", "maj"):
            with self.subTest(name=name):
                rules = bool_rules(name)
                cnf = symbol_rules_to_cnf(rules)
                allowed = {symbols_to_assignment(rule) for rule in rules}
                accepted = {assignment for assignment in all_assignments(8) if cnf_accepts(cnf, assignment)}
                self.assertEqual(accepted, allowed)

    def test_full_boolean_if_rows_can_be_encoded_as_cnf(self) -> None:
        rows = bool_full_rows("if")
        from sha256_reduced.cnf import rows_to_cnf

        cnf = rows_to_cnf(rows)
        allowed = set(rows)
        accepted = {assignment for assignment in all_assignments(11) if cnf_accepts(cnf, assignment)}
        self.assertEqual(accepted, allowed)

    def test_expansion_rules_are_encoded_as_cnf(self) -> None:
        for rules, num_vars in ((expansion_rules_method1(), 8), (expansion_rules_method2(), 8)):
            with self.subTest(size=len(rules)):
                cnf = symbol_rules_to_cnf(rules)
                allowed = {symbols_to_assignment(rule) for rule in rules}
                accepted = {assignment for assignment in all_assignments(num_vars) if cnf_accepts(cnf, assignment)}
                self.assertEqual(accepted, allowed)

    def test_table14_15_conditions_hold_for_published_collision(self) -> None:
        self.assertEqual(
            failing_conditions(TABLE14_15_CONDITIONS, _table13_second_block_values()),
            (),
        )

    def test_solver_presence_probe_is_safe_without_z3(self) -> None:
        self.assertIsInstance(z3_available(), bool)

    def test_sha2_a_builder_uses_section2_state_update_formula(self) -> None:
        source = inspect.getsource(smt_characteristic.CharacteristicSearch._build_sha2_a)
        self.assertIn('self.e_rows[i], b8', source)
        self.assertIn('self.a_rows[i - 4], b10, b9', source)

    def test_section_4_1_w_shape_matches_paper(self) -> None:
        self.assertEqual(SECTION_4_1_W_INDICES, frozenset({8, 9, 10, 11, 12, 16, 17, 24, 26}))

    def test_section_4_1_delta_a_zero_range_matches_paper(self) -> None:
        self.assertEqual(list(SECTION_4_1_DELTA_A_ZERO_RANGE), list(range(19, 39)))

    def test_section_4_1_delta_e_zero_range_matches_paper(self) -> None:
        self.assertEqual(list(SECTION_4_1_DELTA_E_ZERO_RANGE), list(range(23, 39)))

if __name__ == "__main__":
    unittest.main()
