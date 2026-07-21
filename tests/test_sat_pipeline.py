from __future__ import annotations

import inspect
import unittest
from unittest.mock import patch

import search_sha256
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
from sha256_reduced.vectors import TABLE_5_39_STEP_SFS


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

    def test_phase1_finds_any_model_then_tightens_weight_bounds(self) -> None:
        class FakeWeight:
            def __le__(self, bound: int) -> tuple[str, int]:
                return ("weight<=", bound)

        class FakeOptimizer:
            @staticmethod
            def assertions() -> tuple[str, ...]:
                return ("base",)

        class FakeSolver:
            def __init__(self) -> None:
                self.results = ["sat", "sat", "unsat"]
                self.weights = [9, 7]
                self.check_index = -1
                self.added: list[object] = []

            def add(self, *constraints: object) -> None:
                self.added.extend(constraints)

            def check(self) -> str:
                self.check_index += 1
                return self.results[self.check_index]

            def model(self) -> int:
                return self.weights[self.check_index]

            @staticmethod
            def reason_unknown() -> str:
                return ""

        fake_solver = FakeSolver()

        class FakeZ3:
            sat = "sat"
            unsat = "unsat"

            @staticmethod
            def Solver() -> FakeSolver:
                return fake_solver

        class FakeSearch:
            z3 = FakeZ3()
            optimizer = FakeOptimizer()
            w = tuple(range(39))

            @staticmethod
            def weight_expr(_words: object) -> FakeWeight:
                return FakeWeight()

            @staticmethod
            def model_weight(model: int, _words: object) -> int:
                return model

        with (
            patch.object(search_sha256, "_build_section_4_1_message_search", return_value=FakeSearch()),
            patch.object(search_sha256, "configure_solver_instance"),
        ):
            result = search_sha256._solve_section_4_1_phase1(1, 1000, 1, object())

        self.assertEqual(result.weight, 7)
        self.assertEqual(result.status, "UNSAT")
        self.assertTrue(result.proven_optimal)
        self.assertEqual(fake_solver.added, ["base", ("weight<=", 8), ("weight<=", 6)])

    def test_solver_status_distinguishes_timeout_from_other_unknown(self) -> None:
        class FakeZ3:
            sat = "sat"
            unsat = "unsat"

        class FakeSolver:
            def __init__(self, reason: str) -> None:
                self.reason = reason

            def reason_unknown(self) -> str:
                return self.reason

        self.assertEqual(
            search_sha256._solver_status(FakeSolver("timeout"), "unknown", FakeZ3()),
            ("TIMEOUT", "timeout"),
        )
        self.assertEqual(
            search_sha256._solver_status(FakeSolver("incomplete theory"), "unknown", FakeZ3()),
            ("UNKNOWN", "incomplete theory"),
        )

    def test_all_section_4_1_phases_use_bounded_sat_search(self) -> None:
        for function in (
            search_sha256._solve_section_4_1_phase1,
            search_sha256._solve_section_4_1_phase2,
            search_sha256._solve_section_4_1_phase3,
        ):
            with self.subTest(function=function.__name__):
                source = inspect.getsource(function)
                self.assertIn("_search_minimum_weight", source)
                self.assertNotIn("minimize_weight", source)

    def test_known_message_characteristic_validation_fixes_every_w_row(self) -> None:
        class FakeSearch:
            def __init__(self) -> None:
                self.constraints: dict[tuple[str, int], str] = {}

            def constrain_word(self, kind: str, index: int, pattern: str) -> None:
                self.constraints[(kind, index)] = pattern

        search = FakeSearch()
        search_sha256._constrain_known_message_characteristic(search, TABLE_5_39_STEP_SFS)

        self.assertEqual(len(search.constraints), 39)
        self.assertEqual(
            {
                index
                for (kind, index), pattern in search.constraints.items()
                if kind == "W" and ("u" in pattern or "n" in pattern)
            },
            SECTION_4_1_W_INDICES,
        )

    def test_phase1_uses_message_schedule_only_model(self) -> None:
        source = inspect.getsource(search_sha256._solve_section_4_1_phase1)
        self.assertIn("_build_section_4_1_message_search", source)
        self.assertNotIn("_build_section_4_1_search(options)", source)

if __name__ == "__main__":
    unittest.main()
