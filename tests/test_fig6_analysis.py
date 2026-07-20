from __future__ import annotations

from collections import Counter
import unittest

from sha256_reduced.fig6 import FIG6_CONDITIONS, FIG6_HASH
from sha256_reduced.fig6_analysis import (
    add_component_condition_branch,
    analyze_fig6,
    condition_key,
    fig6_witness,
    local_condition_branches,
    modular_addition_sources,
    symbolic_condition_branches,
    symbolic_boolean_sources,
    symbolic_component_transitions,
    witness_matches_characteristic,
)


EXPECTED_FIG6_BOOLEAN_GAPS = {
    "W20[4] == W20[6]",
    "W20[31] == W20[22]",
    "E7[21] != E7[3]",
    "E7[10] != E7[15]",
    "A14[18] == A14[6]",
    "A14[8] == A14[17]",
    "A15[29] == A6[29]",
}

EXPECTED_SYMBOLIC_BOOLEAN_GAPS = {
    "W20[4] == W20[6]",
    "W20[31] == W20[22]",
    "A15[29] == A6[29]",
}

EXPECTED_EQUATION_RESOLVED_GAPS = {
    "W7[22] != W7[18]",
    "W7[13] != W7[9]",
    "W7[23] != W7[8]",
    "W7[11] == W7[22]",
    "W7[14] == W7[31]",
    "W7[20] == W7[31]",
    "W20[4] == W20[6]",
    "W20[31] == W20[22]",
    "W20[31] != W20[1]",
    "W20[30] != W20[0]",
    "W20[25] != W20[16]",
    "W20[21] != W20[14]",
    "E7[21] != E7[3]",
    "E7[10] != E7[15]",
    "A3[4] == A4[4]",
    "A3[18] != A4[18]",
    "A14[18] == A14[6]",
    "A14[8] == A14[17]",
    "A15[29] == A6[29]",
}


class Fig6AnalysisTests(unittest.TestCase):
    def test_fig6_witness_matches_published_characteristic_and_hash(self) -> None:
        witness = fig6_witness()
        self.assertTrue(witness_matches_characteristic(witness))
        self.assertEqual(witness.collision_hash, FIG6_HASH)

    def test_published_witness_misses_the_same_seven_conditions_as_the_boolean_analysis_gap(self) -> None:
        witness = fig6_witness()
        failing: set[str] = set()
        for condition in FIG6_CONDITIONS:
            left_word = witness.left[(condition.left.kind, condition.left.index)]
            right_word = witness.left[(condition.right.kind, condition.right.index)]
            left_bit = (left_word >> condition.left.bit) & 1
            right_bit = (right_word >> condition.right.bit) & 1
            holds = (left_bit == right_bit) if condition.op == "==" else (left_bit != right_bit)
            if not holds:
                failing.add(str(condition))
        self.assertEqual(failing, EXPECTED_FIG6_BOOLEAN_GAPS)

    def test_symbolic_component_analysis_does_not_use_the_collision_witness(self) -> None:
        transitions = symbolic_component_transitions()
        self.assertEqual(len(transitions), 5696)
        if_output = next(transition for transition in transitions if transition.source == "IF@5[29]")
        self.assertEqual(if_output.input_pattern, "n==")
        self.assertEqual(set(if_output.output_symbols), {"n", "u", "0", "1"})

    def test_symbolic_branch_can_be_attached_to_the_value_model(self) -> None:
        from sha256_reduced.smt_value import Sha256ValueModel
        from sha256_reduced.fig6 import FIG6_MESSAGE, FIG6_MESSAGE_PRIME

        branch = next(
            branch
            for branch in symbolic_condition_branches()
            if branch.transition.source == "sigma0(W4)[26]" and branch.output_symbol == "u"
        )
        model = Sha256ValueModel(35, prefix="branch_test")
        witness = fig6_witness()
        model.fix_cv(witness.cv)
        model.fix_left_block(FIG6_MESSAGE_PRIME)
        model.fix_right_block(FIG6_MESSAGE)
        add_component_condition_branch(model, branch)
        self.assertEqual(model.solver.check(), model.z3.sat)

    def test_local_tables_have_seventy_fig6_candidate_conditions(self) -> None:
        keys = {
            condition_key(condition)
            for branch in local_condition_branches()
            for condition in branch.conditions
        }
        recovered = {condition_key(condition) for condition in FIG6_CONDITIONS if condition_key(condition) in keys}
        missing = {str(condition) for condition in FIG6_CONDITIONS if condition_key(condition) not in keys}
        self.assertEqual(len(recovered), 70)
        self.assertEqual(missing, EXPECTED_SYMBOLIC_BOOLEAN_GAPS)

    def test_complete_equations_filter_ambiguous_component_conditions(self) -> None:
        sources = symbolic_boolean_sources()
        recovered = {condition_key(condition) for condition in FIG6_CONDITIONS if condition_key(condition) in sources}
        missing = {str(condition) for condition in FIG6_CONDITIONS if condition_key(condition) not in sources}
        self.assertEqual(len(recovered), 54)
        self.assertEqual(missing, EXPECTED_EQUATION_RESOLVED_GAPS)

    def test_modular_addition_table_is_applied_to_all_update_stages(self) -> None:
        sources = modular_addition_sources()
        self.assertGreater(len(sources), 0)
        self.assertIn(
            (("W", 6, 29), "==", ("W", 22, 29)),
            sources,
        )

    def test_fig6_report_can_skip_full_model_and_still_classify_missing_conditions(self) -> None:
        report = analyze_fig6(run_full_model=False)
        self.assertTrue(report.witness_matches_characteristic)
        self.assertTrue(report.witness_is_collision)
        self.assertEqual(report.full_model_satisfiable, "skipped")
        self.assertEqual(Counter(result.source for result in report.conditions), Counter({"component": 54, "missing": 19}))
        self.assertEqual({str(result.condition) for result in report.conditions if not result.witness_holds}, EXPECTED_FIG6_BOOLEAN_GAPS)


if __name__ == "__main__":
    unittest.main()
