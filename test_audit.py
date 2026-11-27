"""验证静态审计的覆盖判定与评审更正流程。"""
import copy
import json
from pathlib import Path
import re
import unittest

from audit import audit, apply_corrections
from records_view import load_sources

RECORDS = Path(__file__).with_name("records")


def path_by_id(report, path_id):
    return next(path for path in report["paths"] if path["path_id"] == path_id)


def conditions_by_id(path):
    return {condition["id"]: condition for condition in path["conditions"]}


class BaseReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = load_sources(RECORDS)
        cls.report = audit(cls.sources)

    def test_every_declared_read_statement_and_variant_is_examined(self):
        expected = set()
        for row in self.sources["reads"]:
            if "reads" not in row:
                continue
            for variant in row.get("path_entries") or ["legacy"]:
                expected.add(f"{row['node']}@{row['version']}/{variant}")
        self.assertEqual({path["path_id"] for path in self.report["paths"]}, expected)

    def test_checks_are_resolved_through_node_references(self):
        path = path_by_id(self.report, "R1@r2/full")
        self.assertEqual(conditions_by_id(path)["check_ref"]["status"], "pass")

    def test_whole_frame_bound_does_not_cover_subsection_read(self):
        path = path_by_id(self.report, "R1@r1/legacy")
        scope = conditions_by_id(path)["scope"]
        self.assertEqual(scope["status"], "fail")
        self.assertIn("part", scope["detail"])

    def test_unit_mismatch_blocks_coverage(self):
        path = path_by_id(self.report, "R1@r1/legacy")
        self.assertEqual(conditions_by_id(path)["unit"]["status"], "fail")
        self.assertEqual(path["status"], "unsupported")

    def test_offset_comparison_alone_is_not_length_coverage(self):
        for path in self.report["paths"]:
            condition = conditions_by_id(path)["variable"]
            self.assertEqual(condition["status"], "unknown")
            self.assertIn("长度比较", condition["missing_basis"])

    def test_check_missing_from_variant_is_reported(self):
        path = path_by_id(self.report, "R1@r2/legacy")
        self.assertEqual(conditions_by_id(path)["presence"]["status"], "fail")

    def test_incomplete_proof_is_not_treated_as_coverage(self):
        for path_id in ("R1@r2/legacy", "R1@r2/full"):
            path = path_by_id(self.report, path_id)
            self.assertEqual(conditions_by_id(path)["proof"]["status"], "fail")

    def test_outer_length_dependency_needs_explicit_reference(self):
        path = path_by_id(self.report, "R1@r2/full")
        self.assertEqual(conditions_by_id(path)["outer_length"]["status"], "unknown")

    def test_fixed_buffer_limit_is_only_claimed_when_referenced(self):
        path = path_by_id(self.report, "R1@r2/legacy")
        self.assertEqual(conditions_by_id(path)["fixed_buffer"]["status"], "unknown")
        new_path = path_by_id(self.report, "R1@r2/full")
        self.assertEqual(
            conditions_by_id(new_path)["fixed_buffer"]["status"], "not_applicable")

    def test_inactive_claim_is_not_a_build_proof(self):
        path = path_by_id(self.report, "R1@r2/full")
        self.assertEqual(conditions_by_id(path)["build"]["status"], "fail")

    def test_missing_call_graph_is_named(self):
        codes = {(item["code"], item["basis"]) for item in self.report["missing_evidence"]}
        self.assertIn(
            ("F-CALLGRAPH", "缺少调用者、调用点或守卫关系"), codes)

    def test_unmapped_layout_is_not_silently_proven(self):
        path = path_by_id(self.report, "R1@r2/legacy")
        self.assertEqual(conditions_by_id(path)["layout_resolution"]["status"], "unknown")
        self.assertNotEqual(path["status"], "protected")

    def test_public_interface_layout_gap_is_reported(self):
        ids = {item["id"] for item in self.report["missing_evidence"]}
        self.assertIn("ME-PUBLIC-INTERFACE", ids)

    def test_report_has_no_trigger_bytes(self):
        text = json.dumps(self.report)
        self.assertIsNone(re.search(r"\\x[0-9a-fA-F]{2}", text))
        self.assertIsNone(re.search(r"\b(?:[0-9a-fA-F]{2}[ :]){7}", text))
        self.assertNotIn("payload", text.lower())

    def test_handoff_covers_nothing_protected(self):
        protected = {path["path_id"] for path in self.report["paths"]
                     if path["status"] == "protected"}
        handed = {item["path_id"] for item in self.report["handoff"]}
        self.assertFalse(protected & handed)
        self.assertTrue(self.report["handoff"])


class CorrectionTests(unittest.TestCase):
    def setUp(self):
        self.sources = load_sources(RECORDS)
        self.corrections = {
            "reads": [
                {"id": "check-2", "node": "C2", "bounds": "part", "offset_unit": "bytes",
                 "length_unit": "bytes", "compares": ["offset", "length"],
                 "outer_length_ref": "frame", "max_bytes": 128,
                 "version": "r2", "present_in": ["full", "legacy"]},
                {"id": "read-v2", "node": "R1", "reads": "part", "uses_check": "C2",
                 "length_unit": "bytes", "version": "r2", "proof": "complete",
                 "path_entries": ["legacy", "full"], "call_site": "S1", "guard": "G1"},
            ],
            "layouts": [
                {"id": "layout-new", "kind": "new", "unit": "bytes", "overall_buffer": "frame"},
            ],
            "releases": [
                {"id": "claim-b", "version": "r2", "variant": "full",
                 "normal_layouts": ["new"], "activated": True, "includes_checks": ["C2"],
                 "normal_read": {"layout": "new", "verified": True}},
                {"id": "legacy-r2", "version": "r2", "variant": "legacy", "activated": True,
                 "normal_layouts": ["layout-old"], "includes_checks": ["C2"],
                 "normal_read": {"layout": "old", "verified": True}},
            ],
        }

    def test_corrections_verify_previously_unknown_paths(self):
        report = audit(self.sources, self.corrections)
        for path_id in ("R1@r2/full", "R1@r2/legacy"):
            self.assertEqual(path_by_id(report, path_id)["status"], "protected", path_id)

    def test_uncorrected_legacy_path_remains_handed_off(self):
        report = audit(self.sources, self.corrections)
        self.assertEqual([item["path_id"] for item in report["handoff"]],
                         ["R1@r1/legacy"])

    def test_reported_actions_are_recorded(self):
        report = audit(self.sources, self.corrections)
        actions = report["review"]["corrections_applied"]
        self.assertTrue(any(row["action"] == "replace" for row in actions))
        self.assertTrue(any(row["action"] == "add" for row in actions))

    def test_tampering_with_corrections_does_not_mutate_source(self):
        snapshot = copy.deepcopy(self.sources)
        audit(self.sources, self.corrections)
        self.assertEqual(self.sources, snapshot)

    def test_duplicate_corrected_identifier_rejected(self):
        with self.assertRaises(ValueError):
            apply_corrections(self.sources, {"reads": [{"id": "check-1", "node": "C1"},
                                                        {"id": "check-1", "node": "C1"}]})

    def test_unknown_source_rejected(self):
        with self.assertRaises(ValueError):
            apply_corrections(self.sources, {"firmware": []})


if __name__ == "__main__":
    unittest.main()
