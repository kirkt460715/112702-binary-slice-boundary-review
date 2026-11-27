"""验证静态审计工具的判定规则与资料入口。"""
import json
from pathlib import Path
import tempfile
import unittest

import records_audit
from records_audit import audit
from records_view import load_sources

RECORDS = Path(__file__).with_name("records")


def write_sources(directory, layouts, reads, releases):
    for name, rows in (("layouts", layouts), ("reads", reads), ("releases", releases)):
        (Path(directory) / f"{name}.json").write_text(
            json.dumps(rows, ensure_ascii=False), encoding="utf-8")


def codes(findings, severity=None):
    return {f["code"] for f in findings
            if severity is None or f["severity"] == severity}


def sample_sources(**overrides):
    base = {
        "layouts": [{"id": "layout-old", "kind": "legacy",
                     "buffers": {"frame": "bytes", "part": "bytes"},
                     "segment_max_bytes": {"part": 64}, "public_max_bytes": 128}],
        "reads": [
            {"id": "check-1", "node": "C1", "bounds": "part", "offset_unit": "bytes",
             "version": "r1", "present_in": ["legacy"]},
            {"id": "read-1", "node": "R1", "reads": "part", "uses_check": "C1",
             "length_unit": "bytes", "version": "r1", "proof": "complete",
             "path_entries": ["legacy"]},
        ],
        "releases": [{"id": "deployed", "version": "r1", "variant": "legacy",
                      "activated": True, "normal_layouts": ["layout-old"],
                      "normal_read_results": {"layout-old": "ok"}}],
    }
    base.update(overrides)
    return base


class ActualRecordsTests(unittest.TestCase):
    def setUp(self):
        self.report = audit(load_sources(RECORDS))
        self.paths = {path["id"]: path for path in self.report["read_paths"]}

    def test_report_identifies_both_reads(self):
        self.assertEqual(set(self.paths), {"read-1", "read-v2"})

    def test_report_does_not_output_trigger_bytes(self):
        text = json.dumps(self.report, ensure_ascii=False)
        for word in ("0x", "payload", "bytes_le", "\\x"):
            self.assertNotIn(word, text)

    def test_read1_whole_frame_does_not_cover_segment(self):
        findings = self.paths["read-1"]["findings"]
        self.assertIn("bounds-whole-frame-for-segment", codes(findings, "unsupported"))

    def test_read1_unit_mismatch_blocks_coverage(self):
        self.assertEqual(self.paths["read-1"]["offset_unit"], "bytes")
        self.assertEqual(self.paths["read-1"]["length_unit"], "records")
        self.assertIn("unit-mismatch", codes(self.paths["read-1"]["findings"], "unsupported"))

    def test_read_v2_is_not_activated_build(self):
        self.assertIn("build-not-activated", codes(self.paths["read-v2"]["findings"],
                                                   "not-actual"))

    def test_read_v2_absent_from_legacy_variant(self):
        self.assertIn("check-absent-in-variant",
                      codes(self.paths["read-v2"]["findings"], "unsupported"))

    def test_read_v2_proof_is_incomplete(self):
        self.assertIn("proof-incomplete",
                      codes(self.paths["read-v2"]["findings"], "incomplete"))

    def test_layout_new_does_not_declare_part(self):
        self.assertIn("buffer-undeclared",
                      codes(self.paths["read-v2"]["findings"], "unsupported"))

    def test_statuses_are_open(self):
        self.assertTrue(all(path["status"] == "open" for path in self.report["read_paths"]))
        self.assertTrue(all(rel["status"] == "open" for rel in self.report["releases"]))
        self.assertTrue(self.report["handoff"])

    def test_layout_reports_split_proven_and_unproven(self):
        layouts = {row["id"]: row for row in self.report["layouts"]}
        self.assertTrue(layouts["layout-old"]["proves"])
        self.assertTrue(any("public_max_bytes" in gap
                            for gap in layouts["layout-old"]["gaps"]))
        self.assertTrue(any("子段" in gap for gap in layouts["layout-new"]["gaps"]))

    def test_missing_basis_is_named(self):
        read1 = codes(self.paths["read-1"]["findings"], "unverified")
        self.assertIn("call-path-missing", read1)
        self.assertIn("check-presence-unverified", read1)
        release = {rel["id"]: rel for rel in self.report["releases"]}
        self.assertIn("activation-missing",
                      codes(release["deployed"]["findings"], "unverified"))
        self.assertIn("normal-layouts-missing",
                      codes(release["deployed"]["findings"], "unverified"))


class RuleTests(unittest.TestCase):
    def test_complete_evidence_is_supported(self):
        report = audit(sample_sources())
        self.assertEqual(report["read_paths"][0]["status"], "supported")
        self.assertEqual(report["handoff"], [])

    def test_whole_frame_bound_never_covers_subsegment(self):
        sources = sample_sources()
        sources["reads"][0]["bounds"] = "whole-frame"
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("bounds-whole-frame-for-segment", codes(findings, "unsupported"))

    def test_length_comparison_alone_is_not_coverage(self):
        sources = sample_sources()
        sources["reads"][1]["proof"] = "partial"
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("proof-incomplete", codes(findings, "incomplete"))

    def test_unit_mismatch_is_unsupported(self):
        sources = sample_sources()
        sources["reads"][1]["length_unit"] = "records"
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("unit-mismatch", codes(findings, "unsupported"))

    def test_missing_offset_unit_blocks_comparison(self):
        sources = sample_sources()
        del sources["reads"][0]["offset_unit"]
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("unit-unverified", codes(findings, "unverified"))

    def test_outer_unit_does_not_cover_inner_read(self):
        sources = sample_sources(
            layouts=[{"id": "layout-new", "kind": "new", "unit": "record",
                      "overall_buffer": "frame"}],
            reads=[{"id": "check-2", "node": "C2", "bounds": "frame",
                    "offset_unit": "bytes", "version": "r2", "present_in": ["full"]},
                   {"id": "read-2", "node": "R2", "reads": "part", "uses_check": "C2",
                    "length_unit": "bytes", "version": "r2", "proof": "complete",
                    "path_entries": ["full"]}],
            releases=[{"id": "claim", "version": "r2", "variant": "full",
                       "activated": True, "normal_layouts": ["layout-new"],
                       "normal_read_results": {"layout-new": "ok"}}])
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("buffer-undeclared", codes(findings, "unsupported"))

    def test_public_max_does_not_replace_segment_bound(self):
        sources = sample_sources()
        del sources["layouts"][0]["segment_max_bytes"]
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("segment-bound-missing", codes(findings, "unverified"))

    def test_check_present_in_must_include_variant(self):
        sources = sample_sources()
        sources["reads"][0]["present_in"] = ["full"]
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("check-absent-in-variant", codes(findings, "unsupported"))

    def test_missing_call_path_is_reported(self):
        sources = sample_sources()
        del sources["reads"][1]["path_entries"]
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("call-path-missing", codes(findings, "unverified"))

    def test_missing_normal_read_result_is_reported(self):
        sources = sample_sources()
        del sources["releases"][0]["normal_read_results"]
        findings = audit(sources)["read_paths"][0]["findings"]
        self.assertIn("normal-read-result-missing", codes(findings, "unverified"))

    def test_unresolved_release_is_reported(self):
        sources = sample_sources()
        del sources["releases"][0]["activated"]
        report = audit(sources)
        self.assertIn("build-inclusion-unproven",
                      codes(report["read_paths"][0]["findings"], "unverified"))
        self.assertIn("activation-missing",
                      codes(report["releases"][0]["findings"], "unverified"))
        self.assertTrue(report["handoff"])

    def test_corrected_statements_can_close_all_paths(self):
        sources = sample_sources()
        with tempfile.TemporaryDirectory() as directory:
            write_sources(directory, sources["layouts"], sources["reads"],
                          sources["releases"])
            loaded = load_sources(Path(directory))
        report = audit(loaded)
        self.assertEqual(report["read_paths"][0]["status"], "supported")
        self.assertEqual(report["variants"][0]["status"], "supported")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        import subprocess
        import sys
        script = Path(records_audit.__file__)
        return subprocess.run([sys.executable, str(script), *args],
                              capture_output=True, text=True, check=False)

    def test_cli_reports_open_findings_with_exit_two(self):
        result = self.run_cli("--records", str(RECORDS), "--summary")
        self.assertEqual(result.returncode, 2)
        self.assertIn("待办交接", result.stdout)
        self.assertIn("read-v2", result.stdout)

    def test_cli_json_report_has_handoff(self):
        result = self.run_cli("--records", str(RECORDS))
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertTrue(report["handoff"])
        self.assertEqual({row["id"] for row in report["read_paths"]},
                         {"read-1", "read-v2"})

    def test_cli_corrected_directory_exits_zero(self):
        sources = sample_sources()
        with tempfile.TemporaryDirectory() as directory:
            write_sources(directory, sources["layouts"], sources["reads"],
                          sources["releases"])
            result = self.run_cli("--records", directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["handoff"], [])

    def test_cli_rejects_missing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "layouts.json").write_text("[]", encoding="utf-8")
            result = self.run_cli("--records", directory)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("缺少来源", result.stderr)


if __name__ == "__main__":
    unittest.main()
