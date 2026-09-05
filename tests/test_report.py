import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudstrike.cli import main
from cloudstrike.report import run_demo
from cloudstrike.verification import ReportVerificationError, verify_report

FIXTURE = Path(__file__).parents[1] / "scenarios" / "iam-passrole" / "inventory.json"


class ReportTests(unittest.TestCase):
    def test_demo_report_is_deterministic(self):
        self.assertEqual(run_demo(FIXTURE), run_demo(FIXTURE))

    def test_end_to_end_before_after_proof(self):
        report = run_demo(FIXTURE)
        self.assertEqual(report["summary"]["before"], "SUCCESS")
        self.assertEqual(report["summary"]["after"], "BLOCKED")
        self.assertEqual(report["summary"]["blocked_at_step"], 2)
        self.assertEqual(report["summary"]["detections_triggered"], 2)
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(
            report["provenance"],
            {
                "generator": "cloudstrike-engine",
                "mode": "controlled-local-simulation",
                "fixture": "inventory.json",
                "live_aws_actions": 0,
            },
        )
        self.assertIn("capability", {node["kind"] for node in report["inventory"]["nodes"]})
        self.assertEqual(
            report["remediation"]["remove_actions"],
            ["iam:PassRole", "lambda:CreateFunction"],
        )

    def test_report_contract_accepts_demo_report(self):
        verify_report(run_demo(FIXTURE))

    def test_report_contract_rejects_live_action_claim(self):
        report = run_demo(FIXTURE)
        report["provenance"]["live_aws_actions"] = 1
        with self.assertRaisesRegex(ReportVerificationError, "live AWS actions"):
            verify_report(report)

    def test_report_contract_rejects_inconsistent_path(self):
        report = run_demo(FIXTURE)
        tampered = deepcopy(report)
        tampered["attack_path"]["nodes"][-1] = "secret:missing"
        with self.assertRaisesRegex(ReportVerificationError, "absent from inventory"):
            verify_report(tampered)

    def test_verify_report_cli_returns_success(self):
        with TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report_path.write_text(
                Path(__file__).parents[1].joinpath("outputs", "demo-report.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            self.assertEqual(main(["verify-report", str(report_path)]), 0)
