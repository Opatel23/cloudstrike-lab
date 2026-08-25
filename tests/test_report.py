import unittest
from pathlib import Path

from cloudstrike.report import run_demo


FIXTURE = Path(__file__).parents[1] / "scenarios" / "iam-passrole" / "inventory.json"


class ReportTests(unittest.TestCase):
    def test_end_to_end_before_after_proof(self):
        report = run_demo(FIXTURE)
        self.assertEqual(report["summary"]["before"], "SUCCESS")
        self.assertEqual(report["summary"]["after"], "BLOCKED")
        self.assertEqual(report["summary"]["blocked_at_step"], 2)
        self.assertEqual(report["summary"]["detections_triggered"], 2)
        self.assertIn("capability", {node["kind"] for node in report["inventory"]["nodes"]})
        self.assertEqual(
            report["remediation"]["remove_actions"],
            ["iam:PassRole", "lambda:CreateFunction"],
        )
