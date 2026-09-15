import json
import unittest
from pathlib import Path

from cloudstrike.cli import _fixture
from cloudstrike.report import run_demo
from cloudstrike.verification import verify_report


class PackagedScenarioTests(unittest.TestCase):
    def test_bundled_scenario_matches_editable_scenario(self):
        source = Path(__file__).parents[1] / "scenarios" / "iam-passrole" / "inventory.json"
        self.assertEqual(
            json.loads(_fixture().read_text(encoding="utf-8")),
            json.loads(source.read_text(encoding="utf-8")),
        )

    def test_bundled_scenario_produces_verified_report(self):
        report = run_demo(_fixture())
        verify_report(report)
        self.assertEqual(report["summary"]["before"], "SUCCESS")
        self.assertEqual(report["summary"]["after"], "BLOCKED")
