import unittest
from pathlib import Path

from cloudstrike.cloudtrail import ingest_cloudtrail
from cloudstrike.safety import LabManifest


FIXTURES = Path(__file__).parent / "fixtures"


class CloudTrailTests(unittest.TestCase):
    def test_ingestion_scopes_and_redacts(self):
        manifest = LabManifest.from_terraform_output(FIXTURES / "terraform-output.json")
        events = ingest_cloudtrail(FIXTURES / "cloudtrail.json", manifest)
        self.assertEqual([event["event_id"] for event in events], ["evt-1", "evt-2"])
        self.assertNotIn("secretString", events[1]["request_parameters"])

