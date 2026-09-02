import unittest
from pathlib import Path

from cloudstrike.safety import LabManifest, SafetyViolation, require_lab_tags

FIXTURE = Path(__file__).parent / "fixtures" / "terraform-output.json"


class SafetyTests(unittest.TestCase):
    def test_manifest_accepts_scoped_lab_outputs(self):
        manifest = LabManifest.from_terraform_output(FIXTURE)
        self.assertEqual(manifest.account_id, "123456789012")
        self.assertEqual(len(manifest.allowed_arns), 3)

    def test_manifest_rejects_wrong_caller(self):
        manifest = LabManifest.from_terraform_output(FIXTURE)
        with self.assertRaisesRegex(SafetyViolation, "does not match"):
            manifest.assert_caller("999999999999")

    def test_tags_fail_closed(self):
        with self.assertRaisesRegex(SafetyViolation, "required"):
            require_lab_tags({"Project": "something-else"}, "cloudstrike-lab-iam-passrole")


