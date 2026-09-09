import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudstrike.cli import main
from cloudstrike.report import run_demo
from cloudstrike.verification import ReportVerificationError, verify_report

FIXTURE = Path(__file__).parents[1] / "scenarios" / "iam-passrole" / "inventory.json"


class VerificationTests(unittest.TestCase):
    def test_missing_or_invalid_detections_raise_contract_error(self):
        for value in (None, {}, 1):
            with self.subTest(value=value):
                report = run_demo(FIXTURE)
                report["detections"] = value
                with self.assertRaisesRegex(ReportVerificationError, "detections must be a list"):
                    verify_report(report)
        report = run_demo(FIXTURE)
        del report["detections"]
        with self.assertRaises(ReportVerificationError):
            verify_report(report)

    def test_altered_detection_event_is_rejected(self):
        for field, value in (("actor", "invented-actor"), ("allowed", False)):
            with self.subTest(field=field):
                report = run_demo(FIXTURE)
                report["detections"][0]["event"] = {
                    **report["detections"][0]["event"], field: value,
                }
                with self.assertRaisesRegex(ReportVerificationError, "not present"):
                    verify_report(report)

    def test_replay_requires_consistent_denial_evidence(self):
        for case in ("empty", "success_denied", "blocked_allowed", "reason", "step"):
            with self.subTest(case=case):
                report = run_demo(FIXTURE)
                if case == "empty":
                    report["after"]["events"] = []
                elif case == "success_denied":
                    report["before"]["events"][0]["allowed"] = False
                elif case == "blocked_allowed":
                    report["after"]["events"][-1]["allowed"] = True
                elif case == "reason":
                    report["after"]["events"][-1]["error"] = "different denial"
                else:
                    report["after"]["stopped_at"] = True
                with self.assertRaises(ReportVerificationError):
                    verify_report(report)

    def test_invalid_encoding_is_a_clean_cli_error(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_bytes(b"\xffinvalid")
            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                main(["verify-report", str(path)])
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("encoding", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
