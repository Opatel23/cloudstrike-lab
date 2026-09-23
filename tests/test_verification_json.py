import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from cloudstrike.cli import _fixture, main
from cloudstrike.report import run_demo, write_report


class VerificationJSONTests(unittest.TestCase):
    def test_valid_report_returns_machine_readable_evidence(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_report(run_demo(_fixture()), path)
            output = io.StringIO()
            with redirect_stdout(output):
                status = main(["verify-report", str(path), "--json"])
            result = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertIs(result["valid"], True)
            self.assertEqual(result["blocked_at_step"], 2)
            self.assertEqual(len(result["sha256"]), 64)
            self.assertEqual(result["path"], str(path.resolve()))

    def test_invalid_or_missing_report_returns_json_and_failure_status(self):
        for content in (None, "{", "{}"):
            with self.subTest(content=content), TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                output = io.StringIO()
                with redirect_stdout(output):
                    status = main(["verify-report", str(path), "--json"])
                result = json.loads(output.getvalue())
                self.assertEqual(status, 2)
                self.assertIs(result["valid"], False)
                self.assertTrue(result["error"])
                self.assertNotIn("sha256", result)
