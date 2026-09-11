import io
import json
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cloudstrike.cli import main
from cloudstrike.report import write_report


class ReportIOTests(unittest.TestCase):
    def test_save_replaces_report_with_portable_json(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "report.json"
            write_report({"old": True}, output)
            write_report({"new": True}, output)
            self.assertEqual(json.loads(output.read_bytes()), {"new": True})
            self.assertNotIn(b"\r", output.read_bytes())
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_failed_replace_preserves_previous_report_and_cleans_temporary(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_bytes(b"previous report")
            with patch.object(Path, "replace", side_effect=PermissionError("file is locked")):
                with self.assertRaises(PermissionError):
                    write_report({"new": True}, output)
            self.assertEqual(output.read_bytes(), b"previous report")
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_invalid_json_value_does_not_touch_previous_report(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_bytes(b"previous report")
            with self.assertRaises(ValueError):
                write_report({"invalid": float("nan")}, output)
            self.assertEqual(output.read_bytes(), b"previous report")
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_bad_fixture_gives_clean_cli_error_and_preserves_report(self):
        for content in (None, "{", "{}", "[]", '{"nodes": null}'):
            with self.subTest(content=content), TemporaryDirectory() as directory:
                fixture = Path(directory) / "inventory.json"
                output = Path(directory) / "report.json"
                output.write_bytes(b"previous report")
                if content is not None:
                    fixture.write_text(content, encoding="utf-8")
                stderr = io.StringIO()
                with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                    main(["demo", "--fixture", str(fixture), "--output", str(output)])
                self.assertEqual(caught.exception.code, 2)
                self.assertIn("demo failed", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertEqual(output.read_bytes(), b"previous report")
