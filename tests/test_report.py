from __future__ import annotations

import tempfile
import unittest
import json
from datetime import datetime, timezone
from pathlib import Path

from log_analyzer.analyzer import analyze_path
from log_analyzer.report import hourly_series, render_json, render_text, sanitize_text


class ReportTests(unittest.TestCase):
    def test_sanitization_escapes_controls(self) -> None:
        result = sanitize_text("before\x1b[31m\n\x00after")
        self.assertNotIn("\x1b", result)
        self.assertNotIn("\x00", result)
        self.assertIn(r"\x1b", result)
        self.assertIn(r"\x00", result)

    def test_missing_hours_are_filled_with_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "access.log")
            path.write_text(
                '192.0.2.1 - - [01/Jun/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "a"\n'
                '192.0.2.1 - - [01/Jun/2026:02:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "a"\n'
            )
            result = analyze_path(path)
        series = hourly_series(result)
        self.assertEqual(len(series), 3)
        self.assertEqual(series[1][1], 0)
        self.assertEqual(series[1][0], datetime(2026, 6, 1, 1, tzinfo=timezone.utc))

    def test_empty_report_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "empty.log")
            path.touch()
            output = render_text(analyze_path(path))
        self.assertIn("No requests", output)
        self.assertIn("Error rate: 0.00%", output)

    def test_json_report_is_valid_for_empty_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "empty.log")
            path.touch()
            document = json.loads(render_json(analyze_path(path)))
        self.assertEqual(document["summary"]["valid_requests"], 0)
        self.assertIsInstance(document["summary"]["error_rate_percent"], float)


if __name__ == "__main__":
    unittest.main()
