from __future__ import annotations

import tempfile
import unittest
import gzip
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from log_analyzer.cli import main


class CliSmokeTests(unittest.TestCase):
    def test_existing_file_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "access.log")
            path.touch()
            stdout = StringIO()
            with redirect_stdout(stdout):
                result = main([str(path)])
            self.assertEqual(result, 0)
            self.assertIn("Access Log Analysis", stdout.getvalue())

    def test_missing_file_returns_nonzero(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            result = main(["does-not-exist.log"])
        self.assertNotEqual(result, 0)
        self.assertIn("input file not found", stderr.getvalue())

    def test_json_gzip_and_custom_top(self) -> None:
        content = (
            b'192.0.2.1 - - [01/Jun/2026:00:00:00 +0000] '
            b'"GET /a HTTP/1.1" 200 1 "-" "agent"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "access.log.gz")
            with gzip.open(path, "wb") as stream:
                stream.write(content)
            stdout = StringIO()
            with redirect_stdout(stdout):
                result = main([str(path), "--format", "json", "--top", "1"])
        self.assertEqual(result, 0)
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["top_endpoints"][0]["endpoint"], "/a")

    def test_time_filter(self) -> None:
        content = (
            '192.0.2.1 - - [01/Jun/2026:00:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "agent"\n'
            '192.0.2.2 - - [01/Jun/2026:01:00:00 +0000] "GET /b HTTP/1.1" 200 1 "-" "agent"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "access.log")
            path.write_text(content)
            stdout = StringIO()
            with redirect_stdout(stdout):
                result = main(
                    [
                        str(path),
                        "--format",
                        "json",
                        "--from",
                        "2026-06-01T01:00:00Z",
                    ]
                )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["summary"]["selected_requests"], 1)


if __name__ == "__main__":
    unittest.main()
