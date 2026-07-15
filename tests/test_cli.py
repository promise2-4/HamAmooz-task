from __future__ import annotations

import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
