from __future__ import annotations

import gzip
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from log_analyzer.io_utils import iter_bounded_lines, open_binary_input


class BoundedReaderTests(unittest.TestCase):
    def test_short_exact_limit_and_final_without_newline(self) -> None:
        records = list(iter_bounded_lines(BytesIO(b"abc\n12345\nlast"), 5))
        self.assertEqual([record.text for record in records], ["abc", "12345", "last"])
        self.assertTrue(all(record.error is None for record in records))

    def test_crlf_exact_limit(self) -> None:
        records = list(iter_bounded_lines(BytesIO(b"12345\r\n"), 5))
        self.assertEqual(records[0].text, "12345")
        self.assertIsNone(records[0].error)

    def test_oversized_line_recovers_at_next_physical_line(self) -> None:
        records = list(iter_bounded_lines(BytesIO(b"x" * 30 + b"\nvalid\n"), 5))
        self.assertEqual(records[0].error, "line_too_long")
        self.assertEqual(records[1].line_number, 2)
        self.assertEqual(records[1].text, "valid")

    def test_invalid_utf8_is_classified(self) -> None:
        record = next(iter_bounded_lines(BytesIO(b"bad\xffline\n"), 20))
        self.assertEqual(record.error, "invalid_encoding")
        self.assertIn("\ufffd", record.text)

    def test_plain_and_gzip_opening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plain = Path(directory, "a.log")
            compressed = Path(directory, "a.log.gz")
            plain.write_bytes(b"plain\n")
            with gzip.open(compressed, "wb") as stream:
                stream.write(b"gzip\n")
            with open_binary_input(plain) as stream:
                self.assertEqual(stream.readline(), b"plain\n")
            with open_binary_input(compressed) as stream:
                self.assertEqual(stream.readline(), b"gzip\n")

    def test_corrupt_gzip_raises(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad.gz")
            path.write_bytes(b"not gzip")
            with self.assertRaises((gzip.BadGzipFile, EOFError, OSError)):
                with open_binary_input(path) as stream:
                    stream.read(1)


if __name__ == "__main__":
    unittest.main()
