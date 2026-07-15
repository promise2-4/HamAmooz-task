from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from log_analyzer.analyzer import AnalyzerOptions, analyze_path


def valid(
    ip: str, timestamp: str, target: str = "/", status: int = 200
) -> str:
    return (
        f'{ip} - - [{timestamp}] "GET {target} HTTP/1.1" '
        f'{status} 10 "-" "agent"'
    )


class AnalyzerTests(unittest.TestCase):
    def analyze(self, content: bytes, options: AnalyzerOptions | None = None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "access.log")
            path.write_bytes(content)
            return analyze_path(path, options)

    def test_counts_rates_endpoints_and_invariants(self) -> None:
        content = "\n".join(
            [
                valid("192.0.2.1", "01/Jun/2026:00:10:00 +0000", "/a?q=1", 200),
                valid("192.0.2.1", "01/Jun/2026:00:20:00 +0000", "/a?q=2", 404),
                valid("192.0.2.2", "01/Jun/2026:02:00:00 +0000", "/b", 500),
                "broken",
            ]
        ).encode()
        result = self.analyze(content)
        self.assertEqual(result.total_lines, 4)
        self.assertEqual(result.valid_requests, 3)
        self.assertEqual(result.malformed_lines, 1)
        self.assertEqual(result.unique_ip_count, 2)
        self.assertEqual(result.endpoint_counts["/a"], 2)
        self.assertEqual(result.endpoint_counts.most_common(1), [("/a", 2)])
        self.assertEqual(result.status_class_counts["4xx"], 1)
        self.assertEqual(result.status_class_counts["5xx"], 1)
        self.assertAlmostEqual(result.error_rate, 2 / 3 * 100)
        self.assertEqual(sum(result.status_counts.values()), result.selected_requests)
        self.assertEqual(sum(result.hourly_counts.values()), result.selected_requests)

    def test_utc_buckets_keep_days_separate(self) -> None:
        content = "\n".join(
            [
                valid("192.0.2.1", "01/Jun/2026:02:15:00 +0200"),
                valid("192.0.2.1", "02/Jun/2026:00:15:00 +0000"),
            ]
        ).encode()
        result = self.analyze(content)
        self.assertEqual(len(result.hourly_counts), 2)
        self.assertEqual(
            result.hourly_counts[datetime(2026, 6, 1, tzinfo=timezone.utc)], 1
        )

    def test_empty_and_malformed_only_have_zero_rate(self) -> None:
        empty = self.analyze(b"")
        malformed = self.analyze(b"broken\n")
        self.assertEqual(empty.error_rate, 0.0)
        self.assertEqual(malformed.selected_requests, 0)
        self.assertEqual(malformed.error_rate, 0.0)

    def test_time_filter_is_inclusive_from_exclusive_to(self) -> None:
        content = "\n".join(
            [
                valid("192.0.2.1", "01/Jun/2026:00:00:00 +0000"),
                valid("192.0.2.2", "01/Jun/2026:01:00:00 +0000"),
                valid("192.0.2.3", "01/Jun/2026:02:00:00 +0000"),
            ]
        ).encode()
        options = AnalyzerOptions(
            from_time=datetime(2026, 6, 1, 1, tzinfo=timezone.utc),
            to_time=datetime(2026, 6, 1, 2, tzinfo=timezone.utc),
        )
        result = self.analyze(content, options)
        self.assertEqual(result.valid_requests, 3)
        self.assertEqual(result.selected_requests, 1)
        self.assertEqual(result.filtered_out_requests, 2)


if __name__ == "__main__":
    unittest.main()
