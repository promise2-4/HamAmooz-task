from __future__ import annotations

import unittest
from collections import Counter
from datetime import datetime, timezone

from log_analyzer.models import LogEntry
from log_analyzer.security import detect_request_indicators, detect_server_error_spikes


def entry(target: str = "/safe", *, method: str = "GET", agent: str = "agent") -> LogEntry:
    return LogEntry(
        ip="192.0.2.1",
        remote_identity="-",
        authenticated_user="-",
        timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
        method=method,
        raw_target=target,
        endpoint=target.split("?", 1)[0],
        protocol="HTTP/1.1",
        status=200,
        response_size=1,
        referrer="-",
        user_agent=agent,
    )


class SecurityTests(unittest.TestCase):
    def categories(self, target: str, **kwargs: str) -> set[str]:
        return set(detect_request_indicators(entry(target, **kwargs)))

    def test_plain_request_is_not_flagged(self) -> None:
        self.assertEqual(detect_request_indicators(entry()), ())

    def test_path_traversal_plain_encoded_and_double_encoded(self) -> None:
        for target in ("/../../etc/passwd", "/%2e%2e/etc/passwd", "/%252e%252e/etc/passwd"):
            with self.subTest(target=target):
                self.assertIn("path_traversal", self.categories(target))

    def test_sensitive_sql_xss_and_command_indicators(self) -> None:
        self.assertIn("sensitive_file_probe", self.categories("/.env"))
        self.assertIn("sql_injection", self.categories("/search?q=1%20UNION%20SELECT%20x"))
        self.assertIn("xss", self.categories("/search?q=%3Cscript%3E"))
        self.assertIn("command_injection", self.categories("/run?x=;%20wget%20example"))

    def test_focused_patterns_avoid_broad_false_positives(self) -> None:
        self.assertNotIn("sql_injection", self.categories("/books?title=select"))
        self.assertNotIn("command_injection", self.categories("/notes?value=a;b"))

    def test_unusual_method_and_controls(self) -> None:
        self.assertIn("unusual_method", self.categories("/", method="PROPFIND"))
        self.assertIn("terminal_control", self.categories("/bad\x1btarget"))

    def test_spike_rule_and_zero_baseline(self) -> None:
        hour = datetime(2026, 6, 1, tzinfo=timezone.utc)
        spikes = detect_server_error_spikes(
            Counter({hour: 100}), Counter({hour: 20}), global_5xx_rate=5.0
        )
        self.assertEqual(len(spikes), 1)
        zero = detect_server_error_spikes(
            Counter({hour: 100}), Counter(), global_5xx_rate=0.0
        )
        self.assertEqual(zero, ())


if __name__ == "__main__":
    unittest.main()
