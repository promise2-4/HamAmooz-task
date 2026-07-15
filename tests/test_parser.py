from __future__ import annotations

import unittest
from datetime import timedelta

from log_analyzer.parser import LogParseError, normalize_endpoint, parse_line


def line(
    *,
    ip: str = "203.0.113.42",
    timestamp: str = "01/Jun/2026:09:14:22 +0330",
    request: str = "GET /products/1877?q=one HTTP/1.1",
    status: str = "200",
    size: str = "5324",
    referrer: str = "https://example.test/from here",
    agent: str = "Mozilla/5.0 Test Agent",
) -> str:
    return (
        f'{ip} - user [{timestamp}] "{request}" {status} {size} '
        f'"{referrer}" "{agent}"'
    )


class ParserTests(unittest.TestCase):
    def assert_reason(self, expected: str, value: str) -> None:
        with self.assertRaises(LogParseError) as raised:
            parse_line(value)
        self.assertEqual(raised.exception.reason, expected)

    def test_valid_combined_line_and_query_endpoint(self) -> None:
        entry = parse_line(line())
        self.assertEqual(entry.ip, "203.0.113.42")
        self.assertEqual(entry.endpoint, "/products/1877")
        self.assertEqual(entry.raw_target, "/products/1877?q=one")
        self.assertEqual(entry.response_size, 5324)
        self.assertEqual(entry.timestamp.utcoffset(), timedelta(hours=3, minutes=30))
        self.assertIn("from here", entry.referrer)
        self.assertIn("Test Agent", entry.user_agent)

    def test_ipv6_and_unknown_size(self) -> None:
        entry = parse_line(line(ip="2001:db8::1", size="-"))
        self.assertEqual(entry.ip, "2001:db8::1")
        self.assertIsNone(entry.response_size)

    def test_escaped_quote_in_quoted_field(self) -> None:
        entry = parse_line(line(agent=r'Agent \"quoted\" value'))
        self.assertEqual(entry.user_agent, 'Agent "quoted" value')

    def test_absolute_form_and_options_asterisk(self) -> None:
        absolute = parse_line(
            line(request="GET https://example.test/a/b?secret=x HTTP/1.1")
        )
        options = parse_line(line(request="OPTIONS * HTTP/2"))
        self.assertEqual(absolute.endpoint, "/a/b")
        self.assertEqual(options.endpoint, "*")

    def test_numeric_ids_are_not_merged(self) -> None:
        self.assertNotEqual(
            normalize_endpoint("/products/1877"),
            normalize_endpoint("/products/1878"),
        )

    def test_unusual_valid_method_is_accepted(self) -> None:
        self.assertEqual(parse_line(line(request="PROPFIND / HTTP/1.1")).method, "PROPFIND")

    def test_malformed_categories(self) -> None:
        cases = {
            "empty_line": "",
            "null_byte": line(agent="bad\x00agent"),
            "format_mismatch": line()[:-1],
            "invalid_ip": line(ip="999.1.1.1"),
            "invalid_timestamp": line(timestamp="32/Jun/2026:09:14:22 +0000"),
            "invalid_status": line(status="700"),
            "invalid_size": line(size="-2"),
            "missing_request": line(request="-"),
            "invalid_request_line": line(request="GET /missing-protocol"),
            "invalid_method": line(request="BAD@METHOD / HTTP/1.1"),
            "invalid_protocol": line(request="GET / FTP/1.0"),
        }
        for reason, value in cases.items():
            with self.subTest(reason=reason):
                self.assert_reason(reason, value)

    def test_invalid_timezone_is_rejected(self) -> None:
        self.assert_reason(
            "invalid_timestamp", line(timestamp="01/Jun/2026:09:14:22 +2500")
        )


if __name__ == "__main__":
    unittest.main()
