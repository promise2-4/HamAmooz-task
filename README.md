# Access Log Analyzer

A command-line tool for reading Apache/Nginx access logs in Combined Log Format.

I wrote it to handle large files without loading the whole log into memory. Bad lines are counted and skipped, so one broken record does not stop the analysis.

Author: Parmis Hemasian

## Run it

Python 3.11 or newer is enough; there are no third-party dependencies.

```bash
python3 -m log_analyzer path/to/access.log
```

For example:

```bash
python3 -m log_analyzer access.log --top 5
python3 -m log_analyzer access.log --format json
python3 -m log_analyzer access.log.gz
```

To analyze a specific UTC time range:

```bash
python3 -m log_analyzer access.log \
  --from 2026-06-01T05:00:00Z \
  --to 2026-06-01T06:00:00Z
```

`--from` is inclusive and `--to` is exclusive. Both values need a timezone offset or `Z`.

Use `python3 -m log_analyzer --help` to see every option.

## What it reports

- valid and malformed line counts
- unique client IPs
- busiest endpoints
- status-code counts and the combined 4xx/5xx rate
- hourly traffic in UTC
- repeated 401/403 responses on login endpoints
- suspicious request patterns and unusual 5xx periods
- elapsed time and processing speed

Query strings are removed when endpoints are counted, so `/search?q=python` and `/search?q=linux` both count as `/search`. Numeric path parts are left alone because the program cannot safely guess the application's route structure.

## How I broke down the problem

I started with the smallest useful path: read one line, parse it, and update the required counters. Once that worked on the real file, I added malformed-line recovery, text output, and tests. JSON, gzip, time filters, and security checks came after the core report was stable.

The file reader is bounded and streaming. If a line is too large, it drains that line, records `line_too_long`, and starts again at the next physical line. This keeps the parser in sync and keeps memory use predictable.

Each matched record is validated field by field. IP addresses, timestamps, status codes, response sizes, and request lines all have their own checks. Malformed reasons are reported separately instead of being hidden under one generic error.

The main consistency check is:

```text
total_lines == valid_requests + malformed_lines
```

Status and hourly counters are also checked against the selected valid-request count.

## Security checks

The analyzer looks for focused indicators such as path traversal, sensitive-file probes, SQL injection combinations, XSS markers, command injection, unusual methods, and oversized targets. It checks both the raw target and up to two percent-decoded versions.

These are warning signals, not proof of an attack. The rules are kept fairly conservative to avoid flagging harmless requests just because they contain a word like `select` or a semicolon.

Repeated login failures are grouped by IP for `/login`, `/auth`, `/signin`, `/api/login`, and `/api/auth`. The default alert threshold is 10.

## Tests

Run all tests from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

There are 38 tests covering valid and broken log lines, IPv4/IPv6, timestamps, oversized lines, recovery after malformed input, gzip files, JSON output, time filters, security rules, terminal sanitization, and CLI failures.

I also compared reports from the original log and its gzip copy to make sure the actual analysis results were the same.

## Result on the supplied log

The sample contains 500,000 lines (about 58 MB):

```text
Valid requests:      495044
Malformed records:     4956
Unique client IPs:      4001
4xx + 5xx responses:   51075
Error rate:            10.32%
```

All malformed records in this file were non-log garbage lines classified as `format_mismatch`.

One IP had an unusual number of failed login requests:

```text
21.67.75.144 -> 7464 responses with status 401 on /login
```

That may be brute force or simply a broken client. An access log by itself is not enough to decide which.

There was also a 5xx spike at `2026-06-01T05:00:00Z`: 8,983 of 51,002 requests returned a 5xx response (17.61%, compared with a 4.94% global rate).

## Performance

A full run on the supplied file took about 6.3 seconds on my test machine:

```text
79253 lines/second
8.79 MiB/second
```

The exact time depends on the machine and disk. Runtime is linear with the input size. Memory mainly grows with the number of unique IPs and endpoints, not with the total number of lines.

## Project layout

```text
log_analyzer/
  cli.py       command-line arguments and orchestration
  io_utils.py  plain/gzip input and bounded line reading
  parser.py    log parsing and validation
  analyzer.py  counters and consistency checks
  security.py  security and 5xx heuristics
  report.py    text and JSON output

tests/         unit and CLI tests
```

## Limits

The parser expects Combined Log Format, not arbitrary custom Nginx formats. Security signatures can miss attacks or produce false positives, and hourly grouping may hide a short incident. Confirming the cause of a 5xx spike would need application logs, traces, or stack traces as well.
