# Access Log Analyzer

A small command-line tool for analyzing Apache/Nginx access logs in Combined Log Format.

The program reads the file one line at a time, skips broken records without stopping the whole run, and prints the traffic statistics that are usually useful during an incident: popular endpoints, status codes, error rate, hourly traffic, repeated login failures, and unusual 5xx periods.

It is written for Python 3.11+ and uses only the standard library.

Author: Parmis Hemasian

## How I approached the problem

I split the task into a few small parts and implemented them in this order:

1. Read the real PDF and inspect the sample log instead of assuming its format.
2. Build a bounded, streaming file reader.
3. Parse and validate one Combined Log Format record at a time.
4. Aggregate the required statistics in the same pass.
5. Add text output and verify it on the real file.
6. Add the optional gzip, JSON, time-filter, and security features.
7. Test malformed input and edge cases separately from the real-log run.

This order kept the mandatory solution working before the optional features were added.

## Running the analyzer

From the repository root:

```bash
python3 -m log_analyzer path/to/access.log
```

For the supplied sample file:

```bash
python3 -m log_analyzer /Users/parmis/Downloads/hamamooz_task/access.log
```

The normal output is a text report. JSON output is also available:

```bash
python3 -m log_analyzer access.log --format json
```

Gzip files can be read directly:

```bash
python3 -m log_analyzer access.log.gz
```

Useful examples:

```bash
# Show only the five busiest endpoints
python3 -m log_analyzer access.log --top 5

# Analyze one UTC hour: start is inclusive, end is exclusive
python3 -m log_analyzer access.log \
  --from 2026-06-01T05:00:00Z \
  --to 2026-06-01T06:00:00Z

# Keep no malformed examples in memory/output
python3 -m log_analyzer access.log --show-invalid 0

# Use a smaller maximum logical line size
python3 -m log_analyzer access.log --max-line-length 32768
```

Time filters must include a UTC offset or `Z` so there is no ambiguity about the timezone.

## Command-line options

```text
input                         path to a plain or .gz access log
--top N                       number of endpoints to show (default: 10)
--format text|json            output format (default: text)
--from DATETIME               inclusive ISO 8601 start time
--to DATETIME                 exclusive ISO 8601 end time
--max-line-length N           maximum logical line bytes (default: 65536)
--show-invalid N              malformed examples to retain (default: 5)
--login-failure-threshold N   repeated login-failure threshold (default: 10)
--spike-min-requests N        minimum requests in a spike hour (default: 20)
--spike-rate-floor PERCENT    minimum hourly 5xx rate (default: 5)
--spike-baseline-factor N     required multiple of the global 5xx rate (default: 3)
```

Exit code `0` means that analysis completed successfully. Malformed records do not make the whole run fail. Invalid arguments, an unreadable file, or a corrupt gzip stream return a non-zero code.

## What the report contains

- total physical lines
- valid and malformed record counts
- malformed counts grouped by reason
- unique client IP count
- endpoint request counts and top N endpoints
- exact status-code and status-class counts
- combined `(4xx + 5xx) / selected valid requests` error rate
- requests grouped by full UTC date and hour
- repeated 401/403 responses on authentication endpoints
- conservative suspicious-request indicators
- suspicious requests associated with 5xx responses
- hourly 5xx spike candidates
- elapsed time, lines per second, and MiB per second

Missing hourly buckets are shown as zero when the time range is reasonably small. This makes a complete traffic gap visible instead of silently omitting it.

## Parsing and malformed input

The reader opens input in binary mode and reads bounded chunks. It never calls `read()`, `readlines()`, or `list(file)` on the complete log.

The default line limit is 64 KiB. If a physical line is larger, the reader drains the rest of that line in bounded chunks, records one `line_too_long` error, and continues from the next line. This is important because simply truncating the line could lose synchronization with the file.

The outer Combined Log Format record is parsed with one precompiled regular expression. Quoted fields support escaped characters, so spaces or escaped quotes in the referrer and user agent do not break field boundaries. The pattern avoids nested greedy `.*` expressions.

After the outer format matches, fields are validated separately:

- IPv4 and IPv6 use `ipaddress.ip_address`.
- timestamps use the documented Combined Log Format and keep their offset.
- status codes must be integers from 100 to 599.
- response size must be a non-negative integer or `-`; `-` becomes `None`.
- request lines must contain a valid method token, a non-empty target, and a supported HTTP protocol.

Malformed reasons are kept separate, for example:

```text
empty_line
line_too_long
null_byte
format_mismatch
invalid_ip
invalid_timestamp
invalid_status
invalid_size
missing_request
invalid_request_line
invalid_method
invalid_protocol
invalid_encoding
unexpected_parse_error
```

Only a small number of malformed examples are retained. Control characters, terminal escape bytes, NUL, tabs, and newlines are escaped before output, so an untrusted log line cannot modify the terminal report.

## Endpoint and time decisions

Query strings are removed for endpoint statistics:

```text
/search?q=python  -> /search
/search?q=linux   -> /search
```

Numeric path components are not generalized. `/products/1877` and `/products/1878` stay separate because the analyzer does not know the application's routing schema.

Request timestamps are converted to UTC before hourly bucketing. The complete date is part of the bucket, so 09:00 on two different days is not merged.

With no time filter, this invariant must always hold:

```text
total_lines == valid_requests + malformed_lines
```

Status and hourly counters must also sum to the selected valid request count.

## Security checks

The security part is intentionally small. This project is a log analyzer, not a WAF or IDS.

The request target is checked in its raw form and after at most two percent-decoding passes. The implemented categories include:

- path traversal
- sensitive-file and administration probes
- focused SQL injection combinations
- common XSS markers
- command-injection combinations
- unusual but syntactically valid HTTP methods
- abnormally long targets or user agents
- control characters

The rules avoid obvious broad matches. For example, the word `select` by itself is not treated as SQL injection, and a semicolon by itself is not treated as command injection.

Repeated 401/403 responses are counted by IP for `/login`, `/auth`, `/signin`, `/api/login`, and `/api/auth`. The default threshold is 10.

An hourly 5xx bucket is flagged only if it has enough requests, exceeds the absolute 5xx floor, and is sufficiently above the global 5xx baseline. These are heuristics, not proof of an attack or crash.

Access logs cannot prove that a request caused a crash. Confirming causality would require application logs, stack traces, traces, request IDs, and process or host telemetry.

## Tests

Run the complete suite with:

```bash
python3 -m unittest discover -s tests -v
```

The current suite has 38 tests. It covers:

- valid IPv4 and IPv6 records
- response size as a number or `-`
- quoted fields containing spaces and escaped quotes
- query strings, absolute targets, and `OPTIONS *`
- invalid IP, timestamp, status, size, method, and protocol
- empty, truncated, NUL-containing, and malformed records
- exact-limit and oversized lines
- recovery when a valid line follows an oversized line
- invalid UTF-8
- plain and gzip input, including corrupt gzip data
- exact counters, error rate, UTC buckets, and time filters
- empty and malformed-only files
- valid JSON output
- positive and negative security cases
- login-failure thresholds and bounded security samples
- terminal-output sanitization
- CLI text, JSON, gzip, mixed, and oversized-input runs

I also ran the analyzer on the real 500,000-line sample and compressed the same sample to verify that plain and gzip input produce equivalent report data.

## Real sample result

The supplied file is 58,180,735 bytes and contains 500,000 physical lines.

```text
Valid requests:                  495044
Malformed records:                4956
Unique client IPs:                4001
Combined 4xx + 5xx responses:    51075
Error rate:                     10.32%
```

All 4,956 malformed records were outer-format garbage lines classified as `format_mismatch`. Representative samples were inspected to make sure valid Combined Log records were not being rejected.

No request-target signatures for traversal, SQL injection, XSS, or command injection were found in the sample.

One source stood out in the authentication results:

```text
21.67.75.144 -> 7464 responses with status 401 on /login
```

This is suspicious and could be brute force or a broken client, but the access log alone cannot tell which.

The analyzer also found one hourly 5xx spike at `2026-06-01T05:00:00Z`:

```text
8983 / 51002 requests were 5xx
hourly 5xx rate: 17.61%
global 5xx rate:  4.94%
```

The final hour ends at 09:43, so its lower request count should be treated as an incomplete final bucket rather than definite traffic loss.

## Performance

The program measures every run with `time.perf_counter()` and includes the result in both text and JSON output.

A recent full run on the supplied file produced:

```text
Elapsed:    6.308858 seconds
Throughput: 79253.64 lines/second
Throughput: 8.79 MiB/second
```

The exact number varies with the machine and current load, but the complete 500,000-line analysis is consistently in the range of a few seconds on this system.

## Complexity

The main pass is linear in the input size: `O(number of input bytes)`.

The analyzer does not keep every parsed request. Exact memory use mainly comes from:

- the unique-IP set
- the endpoint counter
- hourly and status counters
- small security counters
- bounded malformed and suspicious examples

At much larger scale, HyperLogLog or heavy-hitter sketches could reduce memory, but they would make results approximate. Exact counting was appropriate for this task and sample.

## Project layout

```text
log_analyzer/
  __main__.py     module entry point
  cli.py          arguments, orchestration, and exit codes
  io_utils.py     plain/gzip input and bounded line reading
  parser.py       Combined Log Format parsing and validation
  models.py       data models
  analyzer.py     streaming aggregation and invariants
  security.py     request and 5xx heuristics
  report.py       text/JSON rendering and sanitization

tests/
  test_parser.py
  test_io_utils.py
  test_analyzer.py
  test_security.py
  test_report.py
  test_cli.py
```

## One implementation issue I had to solve

The tricky part of the bounded reader was deciding whether a line exactly at the limit was valid while still supporting both LF and CRLF. It also had to discard a huge line without consuming the next valid record.

The final reader requests at most `limit + 2` bytes, removes the physical line terminator before checking the logical length, and drains an oversized line until its newline. Tests cover exact-limit LF/CRLF, final lines without a newline, and an oversized line followed by a valid one.

## Known limitations

- Only Combined Log Format is supported, not arbitrary custom Nginx formats.
- Exact IP and endpoint counters grow with the number of distinct values.
- Authentication endpoints use a small configured set rather than automatic route discovery.
- Security signatures can have false positives and false negatives.
- Hourly spike detection may miss a short minute-level incident.
- The analyzer cannot inspect request bodies, application exceptions, or trace context.
