# SCRIPT-1/2/3 — Browser-generated, user-run Python test sender (2026-10-18)

## Product boundary

The existing Auto Parser **Add Logs** step includes an optional
**Generate a Python Test Sender** section. A user enters or uploads a bounded
sample and intentionally downloads a self-contained parser_studio_test_sender.py
file; there is **no application/network sensor connection, raw sample upload,
third-party dependency or Python execution** at download time.

The Python file includes the user's sample as **base64 (NOT encryption)**. It
prompts for an explicit sensor IP address, port, UDP (default) or TCP, count
(default 60; bounded to 1–600) and YES before opening a socket. A valid
unicast IPv4/IPv6 address and destination port are required. The script
transmits at most one logical event per second using a monotonic clock and
stops after the selected finite count or on Ctrl-C. UDP is a datagram per
event; TCP is LF-framed for one-line messages or LF LF between explicitly
configured blank-line logical records. There is no delivery proof.

Only Python 3 standard library dependencies are used: base64, csv,
datetime, io, ipaddress, json, re, secrets, socket, sys and time.

## Transformations and limitations

- User-controlled source event boundaries and record order are preserved.
- RFC3164 BSD timestamps, RFC5424/ISO8601 (including Z and numeric zones),
  slash-style dates, date/time KV and 10/13/16/19-digit epoch time values
  in recognized timestamp fields are updated from the **executing computer's
  current clock for each transmission**.
- Keyed JSON, KV, CEF, LEEF and reviewed CSV expose conservative, known
  address, user, email, city/country/location aliases. Replacements use
  reserved documentation IPv4/IPv6 ranges, example.test email domain,
  synthetic user identifiers and example places.
- JSON and CSV remain syntactically valid, keeping object/column order and
  quoting/escaping as required. Existing CEF/LEEF headers, Syslog PRI and
  unknown literals remain unchanged. RFC6587 octet-counting, unsupported
  vendor-specific positional schemas and ambiguous free-text transformations
  remain out of scope. This is test-data mutation, **not guaranteed
  irreversible anonymization**.
- The user is warned of original sample disclosure before download, and
  must choose a target **only on their own machine**. There is no automatic
  external LLM request or browser/server stored replay session.

## Acceptance evidence

- Current candidate: TypeScript, Vite build, complete 98-file / 786 Vitest
  suite PASS; source generator focused Vitest and English-policy included.
- Python pure standard-library regression: 7/7 PASS for JSON, CSV, KV,
  RFC3164, RFC5424, CEF/LEEF and epoch/time identity.
- Real Playwright download -> spawned standard CPython -> **loopback**
  UDP receiver (3 events) and TCP receiver (2 events) E2E: **2/2 PASS**.
  One event per second, timestamp freshness, dynamic values, rejection
  of unconfirmed target and no web-app API POST were verified.
- CI additionally runs the Python format regression before browser
  E2E; the exact-head GitHub workflow outcome must be recorded separately.

The sender does not upload/install a parser to Stellar/DP, send a sensor
packet from Parser Studio's service, or check syslog/traffic/Interflow
ingestion. It is an **explicit user-run offline test utility** and does not
change any previously excluded live device features.
