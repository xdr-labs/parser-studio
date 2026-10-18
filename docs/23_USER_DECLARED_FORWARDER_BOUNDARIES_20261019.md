# User-declared prefix, postfix and forwarding-header review

**Scope:** optional, browser-local source investigation inside the existing
Auto Parser → Add Logs step. No new parser creation path, DP/sensor action,
native compiler assertion or automatic log-sample rewrite.

## Beginner workflow

1. Paste complete logs into Add Logs. Expand **Mark a forwarding prefix or
   suffix** only when a forwarding service appears to have changed the record.
2. For a fixed literal wrapper, select exact text at the start or end of the
   first log and click the corresponding marking button. Alternatively enter
   the literal prefix and/or suffix directly.
3. Confirm coverage for **every** input event. Any event whose wrapper differs
   remains unchanged and is listed as not matched.
4. For a changing RFC3164/RFC5424 forwarding header, enter the exact
   **relay hostname** yourself and the maximum number of relay layers.
   Parser Studio reviews only those declared hosts; it never learns arbitrary
   hostnames or strips guessed headers.
5. Inspect the original body preview and the UTF-8 payload byte offset. Use
   the ordinary Analyze Logs and subsequent workflow to review the original
   source independently. These optional previews **do not** unlock parser
   generation for an unsupported forwarder.

## Hard boundaries and verification

- Input remains the original immutable browser string and is not sent to a
  model, a sensor, a DP, or a server for the marking operation.
- Literal markers are bounded to 512 UTF-8 bytes each, cannot contain
  control characters or a newline, and require a nonempty body.
- The report bounds source to 64 KiB and 500 single-line records; source
  byte offsets use TextEncoder UTF-8, not JavaScript UTF-16 indices.
- A typed relay profile has 1–3 hops and 1–8 unique explicit hostnames.
  Exceeding the hop budget, unknown hosts and malformed candidate headers
  do not receive a successful unwrapped status.
- The original parser compiler is unchanged. No claim is made that a
  downloaded Ruby/CONF DRAFT can parse the same forwarded record until its
  full grammar has a separately qualified backend contract.
- Representative checks include UTF-8 Korean/Japanese/Chinese payloads,
  manual selection and typed fallbacks, mismatched wrappers, nested relay
  headers and declared hop limits. Browser E2E checks do not require a real
  Stellar server, DP or sensor.

Native forwarder transformation and event-specific conditional compiler
support remain separate candidate work, not hidden behind this read-only UI.
