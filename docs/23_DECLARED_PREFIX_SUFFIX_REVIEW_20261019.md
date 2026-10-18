# User-marked prefix / suffix — bounded source review

In **Auto Parser → Add Logs**, the optional *Mark text added before or after
a log event* control lets an author highlight a fixed literal prefix or suffix
in the first sample event and mark it, or type it using a keyboard. It shows
whether the **exact** UTF-8 characters occur at the same boundaries on every
log line. It never assumes the user knows RFC, CEF or other formats.

The initial, non-mutating acceptance scope is intentionally narrow:
- 1–500 nonblank physical events and at most 64 KiB source, no NUL and valid UTF-8.
- 1–256 UTF-8 bytes per nonempty prefix/postfix, not a regular expression.
- Exact, case-sensitive, start/end matching with at least one inner character.
- Unequal markers or unsupported source → whole-sample **REVIEW_ONLY**; unmatched
  events are never silently dropped, edited or counted as supported.
- Display original source offsets in UTF-8 bytes, inner-format preview
  and at most three local representative payloads.
- All text stays in browser state; no server API, external AI, DP, sensor or
  outbound network operation.
- A matching preview is **not** a parser recipe. Native execution and
  generated Ruby/CONF are **not verified** to use these markers.

**Not yet implemented:** dynamic timestamp/hostname relay boundaries,
arbitrary rewritten forwarder payloads, historical parser event routing,
browser snapshot persistence for markers, or compiler generation of these
exact literals. Do not silently insert a source rewrite into the existing
stateless compiler, and do not claim unsupported marker previews are
exportable. A separate exact-backend contract with native execution
evidence is necessary before marking this generation-ready.

Tests cover literal selection, Unicode byte offsets, original source
preservation, inconsistent markers, bounds/UTF-8 safety and beginner Chromium
interaction.
