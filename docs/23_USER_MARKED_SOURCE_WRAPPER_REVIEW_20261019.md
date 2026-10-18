# Manual forwarder prefix/postfix inspection — source-only slice

The optional Auto Parser **Add Logs** panel lets a beginner select exact
literal prefix and postfix characters in the first log event by highlighting
them directly in the original input. No parser syntax knowledge is required.

The browser verifies that the same literal wrapper surrounds every provided
nonempty record. It displays the bounded extracted payload and exact byte
positions (with UTF-8 multi-byte values accounted for) while preserving the
original log input without changing its active parsing or mapping state.

The inspector rejects mismatched/overlapping boundaries, malformed CR/NUL,
oversized source or selections, and ambiguous empty payloads. Neither the
panel nor any REST service uploads or saves the source, creates a pattern
heuristic, requests AI, connects to a sensor, or silently rewrites a parser.

**Source-only:** A highlighted prefix can contain a timestamp or identity
that changes between events. A literal match on one line is not a safe
adaptive rule for those sources. This first slice deliberately does **not**
mark the backend compiler as verified and does not generate native Ruby
prefix-removal code. The original source still enters Create Parser; invalid
or unsupported compiler scenarios stay blocked. Later runtime parity must
qualify dynamic relay headers, user-controlled source delimiters, and
multi-event normalization separately under same-HEAD native acceptance.

A browser E2E demonstrates exact user selection, Korean/Japanese UTF-8
preservation, consistent payload comparison, stale source rejection and
clear-marks behavior. The original protected forwarder/backend dirty
worktrees remain untouched.
