# Explicit multi-event and relay parser DRAFT user workflow

This experimental candidate stacks on PR #97 and adds the operator-facing
controls required to create one Parser Studio Ruby + CONF DRAFT for several
distinct security event types.

1. Paste representative events and review the extracted source fields.
   Users do not need to identify JSON/KV/CEF/LEEF or Syslog grammar to
   begin analysis.
2. On Review Fields, optionally open One parser for several event types.
   Choose an exact source discriminator (for example event_type). Parser
   Studio checks every extracted sample for a nonempty safe discriminator.
   Users can explicitly edit type-specific destination names and value types,
   compare common and type-specific fields, see classifier changes, and
   approve or undo the configuration.
3. Conditional compilation is permitted only when the local backend
   advertises the exact event-family and unknown-reject capabilities.
   Unknown source types cannot fall back to a global routing rule.
4. If every source event comes through reviewed Syslog relays, optionally
   declare the relay hostname allowlist (maximum 8) and up to 3 nested
   hops. The preview checks all records; partial matches are rejected.
   A hostname printed in a log is not sender authentication.
5. Review Stellar mappings and run the final entire-sample test before
   downloading a Ruby parser and CONF pair. These are uninstalled DRAFT
   artifacts with SHA-256 integrity checks, not target verification.

The downloaded parser contains only reviewed parser configuration, not raw
sample values. UTF-8 usernames and other event values remain in source data.

## Qualification boundary

The browser source preview is not proof of proprietary Fluentd/Stellar DP
compatibility. Native Ruby execution is tested independently on the stacked
backend CI. A dedicated browser CI step uses this exact PR HEAD, including
the local authoring-only backend, and rejects falsely green runs unless two
Chromium user cases actually execute and pass.

The broad ordinary browser suite retains its independent pinned-backend
contract. The two specialized cases are explicitly SKIP in that suite
because its older backend lacks the new capability; the dedicated gate
must execute them before CI succeeds.

No DP upload/apply, Parser Studio-originated sensor delivery, ingestion
verification, credential change, target connection, or production release
is included. Parent PR #91 and backend PR #97 remain separate Draft
integration candidates until exact-HEAD gates and applicable security
and owner acceptance are complete.
