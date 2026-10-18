# Multi-event source-field comparison — read-only beta slice

Parser Studio can accept representative events from a product without
assuming that alert, user, asset and traffic logs all have the same
structure. In the existing **Auto Parser → Review Fields** step, the
optional "Compare fields across log types" panel uses browser-parsed data
to summarize the union of observed source field names.

It chooses up to 10 representative events in total, preserving distinct
recognized formats, event-type values and field novelty. The selector is
an explicitly named source field, initially event_type. User-provided
values are never interpreted as permission to create event routing
rules. The review reports which fields are populated, blank, missing or
only temporary positional names in each group. Additional events still
contribute to the normal whole-sample validation, not the ten-example
summary.

The panel is intentionally **read-only**. It does not merge incompatible
formats, assume a field's semantic meaning, create a conditional Ruby
parser, expose customer log values in downloaded reports, upload source
data or imply Stellar native/DP compatibility. The source event remains
available in the adjacent browser-only inspector for direct review.
Unsupported log types remain unscorable rather than being promoted to
successful parser coverage.

This first slice is separate from the later reviewed conditional-routing
compiler work and from manually selected relay prefix/postfix support.
It preserves those tasks as outstanding roadmap steps.

Regression evidence uses multilingual sample events with Korean, Japanese
and Chinese values, immutable browser input, source-field grouping,
explicit English UI labels and existing mapping/two-path contracts.
