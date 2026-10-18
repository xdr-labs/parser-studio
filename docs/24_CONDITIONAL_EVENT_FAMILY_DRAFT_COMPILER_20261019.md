# Conditional event-family and declared relay compiler (experimental)

This is a **separate, unmerged backend candidate stacked on the
offline-only authoring backend**. It is not a production product route or a
Stellar DP/sensor feature.

The author may explicitly configure a source field that discriminates
between two to sixteen named event families. Each family can map additional
source keys to normalized targets while preserving common mappings. Unknown,
ambiguous, missing or conflicting family selectors reject that event.
An optional Syslog forwarder profile requires one to eight named relay
hosts and at most three strict RFC3164/5424 envelope layers. Neither a
hostname label nor parsing success authenticates a real relay sender.

The backend ParserProject JSON Schema, TypeScript validation, deterministic
Ruby/CONF DRAFT compiler and recipe v0.2 fail-closed projection have been
updated in this **isolated** branch. Old projects without any conditional
family configuration continue to compile with their unchanged original
Ruby/CONF template. The compiled output is never marked native or target
verified based on the compiler receipt alone.

Qualification includes the original whole-schema validations, independent
tests of unsafe source keys, duplicate identities, collision rejection,
unsupported transformations and the same immutable artifact pair. Where
Ruby is installed, separate **actual Ruby stdlib execution tests** parse
three synthetic event families through one generated parser, inspect
declared nested-relay provenance and reject unknown families, undeclared
relays and excessive hop counts. Ruby test cases are skipped (NOT PASS)
when Ruby is unavailable locally; GitHub CI must exercise them.

No real Stellar target, DP import, operational sensor, tenant credentials,
runtime release or automatic ChatGPT submission is involved. Before future
product integration, obtain independently reviewed frontend authoring
controls and native compatibility evidence; do not surface an unverified
family-aware compiler as a completed Parser Studio product feature.
