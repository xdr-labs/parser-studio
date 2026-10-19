# Conditional event families + declared Syslog relay compilation (DRAFT experiment)

This **stacked backend candidate** is based on the unmerged offline-only
authoring backend PR #91. It imports only the seven backend source changes
and two new source files from the protected developer proof-of-concept
worktree, leaving both intentional dirty worktrees unchanged.

A single **offline** ParserProject v0.1 may contain:

- One explicit event discriminator and 2–16 distinct event-type values.
  Each value has its own reviewed normalization mapping group alongside the
  common mapping rules. Missing/unknown/ambiguous types fail closed instead
  of using a guessed family.
- Up to three user-declared RFC3164/RFC5424 forwarding hops, bounded to
  eight enumerated relay host identifiers. No silent prefix detection, blind
  character slicing, or claim of authenticating a relay host from text.
- One pair of DRAFT Ruby and CONF files. Existing projects with no
  additional profiles use the unchanged compiler path.
- Independent map validation for unsafe names, collisions, conflicting
  destinations, invalid source families, forbidden fallback or unreviewed
  forwarder parameters.

Native runtime compatibility and correct conditional field values cannot
be inferred solely from successful file generation. Source-level tests
verify deterministic output and model rejection. Ruby execution tests in
GitHub CI are the required follow-up proof; the local dev-atlas node does
not have a Ruby interpreter and **skips** those tests (never counts them as
PASS). Even a native Ruby PASS is not proof of Stellar proprietary loader,
hardware, DP ingest or customer log correctness.

The mainline product UI has not been connected to these new options yet.
There is no public parser deployment path, no DP upload, no app-originated
sensor transmission, no Interflow query and no target configuration change.
The historical backend server remains restricted by PR #91's offline-only
HTTP allowlist. Do not merge/release this stacked experimental candidate
automatically or activate its capability in the user-facing beta before
the same exact HEAD frontend and native compiler contract is reviewed.

Evidence: scoped backend tests, isolated HTTP contract test, static model
validation, Ruby/CONF golden files, and CI's Ruby grammar/runtime checks.
