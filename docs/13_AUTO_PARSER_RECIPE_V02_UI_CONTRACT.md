# Auto Parser v2.0 — Reviewed staged contract and restricted backend compilation

Status of each generated recipe: **REVIEW_ONLY**. Source of truth: `src/guided/parserRecipeV2.ts` and its runtime validator. `parserRecipeDraft.ts` only re-exports that same contract. A separately checked backend capability can compile **only the strict v0.1-equivalent staged subset** into real matched DRAFT files; the recipe alone is not evidence of native user-parser or Stellar target qualification.

## Typed review result

- `contract = parser-studio.recipe.v0.2`, `schemaRevision = 0.2`, `compilerMode = REVIEW_ONLY`.
- `projectId` and exact `sourceFormat` + `bodyFormat`; `sample` contains only a SHA-256 digest and event count, never raw event text.
- Strict ordered `stages`: `split_event`, optional `unwrap_syslog`, one reviewed parse operation, or one strict dispatch_family stage for explicit JSON/KV/CEF/LEEF, bounded `map_field` with an adjacent type cast when needed, exactly one `classify`, and a final `fallback_unparsed`.
- All unknown operators, prototype-path segments, duplicate mapping destinations, misplaced casts, forged native/target PASS flags, mismatched body parsers, malformed shapes and source/sample mismatches fail closed.
- `legacyProject` is returned **separately** as the unchanged typed ParserProject v0.1 projection. `V01_SNAPSHOT_PRESERVED` and `lossyOperations: 0` refer **only to this parallel snapshot**, not v0.2 compiler/native semantic equivalence. Project enrichment/receiver semantics are not silently inferred as supported staged operations.
- `nativeVerified`, `targetVerified`, `nativeUserParserVerified` and `targetImportVerified` are **always false** in recipe and receipt. Initial local `v02CompilerAvailable=false` means **not yet negotiated**: an explicit separate request can establish a limited v0.2 backend capability, not native readiness.

## UI and API boundaries

- Beginner default remains **Add Logs → Review Results → Test & Generate**, with the existing Edit Details and Expert routes unchanged.
- v0.2 metadata is shown by the advanced **Review Staged Recipe** action; it is built locally from the exact browser suite and invalidated by source edits. Nothing is posted until the user explicitly selects **Validate and Compile Strict v0.2 DRAFT Pair** after generating the independently validated v0.1 pair.
- Existing v0.1 `validate`/`generate` remain unchanged. The separately pinned backend `d5f3992` exposes `/api/v1/parser-pairs/recipe/v0.2/{capabilities,validate,generate}`. Only the reviewed `{recipe, legacyProject}` pair is transmitted (no raw events). The backend verifies exact mapping/cast/classification equivalence, and the browser independently hashes the recipe, legacy project, returned Ruby+CONF, compiler receipt and file contents, requiring a byte-identical match to the previously generated v0.1 pair. Older backends fail closed without affecting v0.1 downloads.
- Native Fluentd, actual Stellar loader, authenticated DP Apply, approved sensor send, tenant Interflow and two-user E2E remain distinct, independently gated verification claims.

## Backend owner contract handoff (PR #4)

The backend provides a strict JSON Schema, versioned allowlisted capabilities, exact v0.1 metadata equivalence and twelve native PUBLIC SYNTHETIC Fluentd/CONF fixtures. This is **not** a general staged engine. The pinned backend now supports a strict RFC3164 TAG/body subset with unknown year/zone. Future native backend work must add broader RFC3164 variants, mixed Syslog/CSV routing, logical multiline support and broaden the independently native-qualified operators before advertising these as supported. Unknown/non-equivalent AI stages must never compile by optimistic coercion.

## Current verification

- Focused source digest, v0.1 preservation, stage order, body-family, native-false, tampered metadata, unsafe field and source-mismatch unit tests: `src/guided/parserRecipeV2.test.ts`, `src/guided/parserRecipeDraft.test.ts`.
- Real Chromium backed by pinned loopback backend tests the advanced review disclosure, no leaked raw addresses and existing generation/download integrity in `tests/integrated-backend.spec.ts`.
- `recipeV2BackendClient.test.ts` verifies capability negotiation, exact receipt/source identity/hash, default-false native/target claims and tampered responses. The exact pinned-backend Chromium scenario also validates the real restricted v0.2 route; backend PR #4 owns the **separate** twelve-profile pinned native Fluentd synthetic evidence. None is a customer parser or actual DP/Interflow test.

## RFC3164 bounded UI/backend support

The public-synthetic RFC3164+KV beginner path and the strict RFC3164 CEF/LEEF envelopes can now be reviewed with an explicit, verified backend capability; the browser preserves the YEAR_AND_ZONE_UNKNOWN header policy and prohibits treating that header as a timezone-qualified date. User-provided event bodies are not POSTed to the versioned compiler. The same sensor destination and CONF receiver port must be >=6800. UI pinned backend commit: d5f3992a951eadc83970d087fe1751b9bfd4229b. Vendor deployment remains NOT VERIFIED.

## Strict mixed single-line JSON/KV/CEF/LEEF (P0-AP1)
The same pinned backend additionally supports the strictly bounded mixed source/body with an explicit dispatch_family stage. The Auto Parser scans and accounts for every original event without transmitting raw source; exactly 2–4 distinct, supported non-Syslog families from JSON, KV, CEF, LEEF can create a mixed DRAFT. A fixed local-safe prefix is required for each event, and an unknown, CSV, RFC3164/5424 or multiline record fails closed rather than being reassigned to a convenient parser.

The browser checks both ordinary capabilities and the versioned v0.2 dispatch_family and family-allowlist claims. Edit Details permits explicit manual family selection and an optional public-synthetic mixed starter. The generated CONF and sensor destination still share one receiving port. Native success refers only to pinned public-synthetic Fluentd/CONF fixtures, not arbitrary customer data or live Stellar targets. Raw log bytes are never sent to the compiler; only reviewed normalized mappings and source digest/count are transmitted on explicit user request.

## Explicit TCP LF LF JSON boundary stage

When a user selects JSON + TCP only + blank-line grouping + TCP JSON Event Framing in Edit Details, the UI may review split_event(boundary=blank-line) and the independently matching ParserProject v0.1 receiver tcpFraming=blank_line_json. This requires the exact reviewed jsonBlankLineTcpFraming/jsonBlankLineOtherTransports/jsonBlankLineDelimiter capability tuple and never enables arbitrary multiline or unknown-source auto generation. See docs/19_EXPLICIT_TCP_JSON_FRAMING.md; user parser and Stellar DP import remain NOT VERIFIED.


## New fixed wrapped RFC5424 mixed family subset

The exact-pinned backend 3ddbdd10e0218156c01d0aa48f3b27e3d686c0b5 adds two explicitly allowlisted single-line mixed format IDs: rfc5424_cef and rfc5424_leef. The browser maps RFC5424 v1 header + strict nested CEF/LEEF only after source accounting and independently checked envelope/body detection, while preserving standalone JSON/KV/CEF/LEEF compatibility and a 2–4-family cap. The same sensor/CONF port must be at least 6800 if any wrapped Syslog family is used.

Auto Parser detects all original events without requiring the user to name the protocol. Edit Details supports manual family checkboxes, and the public-synthetic Mixed JSON + RFC5424 CEF/LEEF starter is provided. Only strict RFC3164 TAG: KV is now additionally reviewed; other RFC3164 mixed bodies, mixed CSV, arbitrary Syslog, multiline or target-deployed compatibility are not assumed. Old backend 4-family capabilities fail closed rather than generating an unsupported pair. A new same-head Chromium localhost case validates the real backend Ruby+CONF and v0.2 recipe SHA match with no raw log event values in API requests. Native Fluentd synthetic evidence remains separate and does not imply DP import.


## Strict RFC3164 TAG: KV mixed DRAFT subset

The 7-entry versioned backend mixed capability now additionally allows rfc3164_kv, subject to a strict RFC3164 TAG: envelope and key/value body. The beginner Auto Parser shows source family review and explicitly warns that RFC3164 headers have neither year nor timezone, so no date is inferred. The approved ParserProject and ParserRecipe v0.2 may only represent this fixed branch when the backend explicitly advertises exact strict rfc3164 time-policy and 7-entry family capability. Earlier 4- and 6-entry backends remain supported for their existing families but fail closed for rfc3164_kv. Edit Details manual options and public-synthetic starter are included; sensor/.conf port must match and be >=6800. Regression covers every source event and unchanged SHA-matched Ruby+CONF, without claiming proprietary loader or live sensor verification.
\n## Native-bound RFC5424 JSON/KV wrapped mixed subset\n\nThe backend now adds strict rfc5424_json and rfc5424_kv IDs to a 9-family server-owned vocabulary (2–4 selected per parser). These two names are only legal for RFC5424 VERSION 1 strict envelopes whose bodies are independently verified JSON objects or quoted-safe KV. The beginner format ledger must account for all events, show an explicit RFC5424 timestamp only when supplied with timezone, and refuse malformed, unknown, CSV or hidden fallback events. Edit Details lets the user explicitly select these branches; the Mixed JSON/KV + RFC5424 JSON/KV public-synthetic starter supplies a complete reviewable no-code example. Old 4-, 6- and 7-entry backend vocabularies remain recognized only for their previous branch subsets and may not compile these new IDs. Strict ParserRecipe v0.2 output is compared byte-for-byte to the same v0.1 Ruby+CONF and user Native / target import remain false; no real sensor/DP/Interflow E2E is inferred. The .conf port is the sensor receive port and Syslog requires >=6800.\n