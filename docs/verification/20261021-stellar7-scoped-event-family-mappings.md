# Fixed Stellar Cyber 7.0 mapping suggestions per explicitly reviewed event type

Scope: the owner's single **Stellar Cyber 7.0** normalization contract.
This is a new, isolated workstream stacked on qualified Draft PR #125.
Do not implement 6.5/6.6 dictionaries, target-version selectors, migrations,
vendor-specific regex patches, DP/sensor transfers, mobile or production release.

## Gap observed

A multi-type Threat/User/Asset parser already had explicit conditional routes,
but its event-specific destination editor initially kept automatically selected
fields in the parser vendor namespace even when the user intended a public
Stellar Cyber 7.0 field. Cross-type whole-sample mapping also demotes a field
seen only in Threat, since User and Asset records legitimately lack it.

## Correctness requirements

- Use only an *already reviewed explicit* event type discriminator. Unknown,
  ambiguous or unparsed records are not assigned a destination or fallback type.
- Evaluate documented 7.0 field names and observed values **within each type's
  own sample set**, while checking all examples of that selected type.
- A source missing in its own type, invalid official target values (including
  SHA-256 hex width), two compatible aliases for one target, and conflicting
  shared/variant destinations are REVIEW, not automatically adopted.
- Preserve manually changed/vendor-local mappings. Offer a catalog-backed
  "Use reviewed 7.0 field" action for safe suggested fields. The action changes
  only the proposed local candidate and its explicit top/ns namespace group;
  user approval and Backend capability checks are still mandatory before
  modifying the current DRAFT.
- Hand editing any destination or type cannot accidentally keep an official
  group with a mismatched type; it conservatively returns to vendor-only review.
- Require official group/type and source value semantics during conditional
  event value review (not just string coercion).
- Never send source field values to a third-party AI service. Original UTF-8
  source and vendor fields remain locally available.

## Independent synthetic golden evidence

Six *authored synthetic* events cover three disjoint types:
Threat contains src_ip, action and a SHA-256 source; User contains username,
login_result and optional host.ip; Asset contains host.name and process.name.
The test has static expected normalized field/value trees created separately
from the extractor and tests exact per-event normalized values, source identity
and an unknown=reject event-family policy. It does not score physical vendor
firmware or target-runtime behavior.

- Deterministic source/field golden assertions: six authored synthetic
  records with **16/16 exact expected official field/value results** across
  Threat, User and Asset; this is not a manufacturer accuracy rate.
  Stale/forged recommendations and manual overrides cannot silently convert
  vendor-local fields to verified official mappings.
- Two extra official value/type validation cases, including malformed SHA-256.
- Controlled UI unit: explicit click and separate owner approval before any
  DRAFT replacement; verified mapping groups survive Backend adapter.
- Real isolated desktop Chromium with local Vite, Python Multi-Pass and pinned
  offline Backend: **two distinct** approved multi-event browser journeys
  with genuine DRAFT Ruby/CONF generation, decoded conditional namespaces,
  and downloaded Ruby/CONF SHA-256. Original multilingual source unchanged;
  no HTTP stubs or re-execution of past public acceptance.
- Both Ruby templates were already qualified by the prior exact-head CI.
  This candidate also adds a scoped six-event native Ruby oracle test, with
  an unknown event type rejected without echoing secret source values.
  Ruby runtime is absent on dev-atlas; GitHub-hosted native gate is required.
- Final exact-HEAD CI and focused regression results are recorded in Issue #1
  and the stacked Draft PR after verification.

## Scope boundary

This contract improves reviewability and prevents incorrect global mappings.
It **does not establish manufacturer-wide normalization precision or recall**:
a real independent manufacturer/firmware field/value oracle remains absent.
No target import or actual Stellar runtime matching was performed; outputs
remain DRAFT and targetImportVerified:false. No main merge or development
application is part of this bounded patch.
