# Stellar Cyber 7.0 normalization accuracy — fixed-schema candidate

**Owner-approved rule:** use a single Stellar Cyber **7.0** Dictionary, sourced from the public 7.0.xs documentation series. Do not implement 6.5/6.6 schema compatibility, cross-version mapping, a version selector, or a migration matrix.

**Isolated implementation:** xdr-labs/parser-studio, branch fix/stellar7-dictionary-integrity-20261021, based on the previously qualified PR #123 main bf6139e12acdf674eb56141f31920aa9e4dedae2. The previous development installation and all existing worktrees remain untouched.

## Grounded 7.0 catalog evidence

- Base standard field list: https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm (preserved snapshot provenance in the existing catalog).
- Nineteen conservative namespace scalar fields: documented 7.0 namespace children independently cross-referenced against https://docs.stellarcyber.ai/7.0.xs/Using/Alerts/Alert-Key-Fields.htm. HTML snapshot retrieved 2026-10-21 with SHA256 5458805df8ee0ed578cc480c8832cd13f0b9df06482a88792702f8aaff49171f.
- Missing type evidence, reserved roots, objects, lists and unsupported backend numeric float conversions remain unselectable; there is no assumed Stellar runtime confirmation.

## New correctness constraints

| Scope | Before | Now |
| --- | --- | --- |
| IP parser | Several malformed IPv6 literals were considered valid | RFC 4291 eight-group structure; one permitted compression marker; strictly validated IPv4 tail |
| Ambiguous status | request_status could alias security action | That alias is removed, but original vendor source fields remain available |
| Duplicate destinations | An arbitrary first source won HIGH approval | Multiple genuinely type-compatible source candidates are visible and REVIEW-only; a structurally invalid clock-only value does not obscure a valid timezone-qualified timestamp |
| Sparse input | 1-of-3 present fields could be HIGH | Every input event must contain the field and there must be informative evidence |
| Official hash fields | String-only test accepted invalid SHA256 length | MD5/SHA1/SHA256 hexadecimal widths are checked before official mapping qualification |
| Action | Numeric HTTP code could be converted to a security action | Numeric action is rejected as an unreviewed official semantic value |
| Nested official fields | Most explicitly documented children were absent from catalog | Nineteen 7.0 typed scalar namespace destinations available for manual and evidence-backed mapping |
| Reviewer message | REVIEW was described as a generic sample type mismatch | Actual missing, ambiguous, uninformative and type explanations are shown |

## Deterministic evidence

- Initial new IPv6/semantic/collision tests: 11 of 25 RED on previous implementation.
- New nested-field and hash-meaning tests: 4/4 RED before implementing 7.0 typed namespace support.
- Focused post-correction unit suites: 46/46 PASS (seven files); additional Generic Structural regression 22/22 PASS.
- A legacy BIG-IP example with two valid hostname sources is intentionally review-only, rather than silently choosing one. Full date_time remains mappable when a distinct clock-only field lacks the required timezone.
- Final frontend Vitest: 1067/1067 PASS across 134 test files.
Web and Backend TypeScript builds/checks: PASS.
Actual browser Chromium: 3/3 PASS using local Vite, Python Multi-Pass,
built offline authoring Backend and no HTTP stubs.
The third scenario creates/downloads Ruby and CONF DRAFT outputs; it
decodes the compiler-embedded project and checks all five 7.0 namespace
destinations, SHA-256 content/download equality and raw-value non-disclosure.
Exact-HEAD GitHub CI is tracked in PR #124. Do not infer manufacturer
or proprietary target accuracy from synthetic fixtures.

## Safety and next scope

Outputs remain DRAFT, engineVerified=false and targetImportVerified=false. No mobile work, real DP parser upload, sensor operation, target receiver, production release or authentication change. Continued independent manufacturer and native accuracy assessment requires licensed originals and explicit goldens; absent sources are UNSCORABLE. Never promote incomplete or unverified outputs.
