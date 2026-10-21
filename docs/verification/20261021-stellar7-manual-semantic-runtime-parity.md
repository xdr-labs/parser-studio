# Manual 7.0 field mapping — Browser/native value-constraint parity

2026-10-21, owner-directed parser quality continuation. Fixed **Stellar Cyber 7.0** Dictionary only; **not** a manufacturer-firmware or Stellar runtime precision claim. Existing verified `main` and public development deployment are preserved until a separately qualified main/development rollout.

## Reproduced correctness defect

A user could manually choose a published official field without using a safe field-suggestion action. Browser Preview converted the value by type alone, without validating the stronger field-specific constraints already enforced by the suggestion and mapping review stages. Invalid `dstport=65536`, `srcport=-1`, `severity=101`, 32-character `sha256`, 40-character `file.hash.md5` and numeric `action=200` were emitted into official fields, with `normalizedOk=true` despite `valueFitsNormalizationTarget(...)===false`.

This is a **real false-success regression in Browser Preview**, not a proof of manufacturer-specific bad data. The original samples remain unchanged. Both generated Ruby DRAFT templates performed the same type-only conversion for such manually chosen fields, so the client-side recommendation guard alone was insufficient.

## Bounded general correction

- Extract a pure, side-effect-free, 7.0-only scalar destination constraint shared by all Browser normalization paths and catalog candidate checks. It requires correct hash widths, official L4 port range 0–65535, severity 0–100 and string security action source type, in addition to the normal conversion rules.
- Block invalid **official top/ns** mappings at runtime with a field-specific `TYPE_ERROR`, mark sample normalization unsuccessful and omit the invalid normalized output. Do not copy source values into diagnostic messages.
- Mirror this fixed value contract in both self-contained Ruby DRAFT templates, including the explicit event-family path. Generated Ruby produces only existing bounded `MappedFieldError` metadata on invalid mapped source fields, not the original value.
- Keep `vendorFields` permissive for legitimate vendor-local nonstandard values; do not alter source extraction, original UTF-8, event boundaries, `6801` listener default, 7.0 catalog provenance, prior approved mappings, or target/sensor authorization.

## Acceptance evidence

- RED before change: six of seven new Browser runtime semantic cases failed against the deployed-main source; the vendor-local control was already valid. Native template test also RED because it lacked an official semantic guard.
- GREEN local: 7/7 Browser runtime semantic cases, 9/9 existing candidate tests and 6/6 prior Stellar 7.0 integrity tests; isolated actual Chrome first-user/manual-official-hash E2E 1/1 PASS, with invalid official data **Not emitted**, explicit mapping warning and disabled unsafe parser creation.
- Ruby executable is absent on `dev-atlas`; locally the shared-template contract passes, but eight newly added real native Ruby cases plus the existing family native case are SKIP. Exact-HEAD hosted GitHub CI Ruby execution is mandatory before native PASS is claimed. Both templates must remain byte-identical for the shared helper and reject unreviewed values in top/ns only.
- The existing 3-scenario desktop 7.0 safety suite now includes this regression for an expected 4/4 real Chromium run. Full frontend and backend build, exact source/CI, main merge and development rollout are independent gates, not inferred from focused tests.

No real Stellar DP import, sensor delivery, private log egress, external AI, mobile UI or production deployment is part of this work. All generated outputs remain DRAFT and `targetImportVerified=false`. A synthetic Browser 4/4 or Ruby 8/8 does not establish real manufacturer-wide normalization F1.
