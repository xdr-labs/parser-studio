# JSON duplicate object members: source/browser/native DRAFT parity

## Scope

Bounded common JSON grammar correction stacked on fixed Stellar Cyber
7.0-only normalization Draft PR #124. No version-selection UI, mobile,
DP/sensors, production, vendor regex workaround or external AI.

## Independently reproduced source loss

Python Multi-Pass SpanJsonDecoder already rejects duplicate decoded keys
with JSON_DUPLICATE_OR_UNSAFE_KEY. Browser and native Ruby JSON.parse
DRAFT paths previously retained the last duplicate value. Synthetic
src_ip duplicates reproduced false browser success.

## Common grammar correction

- After JSON syntax validation, scan lexical JSON strings with a distinct
  decoded key set for each object. Original raw records are unchanged.
- Mirror the same refuse-duplicates behavior in both native Ruby DRAFT
  templates using byte-based structural scanning (no external code).
- Reject root/nested/escaped-equivalent and array child collisions.
  Identical names in distinct objects remain valid. Source census marks
  BODY_MALFORMED, not a completed parsed event.

## Qualification and limitations

- Four duplicate cases RED on previous browser source.
- Focused new browser grammar cases 8/8 GREEN.
- New real Chromium source workflow against localhost Vite, Python
  Multi-Pass and actual offline Backend: 2/2 PASS, no HTTP stubs.
- Local backend static contract PASS. Native Ruby execution test SKIP
  on dev-atlas (Ruby absent); exact-HEAD GitHub CI Ruby must qualify.
- Explicit JSON DRAFT parser path only. Generic prefixed/container JSON
  families require independent native-compilation proof.
- Generated artifacts remain DRAFT, targetImportVerified:false.
  No target API, parser import, user credentials or release changes.

Exact source commit, Draft PR and CI receipts are stored on GitHub Issue #1.
