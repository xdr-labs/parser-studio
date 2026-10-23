# 2026-10-23 — Real public Web diverse security-log E2E and 64 KiB JSON envelope boundary

## Product and evidence boundary

Owner requested hands-on actual Chromium E2E with diverse security logs. The
live, already accepted **development** app at
`https://app.parser.xdr.ooo/` served merged main
`2f7a0d876213e5775ca3e2ae04e25bc63d9299f5`,
`/assets/index-DuC49Nzm.js`. The tests called the **real, installed**
Web, Multi-Pass and offline DRAFT authoring API, not mocked endpoints.
Fixtures are safe authored examples of vendor syntax, **not verified original
device captures or manufacturer firmware goldens**. There is no DP/sensor
traffic, native Stellar target import, production, or mobile scope.

### Actual installed public browser results

1. Existing 54-format Web corpus: **54/54 Chromium E2E PASS**, zero SKIP,
   page errors and HTTP 5xx. **42/54 reached fully extracted source Review
   Fields**, while **12/54 required truthful review**, including W3C/Zeek,
   malformed/unlabeled CSV, Windows Event XML, Snort and selected
   manufacturer-style free-form text. This is not an all-vendor accuracy
   percentage.
2. Additional real browser functional tests: **33/33 PASS**, including
   PAN-OS and year-bearing Cisco ASA, BIG-IP ASM, RFC framing (octet, NUL,
   GELF, JSON sequence and journal), structural review and Zeek explicit
   schema preparation.
3. Independently authored 19-log deeper real Web UI matrix: **19/19 PASS**.
   **16** valid families walked actual
   Analyze Logs → Review Fields → Map Fields → Create Parser Files and
   successfully downloaded and checked DRAFT CONF files with port 6801.
   Families included WAF, CloudTrail, Suricata, Entra, Okta, Defender,
   Korean UTF-8 JSON, FortiGate, Check Point, CEF, LEEF, RFC5424, year-bearing
   Cisco ASA, F5 ASM, Windows JSON and mixed threat/user/asset.
   **Three unsupported/invalid sources** (unfinished CSV quotation,
   duplicate decoded JSON key and Windows Event XML) were correctly blocked:
   zero parser generate POSTs. No third-party HTTP egress or API 5xx.
4. 501 compact JSON records within the byte limit were explicitly rejected
   by the visible **500-event maximum**; no silent sample truncation and
   no parser generation.

Real browser JSON reports and original console evidence reside only on
the authorized development server at
`/home/aella/.local/state/parserstudio-public-rollouts/pr147-diverse-log-e2e-20261023/`
(corpus-report.json, functional-report.json, draft-report.json,
volume-report.json). The complete happy-path subtotal excluding the special
500-record boundary was **106/106 PASS**.

## Genuine NEW 500-event boundary defect found on actual public installation

A manually entered, valid **500-record** mixed threat/user/asset JSON input
was **61,673 UTF-8 source bytes**, under the advertised 65,536-byte / 500-event
limits. The Browser's `JSON.stringify({raw})` produced **73,182 HTTP body
bytes** due to escaping JSON quotation and newline characters. The Multi-Pass
HTTP handler incorrectly capped the encoded body at
`MAX_BYTES+1024=66,560` instead of separately enforcing raw-source limits.

**Direct public API reproduction:** 100 records (12,182 raw / 14,491
encoded bytes) returned HTTP 200 and 100 frames, whereas 500 (61,673
raw / 73,182 encoded bytes) returned **HTTP 422
INVALID_OR_OVERSIZED_SOURCE**. Real browser Analyze Logs then showed a
non-specific preserved-source error, with no visible parsed result. This is
a legitimate product failure, not a parsing algorithm limitation or a
Playwright timeout alone. Its initial public 500-event UI case FAILED.

## Root fix, proof, and protections

An isolated source branch:
`fix/multipass-body-boundary-20261023` from exact merged main.

- `runtime/multipass/multipass_preview_api.py`: bound only the JSON HTTP
  **transport envelope** to at most `MAX_BYTES*6+1024` (safe worst-case
  6-byte escaping of one raw byte). Both decoded `preview()` and
  `preview_batch()` still independently enforce **65,536 original UTF-8
  bytes**, and batch framing still independently enforces 500 events.
  The handler keeps its HTTP body-size cap; the change does not permit
  arbitrary input growth.
- `tests/test_embedded_multipass_service.py`: actual loopback HTTP test
  authenticating 500 JSON records, original UTF-8 byte count, full source
  SHA-256, all 500 output events and no native/target claim. Also
  explicitly assert HTTP 422 for a decoded 65,537-byte source and for an
  HTTP envelope exceeding its bounded cap.
- `tests/novice-500-events-json-wire-20261023.spec.ts`: real Chromium
  UI scenario with 500 mixed JSON records progressing to Review Fields,
  and 501-source hard rejection with original source unchanged.
- `.github/workflows/quality.yml`: include both browser cases in the
  exact-head first-user gate; expected count 15→17.

The focused Python regression was directly executed against the **original
source before fixing** and was RED (HTTP 422), then GREEN after the fix.
Candidate Python test suite **101/101 PASS**; candidate isolated local
Chromium **2/2 PASS** with output `500 of 500 log events parsed completely`
and a separate 501-event explicit blocking PASS. Candidate TypeScript/Vite
build PASS. No raw source bytes, grammar, extraction span algorithm,
Stellar 7.0 Dictionary, or compiler output was changed.

## Release boundary

The HTTP change is **not installed on the public development app**.
The already accepted production-excluded Web/static rollout remains on the
prior approved main. The candidate requires an exact-HEAD CI qualification
and separately approved development backend service rollout; do not
silently restart shared services or claim the live 500-event bug is repaired.
