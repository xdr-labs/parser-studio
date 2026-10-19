# RFC3164 — Strict yearless Syslog authoring subset

Backend PR #4 supports a bounded **single-line RFC3164 PRI + BSD TIMESTAMP + HOST + TAG (optional PID) + colon-delimited body** extraction mode (`syslog_rfc3164`). This is **not** general RFC3164 compatibility and does not infer missing metadata.

Accepted synthetic shape:

```
<34>Oct  9 14:15:16 edge fw[122]: src_ip=198.51.100.14 dst_port=443 action=deny
```

The strict implementation checks PRI 0–191, a fixed English month list, month/day maximum (February 29 allowed because year is unknown), 24-hour clock ranges, bounded ASCII hostname, bounded application name and optional decimal PID, and a nonempty message. It refuses malformed headers, unknown month, impossible date, missing TAG delimiter, invalid quoted KV, mixed physical lines, or unsupported body syntax. A message parser must be explicitly declared as `raw`, `json`, `kv`, `cef` or `leef`; there is **no blind mixed-format fallback**. Strict unquoted KV rejects unmatched quote characters, including malicious malformed quoted fields.

`syslog_timestamp` preserves the original month/day/clock as a **string** (`Oct  9 14:15:16`). The additional metadata `syslog_time_policy` is always `YEAR_AND_ZONE_UNKNOWN`; no parser date conversion is applied. Mapping `syslog_timestamp` as date is rejected at **authoring validation**. To produce a real timestamp, a separate explicitly reviewed year+timezone policy and native tests are needed; none is generated here.

The same parser receiver port is used in every emitted `.conf` UDP/TCP source and is exactly the selected sensor destination ingest port. Syslog ports must be >=6800; the standalone port planner supports `syslog_rfc3164` with the same minimum, but returns a tentative plan pending trusted inventory and final binding check.

## Provenance and tests

`test_native/fixtures/recipe-v0.2-golden.json` adds 3 independent public-synthetic RFC3164 profiles (quoted/unquoted KV, CEF and LEEF wrappers) and 9 fixed negative cases. `scripts/verify-recipe-native.ts` generates the exact v0.2/v0.1-equivalent Ruby+CONF pairs and their SHA receipts. `test_native/recipe_v02_native_smoke.rb` runs exact fixed-source Fluentd 1.17.1 callbacks and `.conf` AST checks without a sensor, live network receiver, customer logs or proprietary loader. Existing 10-profile/23-case v0.1 golden fixtures remain unchanged. Header and body evidence is **PUBLIC SYNTHETIC ONLY**, not proof of a customer or Stellar target loader.

Unsupported: no RFC3164 no-PRI recovery, no year/zone guessing, no multiline assembler, no arbitrary TAG grammar, no arbitrary new DSL operators, no automatic mixed-family dispatch. Unsupported inputs must not be silently counted as parsed events or emitted as native success.
