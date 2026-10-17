# Isolated Source-KV UTF-8 Byte-Span Oracle and Wire-Format Escape Review — 2026-10-17

## Scope and authorization

This research PoC is **stacked on Draft PR #40** (`399634190f25645060d5f7b330602bc3a02e6617`). Only a **new isolated PoC worktree** is modified. The product branch (`da94aa9177c6b652eee47768efb98a9d47df8c5e`), main, prior #29–#40 PR branches, DP, sensors and deployments remain unchanged. No product parser, native adapter, or production escape-decoding rule is promoted.

Goal: independently prove exact original **(field name, UTF-8 raw byte span, decoded source field value)** instead of counting generic KV syntax recognition as a parse. A source-exact event is at most `REVIEW_ONLY_SOURCE_EXACT`, not manufacturer certification or a native/Stellar parser success.

## Independent oracle architecture

- `scripts/poc/createSourceKvUtf8SpanOracle.py`: **byte-oriented Python scanner**, independent of the candidate TypeScript regex. It records half-open UTF-8 ranges for full-source field token, field name and raw value; the envelope prefix is included in all offsets. It independently scans PRI-only, yearless RFC3164 and bare KV; malformed/incomplete sources, duplicate/canonical-colliding names, unsafe prototype names and invalid UTF-8 are rejected. Double-quoted known `\"` and `\\` escapes are decoded, unknown sequences remain source-literal; shell-like single-quote escapes are not inferred.
- Historical independent source field/value references come from **previously pinned private Python shlex-based oracles**; the new reference never learns expected fields or byte spans from the TypeScript candidate. A disagreement is explicitly `VALUE_AMBIGUOUS`/`SOURCE_UNSCORABLE`; the scanner does not manufacture an expected value.
- `scripts/poc/createAdditionalKvUtf8SpanOracle.py`: new byte-span references for previous separately sourced Fortinet, SonicWall, and Sophos original cohorts. They independently pin raw-file hashes and previous source-value oracle hashes. Only this *new* byte-range dimension is qualified; prior holdouts are not advertised as newly unseen.
- Private exact originals and expected field values remain under `~/.local/state/parserstudio-*/` and the new `~/.local/state/parserstudio-source-kv-byte-span-20261017/` directory, with oracle files mode `0600`; only count/hash evidence is publishable.
- `src/poc/conservativeKvUtf8Span.ts`: **observer of unchanged lexical candidate**, recomputes UTF-8 byte positions, checks exact byte name slices, and rejects lone surrogate code units rather than silently accepting replacement characters.
- `src/poc/sourceKvSpanReviewGate.ts`: fail-closed field-level name/value/byte-span comparison. Incorrect bytes, invalid/missing source identity, ambiguous values, additional fields, collisions and absent independent oracles cannot become source-exact. **canAutoPromote=false** on all paths.

## Frozen original source field/byte-span results

All values below are independently qualified *source* field/name/value/byte-span comparisons, not vendor/native approvals.

| Cohort | Scorable events | Exact triple fields | Exact events | FP | FN | Byte-span mismatches |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original SonicWall | 178 | 3,869 / 3,869 | 178 / 178 | 0 | 0 | 0 |
| Original Fortinet | 7 | 291 / 291 | 7 / 7 | 0 | 0 | 0 |
| Additional Fortinet | 1,002 | 11,848 / 11,848 | 1,002 / 1,002 | 0 | 0 | 0 |
| Additional SonicWall | 59 | 759 / 759 | 59 / 59 | 0 | 0 | 0 |
| Additional Sophos | 151 | 4,956 / 4,956 | 151 / 151 | 0 | 0 | 0 |
| **Source-qualified total** | **1,397** | **21,723 / 21,723** | **1,397 / 1,397** | **0** | **0** | **0** |

The first 185 frozen events contain **53 non-ASCII original records**. All byte coordinates refer to the original UTF-8 input, rather than JS UTF-16 code-unit offsets.

An additional observer-only parity replay against 1,361 previously frozen non-JSON/security original records and 2,892 adversarial mutated inputs found **zero new lexical eligibility changes**: 254 originals remain eligible, 600 invalid Sophos mutations remain grammar-matched and vetoed; Juniper and external mutations remain refused. This is a safety parity measure, not a new independent source-value oracle or proof of manufacturer semantics.

**Exclusions are mandatory:** SonicWall has **2 additional independent-original source-ambiguous events** explicitly `SOURCE_UNSCORABLE`. Sophos has **120 independent-original events without a complete field oracle**; 103 of these may match generic lexical syntax but remain `UNSCORABLE/REVIEW_ONLY`. The earlier 600/900 Sophos malformed mutations still match generic KV lexical syntax, yet **all 600 remain vetoed** by the existing source-specific vendor profile; zero are promoted. Scorable totals exclude all unscorable originals and malformed controls.

### Frozen source and independent reference identifiers

- Original 222-event corpus (185 qualified): `153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32`
- New private original byte-span Oracle: `33b2bd524ac20ee4f9f5e0970a9bf1de6c4e8d3310fe5e99b35a439571e73cf9`
- Fresh Fortinet original file hashes: `e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2`, `53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440`
- Fresh SonicWall original file: `949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9`
- Sophos 571-event vendor original corpus: `3e915882a7ea3e432cf46739342b30595581fc2e3db23247da1dbfc5346a6eb2`
- Source-value oracle SHA-256: Fortinet `cdcf58126d8c45eb96b6832c381b6d943d07cde78ea2ee39648c402207a97fc9`; SonicWall `a3204563622c538a870d6e5cbe9756d01c86a6edfe87eafef16c6d9ed8be038a`; Sophos `b1ebbc634268050a276fe3af1e478652cfdb71a88b4e0c2d14cae5114210f3fb`
- New private additional source byte-span Oracle: `d45ae3af2fb68f6efa8527d281df30e4dce648ffc7b2c271e60a943dfc034f78`
- Malformed Sophos controls: `1b4d044ccb129d16860afc1c6b6490383b2b021b4366dcb5fcfc9c818497bd82`

## Authoritative manufacturer/transport escape evidence

**A field's literal source slice is distinct from vendor-decoded meaning.** Neither a device family name in an external record nor a valid lexical token proves device firmware version, wire format, and exact escape semantics. The current originals lack complete independently pinned device-version and configured syslog format evidence. Therefore **NOT_CERTIFIED** applies to every manufacturer.

| Explicit wire scope | Source contract documented | What remains unverified |
| --- | --- | --- |
| FortiOS 7.2-series native RAW/FGT | Fortinet reference describes raw log display and separate CEF support | Whether a backslash-escaped special character in a specific RAW firmware release is literal or decoded on the wire |
| FortiOS 7.2-series CEF | CEF mapping strips quotes and escapes slash, equals and backslash in the **CEF extension** | Cannot import this CEF rule into native FGT; no pinned emitted raw packet + expected decoded oracle for each firmware mode |
| RFC5424 structured data | RFC5424 §6.3.3 defines escaping of quote, backslash and right bracket **within SD-PARAM**; other slash sequences stay unchanged | Not a license to apply SD decoding to RFC5424 MSG, RFC3164 or a manufacturer's native KV body |
| SonicOS 7.1 Default, Enhanced, ArcSight CEF | Official SonicWall guide documents **selectable distinct formats** and configurable fields | No authoritative per-value escape behavior pinned for the observed source's version/mode |
| Sophos Firewall 20.0 Standard / legacy | Official Sophos guide differentiates standard syslog and module-specific legacy format | No proven per-value escape semantics for each independently observed original source |

Pinned manufacturer/standards references checked 2026-10-17:
- Fortinet FortiOS 7.2.0 CEF mapping: https://docs.fortinet.com/document/fortigate/7.2.0/fortios-log-message-reference/998820/fortios-to-cef-log-field-mapping-guidelines
- Fortinet 7.2.7 RAW reference scope: https://docs.fortinet.com/document/fortigate/7.2.7/fortios-log-message-reference/86230/before-you-begin
- IETF RFC5424 §6.3.3: https://www.rfc-editor.org/rfc/rfc5424.html
- SonicWall SonicOS 7.1 syslog settings: https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-device_log/Content/Logs_Syslog/logs-syslog-settings.htm
- Sophos Firewall 20.0 syslog configuration: https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/SystemServices/LogSettings/SyslogServerAdd/

`src/poc/transportEscapeReview.ts` and its isolated tests distinguish obvious CEF, RFC5424, and KV signatures, require declared wire mode and device version for manufacturer evidence, and explicitly **never decode or promote** based on documentation alone. The observed signature remains a format *hint*, not a verified device identity. CEF extension escapes and RFC5424 structured-data escapes are not conflated with FGT native log escaping.

## Reproduce affected verification

```sh
python3 -m unittest scripts/poc/testSourceKvUtf8SpanOracle.py -v
python3 scripts/poc/createSourceKvUtf8SpanOracle.py
python3 scripts/poc/createAdditionalKvUtf8SpanOracle.py
node_modules/.bin/vite-node scripts/poc/runSourceKvUtf8ByteSpanAudit.ts
node_modules/.bin/vite-node scripts/poc/runAdditionalKvUtf8SpanAudit.ts
node_modules/.bin/vite-node scripts/poc/runSourceKvUtf8SpanSafetyReplay.ts
node_modules/.bin/vitest run src/poc/conservativeKvUtf8Span.test.ts src/poc/sourceKvSpanReviewGate.test.ts src/poc/transportEscapeReview.test.ts
npm run typecheck
npm test
npm run build
```

The private source directories must already exist for the two audit runners. Exact-head GitHub CI should validate the same PoC commit; CI is not a vendor or native parser qualification. This PoC is stacked on PR #40 only, not merged.

## Product backlog (explicitly **NOT** authorized in this PoC)

At product branch `da94aa9`, carry **R1 P0** (Junos residual 5/100 assisted records, Defender-style endpoint generation/compilation, Umbrella Proxy 23-column quoted CSV), **R2 P1** (beginner progress feedback for 100–400 events), **R3 P0** (owner visual acceptance: Review Fields → Map Fields → Create Parser, mapping overrides and mobile UX), and **R4 owner gate** (same-HEAD full CI/provenance/browser/Full User E2E, separate release authorization). NORM-01..07 completed scope is not repeated. DP upload, sensors and live target-index readback are excluded from the recorded product completion gates. No product integration is permitted by this PoC.

## Next remaining evidence

A source packet + producer/transport/version configuration and externally verified decoded expected output are needed to *certify* FortiOS native FGT/CEF and SonicWall/Sophos escapes. Unproven semantics must remain `NOT_CERTIFIED`/`SOURCE_UNSCORABLE`; independent lexical source matches alone do not establish vendor semantics or native parser compatibility.
