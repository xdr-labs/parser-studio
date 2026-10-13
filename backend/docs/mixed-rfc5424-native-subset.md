# Strict mixed RFC5424 CEF/LEEF and standalone JSON/KV — bounded Native subset

## Scope

The **explicit mixed** extraction allowlist may now include two new fixed logical families: `rfc5424_cef` and `rfc5424_leef`. These can coexist with the existing `json`, `kv`, `cef` and `leef` families (2–4 *distinct* selections per parser). The receiving Syslog port is identical to the `.conf` source port and must be **at least 6800** when either wrapped family is selected. This change does not auto-detect an arbitrary vendor message syntax in production, and it does not enable RFC3164, unwrapped CSV or multiline streams in a mixed parser.

The Ruby dispatcher routes only exact input prefixes. A leading `<PRI>` is passed to the previously Native-reviewed **strict RFC5424 VERSION=1** parser, including mandatory offset-bearing timestamp or NILVALUE, bounded printable header fields and strict structured-data parsing. Its raw message is then classified **only if** it begins with `CEF:` or `LEEF:` and that exact wrapper family has been explicitly allowed. Only then is the existing strict CEF/LEEF body parser invoked. Invalid versions, timestamps, CEF versions, LEEF extensions, RFC3164-like headers and unsupported message bodies yield one static extraction-error result. No exception message or original log contents are surfaced in the error.

The JSON/KV/CEF/LEEF standalone routes remain byte-compatible for existing ParserProjects, and the `ParserRecipe v0.2` stage must exactly match the `ParserProject v0.1` `mixedFormats` order with no hidden additions. The checked `.conf` output uses the same TCP/UDP listener port as the sensor destination. No broad regex, user-supplied Ruby, arbitrary Syslog dispatch, auto-apply or source modification is added.

## Native evidence

The public-synthetic Native Fluentd 1.17.1 suite now includes 13 exact compiled SHA-256 Ruby/CONF profiles. `v02_mixed_rfc5424` deliberately uses four explicitly declared families: JSON and KV plus RFC5424-wrapped CEF and LEEF. The original JSON event, three additional synthetic family events and eight invalid messages undergo the real pinned Fluentd Parser Plugin callback; normalized fields, log-index classification, RFC5424 timestamp conversion, per-event count and the static failure branch are compared to independently authored golden records. An exact `.conf` AST/port check ensures the reserved Syslog port and file/source checksum correspond to this recipe.

This is **not** a real Stellar loader import, DP Apply or sensor/Interflow E2E. Only pinned public-synthetic Native parser semantics are verified; all returned general API and compiled DRAFT manifests keep `engineVerified=false` / `targetImportVerified=false` and require actual target qualification before deployment.

## Remaining unsupported cases

RFC3164 mixed events (year/zone unknown), RFC5424-wrapped JSON/KV, mixed CSV, arbitrary unlabeled Syslog, Java stacktrace/multiline, proprietary headers/escaping and customer-specific Ruby remain unsupported. Unsupported events must never be automatically reassigned to KV or marked as native/target successful.
