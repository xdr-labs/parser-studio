# Installed Stellar customized parser **structure**, independently observed (read-only)

Date: 2026-10-21. Host: `rickmodular` via the owner's authorized Desktop Commander/SSH connection. Scope is strictly **structure compatibility for a general-purpose security-log parser**, NOT accuracy per manufacturer, version or firmware. The device had an active `td-agent.service`; nothing was installed, restarted, or sent to it. No existing parser files, raw logs, customer payloads, secrets, or code contents were copied into the repository.

## Independent observed pair topology

Four installed customized pairs under `/etc/td-agent/conf/all-tenants` and `/etc/td-agent/plugin/all-tenants` were inspected **in place**, without changing bytes:

| Installed reference | CONF SHA-256 (first 12) | Plugin SHA-256 (first 12) |
| --- | --- | --- |
| Forti Analyzer Ackcent | `ef4011552f7f` | `ba3942193ac8` |
| Huawei Switch | `6c72317b7757` | `578440cfdbc0` |
| Monitorapp AI WAF | `25e8567d9626` | `7ee7bc2775ce` |
| Sangfor EDR | `3ef35c1c32a1` | `b4b658b6e68` |

Observed **in all 4/4**:

- A paired `customized_<slug>.conf` containing two `<source>` entries, UDP and TCP, each with matching `<parse> @type customized_<slug>` and a shared listener port; TCP includes `/etc/td-agent/transport_settings.conf`.
- Exactly one `<match customized_<slug>.**>` with `@type rewrite_tag_filter`, routing by `stellar_log_index`. **The last rule has `tag syslog` and `invert true`** so unmatched indices or a diagnostic can fall back safely to Syslog.
- The installed plugin is a full `parser_customized_<slug>.rb` file with `module Fluent; module Plugin`, an outer parser class and `Fluent::Plugin.register_parser`, plus a `StellarInnerParseClass < Parser` containing **exactly one pair of `STELLAR_INIT_BEGIN/END` and `STELLAR_PARSE_BEGIN/END` markers**. Both outer and inner parser use a `parse(text)` callback. This is the *installed wrapper*, not what the user uploads as an editor fragment.

## Parser Studio generated artifact comparison

The Browser/Backend compiler creates a **two-file DRAFT**: `customized_<slug>.conf` and extensionless `customized_<slug>` Ruby **fragment** intended for the installed wrapper's two edit regions. Comparing the fragment directly against a complete installed `.rb` must not be reported as a mismatch: the complete Fluentd registration and wrapper are provided by the host. Our fragment has the two matching markers, `initialize`, `parse(text)`, one `(time, record)` yield, `stellar_log_index`, `msg_origin`, and bounded parser error diagnostics. No claim is made that a downloaded fragment is a standalone self-registered plugin.

The generated CONF already matched protocol/source, name/reference, shared port, TCP include and rewrite matcher topology. **Actual difference reproduced**: the generated route ended with an exact Syslog match, not the `invert true` fallback observed in all four references. With non-Syslog default classification and no explicit Syslog route, the compiler also omitted an error's own `stellar_log_index=syslog` route. An independent baseline structural test reproduced two failing cases (**RED**); the fragment-marker control passed.

## Correction

The compiler now emits explicitly chosen `threat`, `session`, and/or `winlogevent` rules first, then **one final inverted `tag syslog` rule**. The inversion guard includes only those recognized, configured non-Syslog destinations, so unexpected values are not silently discarded and the fallback does not capture valid earlier classes. No vendor-specific pattern, extraction rule, 6.5/6.6 Dictionary, target API, sensor, or DP change is introduced. The default listener port remains **6801**, with user override and prior saved projects preserved.

Evidence gates: three deterministic structural assertions; existing compiler/Syslog/7.0 routing tests; native Fluentd config parsing additionally checks the last rule's `tag` and `invert` without opening a socket. New source/CI and actual development application must be verified independently before calling the correction deployed. **No production DP install or native proprietary Stellar import is part of this verification.**

## Objective and acceptance boundary

The product's target is **vendor-independent structural detection and bounded extraction**: recognize records, preserve original bytes and fields, classify fully parsed vs partial/review vs unsupported honestly, and produce a structurally compatible DRAFT when the source grammar is supported. Manufacturer/firmware-by-firmware precision and an on-device DP installation run are explicitly **out of scope**. Stellar Cyber field mapping remains fixed to public **7.0** metadata and still distinguishes approved official destinations from vendor-only/review fields. Unknown or unsupported original transport must remain blocked from confident native export.
