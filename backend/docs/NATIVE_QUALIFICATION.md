# Backend native synthetic qualification

**Only synthetic fixtures and generated fixed templates.** This document does not claim actual Stellar Cyber installation, loader compatibility or real customer-log behavior.

## Runtime profile

- Node.js 22+, strict TypeScript and Node test runner.
- Ruby **3.2.3** (dev-drlink local project-only extracted Ubuntu packages; no global installation).
- Fluentd **1.17.1**, Ruby test-unit **3.6.7**; dependency versions pinned by `Gemfile.lock`.
- A transient local `.tmp/ruby-root` and `.tmp/gems` are ignored by Git; target `rickmodular` was not modified.

## Reproduce

```sh
cd backend
npm ci
# Install the exact Ruby/Fluentd Gemfile.lock dependency set in an isolated runner.
bundle install
bash scripts/qualify.sh
```

`scripts/qualify.sh` works with `PARSER_RUBY_BIN` or its project-local Ruby fallback if present. It checks Node validation/generator/API, builds ten synthetic artifact pairs, Ruby fragment syntax, pure Ruby callbacks, and actual Fluentd 1.17.1 Parser Plugin driver + native Fluent config AST (using an in-memory removal of the production-only transport include).

The run also executes test_native/golden_events_smoke.rb through Fluentd's Parser Test Driver, comparing 22 fixed synthetic event inputs to full independently authored expected normalized records across all ten generated parser profiles. It uses the public-synthetic JSON fixture in test_native/fixtures and writes an ignored .tmp/synthetic-golden-report.json recording the fixed input SHA-256 and pinned runtime. The final synthetic native report validates this hash, the twenty-two PASS cases and ten profiles, alongside the pair import checks. Neither report attests to proprietary loader/receiver operation.

The generated `.tmp/synthetic-native-report.json` includes HEAD, worktree-dirty state, SHA-256 hashes and explicit `targetImportVerified:false`. An uncommitted/dirty run is **not** exact-HEAD qualification; commit and rerun before asserting exact-HEAD PASS.

## Real scope of native verification

Verified on synthetic examples: JSON, strict KV, CSV, RFC5424 Syslog, standalone CEF and LEEF, typed normalization, stage+field error diagnostics, ordered enrichment, event classification, emitted UDP/TCP config parse syntax and Fluentd Parser Plugin API callback behavior.

Not verified: vendor's proprietary plugin assembly/loading from the extensionless Ruby fragment, transport include on the running td-agent, actual listener/network behavior, official portal import format, customer data correctness, other parsers from 454-reference corpus, or production use.

## Metadata fail-closed checks

The bounded RFC5424 header now requires VERSION=1, printable US-ASCII
HOSTNAME (maximum 255 octets), APP-NAME (48), PROCID (128), and MSGID (32).
A native negative suite checks unknown version, overlong headers, controls,
and non-ASCII host tokens before normalization, alongside upper bounds and
valid NILVALUE. These are RFC5424 version-one limits, not vendor compatibility.


The bounded RFC5424 extractor validates explicit UTC/offset timestamps
(or '-' NILVALUE) *before* optional normalization fields are selected.
CEF extraction explicitly accepts version 0 only; unsupported versions
produce extraction diagnostics. The native smoke suite validates the
negative raw extractor behavior, not just downstream type coercion.

## Bounded LEEF 2.0 hexadecimal separator support

LEEF 2.0 can declare a single-byte separator as 0xHH. The reviewed
subset accepts TAB or printable ASCII except space, equals or backslash;
NUL, newline, invalid hex and ambiguous separators fail closed. The
native suite checks both accepted caret/pipe encodings and negative
examples; the Capabilities API exposes leefHexSeparatorSubset=true.
This is not a claim of support for every LEEF vendor extension.

## Bounded RFC5424 Structured Data subset

The bounded RFC5424 envelope now optionally extracts explicitly selected
standalone CEF or LEEF bodies under body.*, preserving typed mapping and
RFC5424 event time. Two additional generated profiles exercise the native
Fluentd Parser API; four new synthetic golden events include both success
and malformed body rejection. This is not RFC3164, arbitrary vendor syntax
or multiline event breaker support.


RFC5424 parameter syntax is additionally checked in
test_native/rfc5424_sd_smoke.rb with two positive and nine negative
synthetic SD cases, including quoted values, escaped bracket/quote/backslash,
missing equals and quotes, duplicate IDs/parameter names and unsupported
characters. A separate Fluentd Parser API check asserts one successful
adjacent-SD event and one invalid parameter fails at the extraction stage.
Only supported SD grammar is asserted; full RFC5424 compliance remains unproven.


The native Ruby parser now retains one or more adjacent RFC5424 SD-ELEMENT
blocks with escaped right-brackets inside quoted parameter values, up to
1024 bytes of structured-data text. Tests cover normal multi-block and
escaped-bracket records and reject unterminated quotes and invalid trailers.
Full parameter semantics, RFC3164, oversized SD and multiline event breaking
remain unsupported. This is a tested parser subset, not a proprietary loader
compatibility claim.

## Format boundary regression

Four extra negative native callback scenarios enforce fail-closed behavior for
single-record non-JSON families: CEF/LEEF trailing physical newlines, CSV CRLF,
and empty LEEF 2.0 extension segments. They must produce extraction-stage
diagnostics without partially normalized events. Pretty-formatted JSON remains
an extraction-level JSON object; this does **not** implement a multiline event
breaker or validate production message boundaries.

## Fixed synthetic fixture output boundary

The fixture writer uses a single ignored project-local directory, rejects a redirected PAIR_OUTPUT_DIR, and will not overwrite symlinks, hard links, unexpected file types or invalid parser filenames (Linux O_NOFOLLOW). The pinned golden runner rejects unexpected input directories and source-file symlinks before class evaluation. The qualifying script checks an explicit untrusted-path refusal. This is a defense for offline synthetic testing, not a general-purpose sandbox for customer files.

## Per-child resource budgets

All synthetic Ruby native checks now execute through the same nonprivileged
child wrapper, limiting address space to 1 GiB and CPU time to 30 seconds,
with a 25-second wall-clock timeout (plus a two-second kill grace). A Ruby
smoke test checks the live process RLIMIT_AS/RLIMIT_CPU values before other
native Ruby checks begin. The final local qualification report records
these values and the resource-limit smoke status. These limits reduce
runaway synthetics; they are **not isolation for customer supplied Ruby**.

## Pre-execution source integrity gate

Before any generated Ruby is evaluated, all offline Ruby/Fluentd smoke harnesses read each approved fixture through a common read-only guard in test_native/synthetic_fixture_guard.rb. It checks exact project-local file paths, Linux no-follow opens, regular-file and single-link constraints, a bounded source length, and SHA-256 matching the validated generated-pair import/recompile evidence from the current Git HEAD. CONF parser sources use the same gate. A dedicated smoke test asserts altered bytes and three unsupported paths/names are rejected. The final native report records generatedFixtureSourceIntegrityChecked=true and sourceIntegrityNegativeCases=4 only after these checks run.

This reduces accidental or simple post-generation fixture substitution. The ignored local report is **not cryptographically signed**, and this execution environment is **not a sandbox** against a hostile user able to edit both source, attestation, and runner. Do not run customer-provided Ruby in it or infer Stellar Cyber plugin-loader compatibility.

## Safety boundary

The runner only executes **repo-generated synthetic artifacts**. Never accept arbitrary customer Ruby or logs into this script. It is not a hardened, multi-user sandbox; real uploaded fixtures require separate isolated workers and limits. The HTTP server does not spawn this runner. Reference host `rickmodular` remains read-only, and the owner separately controls actual Stellar Cyber application.
