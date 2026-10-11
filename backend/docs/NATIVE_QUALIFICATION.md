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

`scripts/qualify.sh` works with `PARSER_RUBY_BIN` or its project-local Ruby fallback if present. It checks Node validation/generator/API, builds eight synthetic artifact pairs, Ruby fragment syntax, pure Ruby callbacks, and actual Fluentd 1.17.1 Parser Plugin driver + native Fluent config AST (using an in-memory removal of the production-only transport include).

The run also executes test_native/golden_events_smoke.rb through Fluentd's Parser Test Driver, comparing 10 fixed synthetic event inputs to full independently authored expected normalized records on all eight generated formats. It uses the public-synthetic JSON fixture in test_native/fixtures and writes an ignored .tmp/synthetic-golden-report.json recording the fixed input SHA-256 and pinned runtime. The final synthetic native report validates this hash, the ten PASS cases and eight profiles, alongside the pair import checks. Neither report attests to proprietary loader/receiver operation.

The generated `.tmp/synthetic-native-report.json` includes HEAD, worktree-dirty state, SHA-256 hashes and explicit `targetImportVerified:false`. An uncommitted/dirty run is **not** exact-HEAD qualification; commit and rerun before asserting exact-HEAD PASS.

## Real scope of native verification

Verified on synthetic examples: JSON, strict KV, CSV, RFC5424 Syslog, standalone CEF and LEEF, typed normalization, stage+field error diagnostics, ordered enrichment, event classification, emitted UDP/TCP config parse syntax and Fluentd Parser Plugin API callback behavior.

Not verified: vendor's proprietary plugin assembly/loading from the extensionless Ruby fragment, transport include on the running td-agent, actual listener/network behavior, official portal import format, customer data correctness, other parsers from 454-reference corpus, or production use.

## Bounded RFC5424 Structured Data subset

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
