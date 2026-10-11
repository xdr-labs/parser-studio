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

## Fixed synthetic fixture output boundary

The fixture writer uses a single ignored project-local directory, rejects a redirected PAIR_OUTPUT_DIR, and will not overwrite symlinks, hard links, unexpected file types or invalid parser filenames (Linux O_NOFOLLOW). The pinned golden runner rejects unexpected input directories and source-file symlinks before class evaluation. The qualifying script checks an explicit untrusted-path refusal. This is a defense for offline synthetic testing, not a general-purpose sandbox for customer files.

## Safety boundary

The runner only executes **repo-generated synthetic artifacts**. Never accept arbitrary customer Ruby or logs into this script. It is not a hardened, multi-user sandbox; real uploaded fixtures require separate isolated workers and limits. The HTTP server does not spawn this runner. Reference host `rickmodular` remains read-only, and the owner separately controls actual Stellar Cyber application.
