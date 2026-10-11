# Backend CI Setup — GitHub workflow scope limitation

The [backend-pair.workflow.yml](backend-pair.workflow.yml) is only a **template** under `backend/docs`. It is not installed at `.github/workflows` and will not execute on PRs yet.

On 2026-10-12 GitHub refused a backend workflow push with:

> refusing to allow an OAuth App to create or update workflow `.github/workflows/backend-pair.yml` without `workflow` scope

Do not bypass the GitHub OAuth permission boundary. A maintainer with appropriate authorization can install this workflow later, after reviewing it against Engineering System and running it on the intended exact PR HEAD. The permission limit is **not a blocker to testing backend code in the separate development runtime**.

## Reproducible local qualification

On the isolated dev-drlink backend checkout, Node 22 and project-local Ruby 3.2.3 were used with Fluentd 1.17.1 and test-unit 3.6.7 locked by `Gemfile.lock`.

```sh
cd backend
npm ci
# Use isolated Ruby and the exact locked Gemfile dependencies.
bundle install
bash scripts/qualify.sh
```

Tests include JSON/KV/CSV/RFC5424/CEF/LEEF formats, typed mapping, ordered enrichment and category routing, generated Ruby fragment callbacks, and **Fluentd 1.17.1 actual Parser Plugin and config AST checks**. The fixed td-agent transport include path is removed only in memory for config parsing.

Current synthetic qualification additionally runs 10 golden events against exact expected Fluentd parser callback records (eight source profiles), verifies the golden source SHA-256 and the existing 8 import + 8 tamper cases. These checks are available locally even while GitHub backend Actions workflow remains uninstalled.

The report is `.tmp/synthetic-native-report.json`, ignored by Git. It records branch HEAD, dirty state, hashes and the explicit `targetImportVerified:false`.

**This is not** a complete Stellar Cyber loader test, live Fluentd listener check or a customer raw-log E2E. The user retains responsibility for final real Stellar Cyber application/acceptance. Do not alter `rickmodular`.
