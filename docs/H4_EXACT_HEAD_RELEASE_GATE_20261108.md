# H4 release candidate CI gate (owner-approved operator procedure)

**Scope:** source-controlled, read-only GitHub CI evidence verification before
explicitly authorized merge/development-preview rollout. This is **not**
GitHub-enforced branch protection, a production release authorization,
a Fluentd or DP certification, or an API for arbitrary user-supplied Ruby.

## Exact-HEAD pre-merge evidence

The operator runs the following command on the same reviewed PR HEAD:

```bash
python3 scripts/verification/h4_exact_head_release_gate.py \
  --repo xdr-labs/parser-studio \
  --pr <reviewed-main-target-pr> \
  --run-id <that-pr-exact-head-pull-request-actions-run-id> \
  --sha <full-forty-character-reviewed-head-sha>
```

The gate uses the authenticated GitHub CLI in read-only mode. It refuses a
different repository, a Draft/closed PR, a PR not targeting `main`, a stale
head SHA or failing/incomplete Actions run. All eight **named** jobs must
pass: main `web-quality`, the isolated fixed synthetic Native Fluentd
runner and six Chromium browser shards. Both sanitized native report
artifacts must be present and unexpired in the **same** successful Actions
run. Error output uses fixed non-source-bearing codes. The gate does not
rewrite or repair failing evidence. Each negative behavior has a local
red/green unit regression.

## Current platform limit

As checked on November 8, 2026, GitHub returns HTTP 403 for both repository
branch protection and repository rulesets on this **private** repository,
with the message that GitHub Pro is required or the repository must be made
public. The repository **must not** be made public to bypass the restriction.
Therefore the script is an explicitly run, owner-approved **operator-side**
gate; it cannot prevent an unrelated GitHub identity from merging without
using this command. Engineering `merge_gate_status` remains `advisory`
until a supported GitHub-enforced branch policy is actually installed and
independently verified. Do not label H4 enforcement COMPLETE.

GitHub CI green does not establish Stellar Cyber DP 7.0 import/receive. For
H5, target verification requires an independently designated, authorized DP
7.0 lab, actual generated pair import, physical event reception and
independent field/diagnostic comparison. A synthetic-only native receipt must
retain `targetVerified=false`.

## Deployment procedure constraints

The development-preview rollout requires a separate staged candidate build
and checked hashes, original service/config backup, loopback health preflight,
atomic code promotion, a site-specific first-user Chromium acceptance test
and rollback verification. The merge gate itself **does not deploy**.
