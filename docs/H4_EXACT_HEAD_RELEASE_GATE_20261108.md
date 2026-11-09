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
  --work-issue 283 \
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

## GitHub-enforced branch protection (2026-11-09)

The repository is public and GitHub's `main` branch protection is **enforced**, verified by reading back its REST representation after the owner-authorized update. It requires strict up-to-date checks from GitHub Actions (the six browser shards, `web-quality` and isolated native Ruby), an actual pull request, resolution of review conversations, administrator enforcement, and no force-push or branch deletion. Approval count is zero; a specific human approval is **not** required by this policy.

The `release-eligibility` GitHub Actions job additionally queries every page of open P0 and P1 issues with a read-only token and fails closed on any match or API error. After its first successful exact-head run, add that ninth job to the required status checks and read back the protection. Engineering `merge_gate_status: enforced` describes this GitHub merge protection; the exact-SHA owner operator procedure, deployment receipts and deployment approval remain separate operational gates.

The prior November 8 private-repository HTTP 403 observation is superseded; there was no change to repository visibility to bypass protections in this release operation.

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

### Mapping Correctness v2 owner-reviewed work packet

The H4 operator command now requires `--work-issue` to identify the current
ACTIVE engineering work packet. It rejects an open packet, unchecked `- [ ]`
acceptance items, and any open repository issues labeled `P0` or `P1`
(including incomplete GitHub search results). This is an **operator check**,
not GitHub branch protection. An all-green CI run with an incomplete Mapping
Correctness v2 Issue #283 is deliberately **not release-eligible**. Verify the
exact PR and SHA again before a separately authorized merge or deployment.
