# Parser Studio Backend CI — Active PR Workflow

The backend-only GitHub Actions workflow is installed on the backend Draft
PR branch at .github/workflows/backend-pair.yml. It runs on changes to
backend/** or the workflow file, with contents:read permissions and no
production secrets, external parser samples, DP credentials or sensor actions.

## Exact-HEAD qualification

The pull_request job explicitly checks out github.event.pull_request.head.sha
instead of GitHub's temporary PR merge commit. For pushes on main, github.sha
is selected. This is the candidate commit tested by the runner. The workflow:

1. Installs Node 22 and Ruby 3.2.x on Ubuntu 22.04.
2. Installs the locked Bundler 4.0.22 and dependencies from Gemfile.lock,
   enabling Bundler 4 frozen mode through local configuration (not --frozen).
3. Runs npm ci and bash scripts/qualify.sh.
4. Requires Node/API, Python operator safety, fixed synthetic Ruby/Fluentd
   parser/CONF, exact golden event records, tamper guards and native synthetic
   per-case evidence archive PASS on that checked-out Git HEAD.

Fluentd is locked to 1.17.1; the Ruby CI patch version can differ from the
project-local dev-atlas Ruby 3.2.3. Check the actual CI job for its Ruby version.
A successful synthetic test still DOES NOT qualify Stellar Cyber's proprietary
loader, actual DP import, sensor listener or customer Interflow E2E.

## Historical credential boundary and CI recovery

The initial attempt on 2026-10-12 to install the workflow through a different
OAuth credential was rejected because it lacked workflow scope. That operation
was not bypassed. A subsequent ordinary authorized Git push installed the
existing reviewed workflow on Draft PR #4 (commit b67ac9d). The first Actions
run #38244003529 reached dependency setup but failed because the template
used Bundler 4's removed --frozen CLI option. The option is replaced by
bundle config set --local frozen true, and the exact PR HEAD checkout is set
explicitly. CI PASS must be verified for the *new* HEAD and must never be
inferred from these past runs or from local qualification alone.

## Local reproducibility

On the development backend worktree:

    cd /home/aella/parser-studio-backend/backend
    npm ci
    # Use the existing isolated Ruby 3.2 profile and pinned Fluentd gems.
    bash scripts/qualify.sh

The script creates ignored, synthetic-only .tmp reports and a private per-HEAD
regression archive of metadata/hashes. It does not contact a DP, access the
private operator profile, start a real sensor sender, activate a parser, or
execute uploaded arbitrary Ruby. The final report includes the exact backend
HEAD, worktree dirtiness, golden fixture SHA and always-false vendor gates.

No PR merge, production deployment, release or permissions escalation follows
automatically from a passing workflow.
