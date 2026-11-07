# H2: Isolated Native Ruby / Fluentd CI security boundary

**Scope:** GitHub-hosted CI only, fixed independently authored synthetic
examples. This is an incremental H2 implementation, **not** a public Native
verification service, customer parser execution permission, Stellar Cyber
Data Processor qualification, or deployment authorization.

## Threat model and enforcement

A compiled parser fragment is executable Ruby and therefore must be treated
as untrusted code. The old local Native adapter uses resource-limited process
execution and is **not** an adequate boundary for a publicly accessible
authoring server. The dedicated CI adapter instead requires a prebuilt
immutable local Docker image ID and sends only a compiler-prepared, hash-bound
project payload on stdin. The Ruby/Fluentd fixture runner verifies the exact
generated fragment/.conf hashes, receiver AST, event outputs, times and
independent expected record hashes. It returns only sanitized hashes/counts.

Runtime isolation is enforced using an ephemeral GitHub-hosted runner plus
`docker run` with all of these fixed options: no network, no IPC sharing,
read-only filesystem, only a 32 MiB noexec/nosuid/nodev temporary filesystem,
non-root UID/GID 65532, all Linux capabilities dropped, no-new-privileges,
default Docker seccomp, no bind mounts, no socket mounts, no host PID or
device access, at most 64 processes, 768 MiB memory, one CPU, 25 CPU seconds,
35 wall seconds and a bounded output size. The Docker CLI is invoked with
`spawn`, never through a shell. The exact local image ID must match
`sha256:[a-f0-9]{64}`; names are generated, bounded and non-user controlled.

The Ruby process sees no production secrets, GitHub workspace mount, Docker
socket or outbound network. Its stderr is consumed but never displayed or
included in CI artifacts. Errors are stable, non-source-bearing codes.
A timeout/output excess kills the Docker CLI and requests force removal of
its exact ephemeral container. `--rm` handles normal cleanup.

The image is built from the fixed official Ruby 3.2.11 Bookworm multiarch
image digest and installs only gems matching the checked-in Gemfile.lock
(Fluentd 1.17.1 and test-unit 3.6.7). The build stage may contact official
registry/gem sources; **the runtime has no network**. Its built image ID is
recorded alongside Ruby, Fluentd, parser/conf, fixture and result hashes.

## Limits and residual risks

- Ruby 3.2.11 reached end of upstream security support on March 27, 2026.
  This pinned profile reproduces a historical parser compatibility contract
  in throwaway CI; it **must not** be repurposed as production infrastructure.
- Docker isolation lowers exposure but is not a proof of full kernel isolation.
  A future customer-input sandbox needs independent container/image review,
  vulnerability scanning, tested host hardening and explicit owner approval.
- A fully pinned image digest and locked dependencies reduce drift; the CI
  dependency-build network is still a supply-chain trust boundary.
- This job tests one fixed synthetic project; it does not claim arbitrary
  customer ParserRecipe reliability or Native conformance for every grammar.
- Source hash matches and successfully executed Fluentd parser callbacks do
  not establish import, routing or receive proof on Stellar Cyber DP 7.0.

## Acceptance evidence

The `isolated-native-quality` GitHub Actions job is distinct from existing
`web-quality` work. It must run the fail-closed Docker policy unit tests,
build the pinned image, execute the exact parser pair in a network-disabled
runtime, assert two independently authored synthetic outputs and upload a
sanitized `parser-studio-h2-isolated-native-evidence` receipt. An unavailable
Docker daemon, missing image, altered output or an execution error **fails CI**;
it never silently skips native verification.

No code path attaches this adapter to the HTTP server. Release policy remains
advisory; the job's presence alone does not change branch protection. H2
feature-flagged development preview is deliberately **disabled** pending
separate safety review and approval. H3 full grammar corpus, H4 enforced merge
gates and H5 actual DP target evidence remain open.
