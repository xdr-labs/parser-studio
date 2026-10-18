# Parser Studio offline authoring backend acceptance

Use npm run test:authoring --prefix backend as the **product CI gate**
for the offline authoring-only backend. The script enumerates all backend
test/*.test.ts suites and explicitly excludes only four retained suites
outside the current product contract:

| Historical suite | Why not a beta acceptance gate |
| --- | --- |
| drain3-worker.test.ts | Optional separate Drain3 engine and owner-authorized worker |
| stellar-legacy-client.test.ts | Legacy Stellar device/DP write and disposable POC client |
| stellar-legacy-http.test.ts | Legacy Stellar HTTP target, updates and deletes |
| stellar-legacy-plan.test.ts | Legacy DP-scope plan and disposable target writer |

**These suites remain tracked, runnable, and NOT claimed successful.**
The earlier unfiltered npm test --prefix backend baseline on dev-atlas
reported **361 tests, 340 PASS, 12 FAIL**, with all 12 observed failures
within those four historical suites (additional skips in the original
runner are neither failures nor PASS). This is not a release-quality PASS
for the complete historical backend. Do not fix legacy target behavior
simply to meet the new offline authoring gate, reenable target operations,
or silently drop files.

The shipping command npm start --prefix backend uses the scoped
authoring-only HTTP entrypoint. Exact HTTP allowlist/denial tests, actual
browser-local user flows, DRAFT generation and QA CI are additional
independent gates; they must not be replaced by the selective unit suite.

For archival reproduction run npm test --prefix backend in an isolated
machine with no live target, credentials, sensor or DP. Diagnose its
legacy compatibility failures separately without promoting them.
