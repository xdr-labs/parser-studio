# Pending backend CI workflow — permission-bound

The repository-side workflow template lives in [backend-pair.workflow.yml](backend-pair.workflow.yml). It is *not* installed in the active `.github/workflows` directory.

On the 2026-10-12 backend branch the authenticated GitHub OAuth account rejected workflow-file push with:

> refusing to allow an OAuth App to create or update workflow `.github/workflows/backend-pair.yml` without `workflow` scope

The repository's existing permissions and protected authentication were not modified. Backend source was committed separately, without a workflow-file mutation. When an authorized maintainer later adds the intended workflow, evaluate the template against the current Engineering System release/CI contracts and verify its exact code SHA.

**Actual dev-drlink evidence:** Node unit/API tests **8/8 PASS**, `npm run check` PASS and `npm run build` PASS. Ruby 3.2.3 was downloaded as signed-index Ubuntu packages and extracted to ignored project-local `.tmp/ruby-root` without modifying system packages; Ruby syntax on **three generated synthetic fragments PASS** and the Ruby callback smoke suite **8 synthetic cases PASS**. This does **not** establish a real Fluentd/plugin loader or Stellar Cyber target import, and no GitHub CI ran because workflow creation permission was denied.

Once Ruby is available in a sandbox or properly authorized CI:

```sh
cd backend
npm ci
npm run check
npm test
npm run build
node dist/scripts/create-synthetic.js
ruby -c .tmp/native-fixtures/customized_sample_firewall
ruby -c .tmp/native-fixtures/customized_sample_kv
ruby -c .tmp/native-fixtures/customized_sample_extended
ruby test_native/fragment_smoke.rb .tmp/native-fixtures
```
