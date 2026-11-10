import test from 'node:test';
import assert from 'node:assert/strict';
import {checkDownloadSinkUsage} from './download-sink-guard.mjs';

const spec = (path, text) => ({path, text});

test('a spec that downloads files but imports test from @playwright/test directly is rejected', () => {
  const v = checkDownloadSinkUsage([spec('tests/a.spec.ts', "import {test,expect} from '@playwright/test';\nawait page.waitForEvent('download');")]);
  assert.deepEqual(v.map(x => x.rule), ['DOWNLOAD_SINK_BYPASSED']);
  assert.equal(v[0].path, 'tests/a.spec.ts');
});

test('the same spec importing the shared sink passes', () => {
  assert.deepEqual(checkDownloadSinkUsage([spec('tests/a.spec.ts', "import {test,expect} from './support/downloadSink';\nawait page.waitForEvent('download');")]), []);
});

test('specs that never mention downloads may keep the stock import', () => {
  assert.deepEqual(checkDownloadSinkUsage([spec('tests/b.spec.ts', "import {test,expect} from '@playwright/test';\ntest('x',()=>{});")]), []);
});

test('the sink module itself, legacy removed-UI tests and non-test helpers are exempt', () => {
  assert.deepEqual(checkDownloadSinkUsage([
    spec('tests/support/downloadSink.ts', "import {test as base} from '@playwright/test'; // download"),
    spec('tests/legacy-removed-ui/old.spec.ts', "import {test} from '@playwright/test'; download"),
    spec('tests/helpers.ts', "import {expect,type Page} from '@playwright/test'; download"),
  ]), []);
});

test('a spec that creates its own browser context must attach the sink to it', () => {
  const text = "import {test,expect} from './support/downloadSink';\nconst c=await browser.newContext({acceptDownloads:true});";
  assert.deepEqual(checkDownloadSinkUsage([spec('tests/c.spec.ts', text)]).map(x => x.rule), ['DOWNLOAD_SINK_OWN_CONTEXT']);
  assert.deepEqual(checkDownloadSinkUsage([spec('tests/c.spec.ts', text + "\nattachDownloadSink(c,test.info());")]), []);
});

test('a synthetic-response declaration needs a real reason, not a placeholder', () => {
  const base = "import {test,expect} from './support/downloadSink';\n";
  assert.deepEqual(checkDownloadSinkUsage([spec('tests/d.spec.ts', base + "test.use({downloadSyntheticReason:'Route-mocked compile response used only to test the download button.'});")]), []);
  assert.deepEqual(checkDownloadSinkUsage([spec('tests/d.spec.ts', base + "test.use({downloadSyntheticReason:'mock'});")]).map(x => x.rule), ['DOWNLOAD_SYNTHETIC_REASON_TOO_SHORT']);
});
