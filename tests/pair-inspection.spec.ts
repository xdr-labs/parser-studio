import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';

const conf = '<source>\n  @type udp\n  port 5514\n</source>\n';
const fragment = '# synthetic parser\n';
const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const capabilities = {
  contract: 'host-customized-pair.v0.1', projectSchemaRevision: '0.1',
  authoring: { receiverProtocols: ['udp', 'tcp'], extractionFormats: ['json', 'kv', 'csv'],
    formatCoverage: 'reviewed-bounded-subset', httpReceiver: false,
    multipleDistinctReceiverPorts: false, multiline: false, arbitraryRuby: false },
  import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
  verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
  limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
};
test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/parser-pairs/capabilities', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(capabilities),
  }));
});
async function choosePair(page: import('@playwright/test').Page, fragmentName = 'customized_demo_fw') {
  await page.goto('/');
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await page.locator('.guided-pair-inspect summary').click();
  await page.getByLabel('Inspect pair CONF').setInputFiles({
    name: 'customized_demo_fw.conf', mimeType: 'text/plain', buffer: Buffer.from(conf),
  });
  await page.getByLabel('Inspect pair Ruby fragment').setInputFiles({
    name: fragmentName, mimeType: 'text/plain', buffer: Buffer.from(fragment),
  });
}
test('legacy pair inspection is opt-in, read-only and never echoes source code', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/v1/parser-pairs/inspect', route => {
    requests++;
    expect(route.request().postDataJSON()).toMatchObject({
      name: 'customized_demo_fw', confContent: conf, fragmentContent: fragment,
    });
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      format: 'host-customized-pair', name: 'customized_demo_fw',
      originalHashes: { conf: hash(conf), fragment: hash(fragment) },
      receiver: { protocols: ['udp'], ports: [5514], sourceCount: 1 },
      fragment: { markersComplete: false, hasParseEntry: false, opaqueRuby: true },
      importStatus: 'OPAQUE_READ_ONLY', roundTripVerified: false, portableProject: null,
      diagnostics: [{ code: 'PAIR_NOT_REPRODUCIBLE', severity: 'warning', message: fragment }],
      warnings: [fragment],
    }) });
  });
  await choosePair(page);
  expect(requests).toBe(0);
  await page.getByRole('button', { name: 'Inspect Selected Pair (Read-only)' }).click();
  const result = page.getByLabel('Parser pair inspection results');
  await expect(result).toContainText('OPAQUE READ-ONLY');
  await expect(result).toContainText('PAIR_NOT_REPRODUCIBLE');
  await expect(result).toContainText('5514');
  await expect(result).not.toContainText(fragment);
  expect(requests).toBe(1);
});
test('mismatched pair file names stop before any API submission', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/v1/parser-pairs/inspect', route => {
    requests++;
    return route.abort();
  });
  await choosePair(page, 'customized_wrong');
  await page.getByRole('button', { name: 'Inspect Selected Pair (Read-only)' }).click();
  await expect(page.getByRole('alert')).toContainText('Matching customized_');
  expect(requests).toBe(0);
});
