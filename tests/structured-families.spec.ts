import { expect, test } from '@playwright/test';

const cap = {
  contract: 'host-customized-pair.v0.1', projectSchemaRevision: '0.1',
  authoring: {
    receiverProtocols: ['udp', 'tcp'], extractionFormats: ['json', 'kv', 'csv', 'cef', 'leef', 'syslog_rfc5424'],
    formatCoverage: 'reviewed-bounded-subset', httpReceiver: false,
    multipleDistinctReceiverPorts: false, multiline: false, arbitraryRuby: false,
  },
  import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
  verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
  limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
};
test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/parser-pairs/capabilities', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(cap),
  }));
});
const fixtures = [
  ['CEF', 'cef', 'CEF:0|Acme|FW|1|100|Denied|5|action=deny src_ip=198.51.100.7 dst_port=443'],
  ['LEEF', 'leef', 'LEEF:1.0|Acme|FW|1|100|action=deny\tsrc_ip=198.51.100.7\tdst_port=443'],
] as const;
for (const [label, format, event] of fixtures) {
  test('Guided standalone ' + label + ' extraction leads to a no-raw-logs backend contract', async ({ page }) => {
    const transmitted: unknown[] = [];
    await page.route('**/api/v1/parser-pairs/validate', route => {
      transmitted.push(route.request().postDataJSON());
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok:true, issues:[] }) });
    });
    await page.goto('/');
    await page.getByLabel('Guided raw sample logs').fill(event);
    await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
    await page.getByRole('button', { name: label, exact: true }).click();
    await expect(page.locator('.guided-extracted-tags')).toContainText('action');
    await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
    await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
    await expect(page.locator('.guided-test-metrics')).toContainText('1');
    await page.getByRole('button', { name: /6\. Generate Files/ }).click();
    await page.getByRole('button', { name: 'Validate Backend Input' }).click();
    await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
    expect(transmitted).toHaveLength(1);
    expect((transmitted[0] as {extraction: {format: string}}).extraction.format).toBe(format);
    expect(JSON.stringify(transmitted[0])).not.toContain('198.51.100.7');
  });
}
