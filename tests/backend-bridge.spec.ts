import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

const backendCapabilities = {
  contract: 'host-customized-pair.v0.1', projectSchemaRevision: '0.1',
  authoring: { receiverProtocols: ['udp', 'tcp'], extractionFormats: ['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef'],
    formatCoverage: 'reviewed-bounded-subset', multiline: false, arbitraryRuby: false,
    httpReceiver: false, multipleDistinctReceiverPorts: false },
  import: { exactInternalPairsEditable: true, unknownLegacyRubyEditable: false, structuralInspectionOnly: true },
  verification: { engineVerified: false, targetImportVerified: false, liveListenerVerified: false, proprietaryLoaderVerified: false },
  limits: { maxProjectBodyBytes: 262144, maxInspectBodyBytes: 2097152 },
};

test.beforeEach(async ({ page }) => {
  if (process.env.PARSER_STUDIO_LIVE_BACKEND === '1') return;
  await page.route('**/api/v1/parser-pairs/capabilities', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(backendCapabilities),
  }));
});

const sample = [
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

async function readyForBackend(page: import('@playwright/test').Page) {
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(sample);
  await page.getByRole('button', { name: 'Next Step' }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await expect(page.locator('.guided-test-metrics')).toContainText('Input Events');
  await expect(page.locator('.guided-test-metrics')).toContainText('2');
  await expect(page.locator('.guided-test-metrics')).toContainText('Failures');
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
}

test('explicit backend validation and draft pair generation downloads two exact SHA-verified files', async ({ page }) => {
  const captures: unknown[] = [];
  const conf = '# TEST ONLY - generated fluentd conf\n<source>\n  @type udp\n</source>\n';
  const ruby = '# TEST ONLY - extensionless Ruby snippet\ndef parse(text)\n  yield nil, {}\nend\n';
  const files = [
    { name: 'customized_demo_firewall.conf', content: conf, sha256: sha(conf), bytes: Buffer.byteLength(conf, 'utf8') },
    { name: 'customized_demo_firewall', content: ruby, sha256: sha(ruby), bytes: Buffer.byteLength(ruby, 'utf8') },
  ];
  await page.route('**/api/v1/parser-pairs/validate', async (route) => {
    captures.push(route.request().postDataJSON());
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, issues: [] }) });
  });
  await page.route('**/api/v1/parser-pairs/generate', async (route) => {
    captures.push(route.request().postDataJSON());
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      contract: 'host-customized-pair.v0.1',
      files,
      manifest: {
        status: 'DRAFT', contract: 'host-customized-pair.v0.1', schemaRevision: '0.1',
        engineVerified: false, targetImportVerified: false,
        fileHashes: Object.fromEntries(files.map((file) => [file.name, file.sha256])),
        warnings: ['Native Fluentd/target compatibility NOT VERIFIED'],
      },
    }) });
  });
  await readyForBackend(page);
  expect(captures).toHaveLength(0);
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
  await page.getByRole('button', { name: 'Validate Backend Input' }).click();
  await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (DRAFT)' })).toBeEnabled();
  await page.getByRole('button', { name: 'Generate 2 Parser Files (DRAFT)' }).click();
  await expect(page.getByLabel('Generated draft parser pair')).toContainText('2 DRAFT Files · SHA-256 Verified');
  await expect(page.getByLabel('Generated draft parser pair')).toContainText('Native Fluentd/target compatibility NOT VERIFIED');
  expect(captures).toHaveLength(2);
  for (const body of captures) {
    const encoded = JSON.stringify(body);
    expect(encoded).not.toContain('198.51.100.10');
    expect(encoded).not.toContain('203.0.113.5');
    expect((body as { receiver: { port: number } }).receiver.port).toBe(7501);
  }
  for (const expected of files) {
    const downloading = page.waitForEvent('download');
    await page.getByRole('button', { name: expected.name, exact: true }).click();
    const item = await downloading;
    expect(item.suggestedFilename()).toBe(expected.name);
    expect(await readFile(await item.path(), 'utf8')).toBe(expected.content);
  }
});

test('HTTP 422 backend validation errors stop draft generation and expose code and field', async ({ page }) => {
  await page.route('**/api/v1/parser-pairs/validate', (route) =>
    route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({
      ok: false, issues: [{ code: 'unmapped_classification_field', path: '/classification/rules/0', message: 'Sample backend rejected the normalized route' }],
    }) }));
  await readyForBackend(page);
  await page.getByRole('button', { name: 'Validate Backend Input' }).click();
  await expect(page.getByLabel('Backend validation errors')).toContainText('unmapped_classification_field');
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
});

test('SHA mismatch cannot become a downloadable or verified parser', async ({ page }) => {
  await page.route('**/api/v1/parser-pairs/validate', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, issues: [] }) }));
  await page.route('**/api/v1/parser-pairs/generate', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      contract: 'host-customized-pair.v0.1',
      files: [
        { name: 'customized_demo_firewall.conf', content: 'bad', bytes: 3, sha256: '0'.repeat(64) },
        { name: 'customized_demo_firewall', content: 'bad', bytes: 3, sha256: '0'.repeat(64) },
      ],
      manifest: {
        status: 'DRAFT', contract: 'host-customized-pair.v0.1', schemaRevision: '0.1',
        engineVerified: false, targetImportVerified: false,
        fileHashes: { 'customized_demo_firewall.conf': '0'.repeat(64), customized_demo_firewall: '0'.repeat(64) },
        warnings: [],
      },
    }) }));
  await readyForBackend(page);
  await page.getByRole('button', { name: 'Validate Backend Input' }).click();
  await page.getByRole('button', { name: 'Generate 2 Parser Files (DRAFT)' }).click();
  await expect(page.getByRole('alert')).toContainText('SHA-256');
  await expect(page.getByLabel('Generated draft parser pair')).toHaveCount(0);
});


test('live isolated backend PR4 validates, generates, hashes and downloads real DRAFT pair', async ({ page }) => {
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND !== '1',
    'Live backend is opt-in and must be bound only to localhost in isolated development.');
  const posted: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/v1/parser-pairs/')) posted.push(request.postData() ?? '');
  });
  await readyForBackend(page);
  await page.getByRole('button', { name: 'Validate Backend Input' }).click();
  await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
  const generating = page.waitForResponse((response) =>
    response.url().includes('/api/v1/parser-pairs/generate'));
  await page.getByRole('button', { name: 'Generate 2 Parser Files (DRAFT)' }).click();
  const response = await generating;
  expect(response.status()).toBe(200);
  await expect(page.getByLabel('Generated draft parser pair')).toContainText('2 DRAFT Files · SHA-256 Verified');
  await expect(page.getByText('Parser Draft Generated · DRAFT')).toBeVisible();
  expect(posted).toHaveLength(2);
  for (const body of posted) {
    expect(body).not.toContain('198.51.100.10');
    expect(body).not.toContain('203.0.113.5');
    // Classification predicates intentionally carry allow/deny strings.
    // The raw sample events and their IP values must not be transmitted.
    expect(body).not.toContain('"src_ip":"198.51.100.10"');
  }
  const artifacts: Record<string, string> = {};
  for (const name of ['customized_demo_firewall.conf', 'customized_demo_firewall']) {
    const downloading = page.waitForEvent('download');
    await page.getByRole('button', { name, exact: true }).click();
    const file = await downloading;
    expect(file.suggestedFilename()).toBe(name);
    artifacts[name] = await readFile(await file.path(), 'utf8');
  }
  expect(artifacts['customized_demo_firewall.conf']).toContain('@type udp');
  expect(artifacts['customized_demo_firewall']).toContain('STELLAR_PARSE_BEGIN');
  // Any input change invalidates the displayed generation/validation evidence.
  await page.getByRole('button', { name: /1\. Import Logs/ }).click();
  await page.getByLabel('Guided raw sample logs').fill(sample + '\n{"action":"allow","src_ip":"198.51.100.1","dst_port":443}');
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await expect(page.getByLabel('Generated draft parser pair')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
});
