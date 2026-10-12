import { expect, test } from '@playwright/test';

test('three-pane editor displays per-event counts, format and unverified export states', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sample logs' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Parser pipeline' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live result' })).toBeVisible();
  await expect(page.locator('footer.status-strip')).toContainText('Dataset 3');
  await expect(page.locator('footer.status-strip')).toContainText('Failed 1');
  await page.getByRole('tab', { name: 'EXTRACTED' }).click();
  await expect(page.locator('.code-output')).toContainText('src_ip');
  await page.getByRole('tab', { name: 'RAW' }).click();
  await expect(page.locator('.code-output')).toContainText('198.51.100.10');
  await page.screenshot({ path: test.info().outputPath('workbench-desktop.png'), fullPage: true });
  await page.getByRole('button', { name: 'Export & History' }).click();
  await expect(page.getByRole('heading', { name: 'Fluentd configuration' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Stellar Cyber parser' })).toBeVisible();
  await expect(page.getByText('Export unavailable')).toHaveCount(2);
  expect(errors).toEqual([]);
});

test('selected log token produces editable regex and tests all samples before application', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await page.getByLabel('PASTE RAW EVENTS').fill('src=198.51.100.4 status=ok\nsrc=198.51.100.5 status=ok');
  await page.getByRole('tab', { name: 'RAW' }).click();
  await expect(page.locator('footer.status-strip')).toContainText('Dataset 2');
  const rawEvent = page.locator('.raw-inspector .raw-view');
  await rawEvent.evaluate((element) => {
    const node = element.firstChild!;
    const text = node.textContent ?? '';
    const start = text.indexOf('198.51.100.4');
    if (start === -1) throw new Error('Expected synthetic token was absent');
    const range = document.createRange();
    range.setStart(node, start);
    range.setEnd(node, start + '198.51.100.4'.length);
    window.getSelection()?.removeAllRanges();
    window.getSelection()?.addRange(range);
    element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
  });
  await expect(page.getByRole('heading', { name: 'Propose a field from source value' })).toBeVisible();
  await page.getByRole('textbox', { name: 'New field name' }).fill('source_ip');
  await expect(page.getByRole('button', { name: 'Apply as draft rule' })).toBeDisabled();
  await page.getByRole('button', { name: 'Preview all samples' }).click();
  await expect(page.getByRole('status')).toContainText('Matched 2 / 2 sample events');
  await page.getByRole('button', { name: 'Apply as draft rule' }).click();
  await expect(page.getByRole('textbox', { name: 'Source for' }).last()).toHaveValue('source_ip');
  await expect(page.locator('footer.status-strip')).toContainText('Matched 2');
  await expect(page.locator('footer.status-strip')).toContainText('Fluentd & Stellar: NOT VERIFIED');
});

test('failed sample is visible in test lab, and rule-only revisions reopen without samples', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await page.getByRole('button', { name: 'Run suite' }).click();
  await expect(page.getByRole('heading', { name: 'Fixture runs & diagnostics' })).toBeVisible();
  await expect(page.getByText('Browser suite executed')).toBeVisible();
  await expect(page.locator('.metric-grid')).toContainText('Failed');
  await expect(page.locator('.report-table tbody tr')).toHaveCount(3);
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await page.getByLabel('Parser project name').fill('Example Test Parser');
  await page.getByRole('button', { name: 'Save revision' }).click();
  await page.getByRole('button', { name: 'Parser Library' }).click();
  await expect(page.getByRole('heading', { name: 'Example Test Parser' })).toBeVisible();
  await page.getByRole('button', { name: /Example Test Parser/ }).click();
  await expect(page.getByLabel('Guided parser name')).toHaveValue('Example Test Parser');
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue('');
  await expect(page.locator('footer.status-strip')).toContainText('Dataset 0');
});

test('narrow devices show panels without browser-wide horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sample logs' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Parser pipeline' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live result' })).toBeVisible();
  const width = await page.evaluate(() => ({ doc: document.documentElement.scrollWidth, viewport: innerWidth }));
  expect(width.doc).toBeLessThanOrEqual(width.viewport + 1);
  await page.screenshot({ path: test.info().outputPath('workbench-mobile.png'), fullPage: true });
});
