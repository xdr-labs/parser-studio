import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('workbench shows all three panes and honest local statuses', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench' }).click();
  await expect(page.getByRole('region', { name: 'Sample logs' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Parser pipeline rules' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Preview results' })).toBeVisible();
  await expect(page.getByText('Fluentd & Stellar: NOT VERIFIED')).toBeVisible();

  const left = await page.locator('.sample-pane').boundingBox();
  const middle = await page.locator('.rules-pane').boundingBox();
  const right = await page.locator('.results-pane').boundingBox();
  expect(left && middle && right).toBeTruthy();
  expect(Math.abs(left!.y - middle!.y)).toBeLessThan(3);
  expect(Math.abs(left!.y - right!.y)).toBeLessThan(3);

  await expect(page.getByRole('button', { name: 'Run suite' })).toBeEnabled();
  await page.screenshot({ path: 'fixtures/private/workbench.png', fullPage: true });
});

test('local suite exposes all events and the exact failing fields', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench' }).click();
  await page.getByRole('button', { name: 'Run suite' }).click();
  await expect(page.getByText('Browser suite executed')).toBeVisible();
  await expect(page.locator('.report-table tbody tr')).toHaveCount(3);
  await expect(page.getByText('NOT FLUENTD VERIFIED')).toBeVisible();

  await page.locator('.report-table tbody tr').nth(2).click();
  await expect(page.getByRole('region', { name: 'Preview results' })).toBeVisible();
  await expect(page.locator('.diagnostic.error')).toHaveCount(2);
  await expect(page.locator('.diagnostic.error').first()).toContainText('TYPE_ERROR');
});

test('select raw value → preview candidate → apply mapping → save local-only', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench' }).click();
  await page.getByRole('tab', { name: 'RAW' }).click();
  await expect(page.locator('.raw-view')).toContainText('198.51.100.10');
  await page.locator('.raw-view').evaluate((element) => {
    const node = element.firstChild;
    if (!node?.textContent) throw new Error('Missing raw log text');
    const value = '198.51.100.10';
    const from = node.textContent.indexOf(value);
    if (from < 0) throw new Error('Value not found');
    const range = document.createRange();
    range.setStart(node, from);
    range.setEnd(node, from + value.length);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
  });
  await expect(page.getByText('Propose a field from source value')).toBeVisible();
  await page.getByRole('button', { name: 'Preview all samples' }).click();
  await expect(page.getByText('Matched 2 / 3 sample events · browser preview only')).toBeVisible();
  await page.getByRole('button', { name: 'Apply as draft rule' }).click();
  await expect(page.locator('.mapping-row')).toHaveCount(4);

  await page.getByRole('button', { name: 'Save revision' }).click();
  await expect(page.getByText('Saved local revision')).toBeVisible();
  const local = await page.evaluate(() => JSON.stringify(localStorage));
  expect(local).toContain('selected_field');
  expect(local).not.toContain('DEMO-FW');
  await page.getByRole('button', { name: 'Parser Library' }).click();
  await expect(page.getByText('Saved parser revisions')).toBeVisible();
  await expect(page.locator('.revision-card')).toHaveCount(1);
});

test('export is only a portable draft: proprietary/native adapters locked', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench' }).click();
  await page.getByRole('button', { name: 'Export & History' }).click();
  await expect(page.getByText('Fluentd configuration')).toBeVisible();
  await expect(page.getByText('Stellar Cyber parser')).toBeVisible();
  await expect(page.getByText('Export unavailable')).toHaveCount(2);
  const dl = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download draft JSON' }).click();
  const download = await dl;
  const body = JSON.parse(await readFile(await download.path(), 'utf8'));
  expect(body.compatibility.fluentd).toBe('not-verified');
  expect(body.compatibility.stellar_cyber).toBe('pending-evidence');
  expect(body.sample_logs_included).toBe(false);
});

test('narrow viewport stacks panes without hiding diagnostics', async ({ page }) => {
  await page.setViewportSize({ width: 750, height: 850 });
  await page.goto('/');
  await page.getByRole('button', { name: 'Workbench' }).click();
  const left = await page.locator('.sample-pane').boundingBox();
  const middle = await page.locator('.rules-pane').boundingBox();
  const right = await page.locator('.results-pane').boundingBox();
  expect(left && middle && right).toBeTruthy();
  expect(middle!.y).toBeGreaterThan(left!.y);
  expect(right!.y).toBeGreaterThan(middle!.y);
  await expect(page.getByText('Fluentd & Stellar: NOT VERIFIED')).toBeVisible();
});
