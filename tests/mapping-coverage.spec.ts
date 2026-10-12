import { expect, test } from '@playwright/test';

test('field mapping card explains missing and type-invalid samples, then opens failing event', async ({ page }) => {
  const samples = [
    '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
    '{"action":"deny","src_ip":"invalid-ip","dst_port":22}',
    '{"action":"allow","dst_port":80}',
  ].join('\n');
  let backendRequests = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) backendRequests++;
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(samples);
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  const coverage = page.getByLabel('Mapping coverage 0');
  await expect(coverage).toContainText('source 2/3');
  await expect(coverage).toContainText('Normalized 1/3');
  await expect(coverage).toContainText('Missing 1');
  await expect(coverage).toContainText('Type Errors 1');
  await coverage.getByRole('button', { name: 'Inspect mapping issue 0' }).click();
  await expect(page.locator('.guided-step.active')).toContainText('Extract Fields');
  await expect(page.getByLabel('Guided selectable raw event')).toContainText('invalid-ip');
  expect(backendRequests).toBe(0);
});
