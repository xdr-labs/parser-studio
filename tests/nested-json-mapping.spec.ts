import { expect, test } from '@playwright/test';

test('guided JSON nested property is discoverable and batch mapped without sending raw data', async ({ page }) => {
  const sample = [
    '{"action":"allow","src_ip":"198.51.100.20","dst_port":443,"http":{"request":{"method":"GET"}}}',
    '{"action":"deny","src_ip":"203.0.113.10","dst_port":22,"http":{"request":{"method":"POST"}}}',
  ].join('\n');
  let apiCalls = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) apiCalls++;
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(sample);
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await expect(page.locator('.guided-extracted-tags')).toContainText('http.request.method');
  await expect(page.locator('.guided-extracted-tags')).not.toContainText('http.request.method=GET');
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  await page.getByRole('button', { name: /Add Remaining Safe Fields/ }).click();
  await expect(page.getByLabel('Source field 3')).toHaveValue('http.request.method');
  await expect(page.getByLabel('Destination field 3')).toHaveValue('custom.http_request_method');
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: 'Normalized' }).locator('strong')).toHaveText('2');
  await expect(page.locator('.guided-test-metric').filter({ hasText: 'Failures' }).locator('strong')).toHaveText('0');
  expect(apiCalls).toBe(0);
});
