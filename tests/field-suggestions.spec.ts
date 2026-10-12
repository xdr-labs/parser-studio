import { expect, test } from '@playwright/test';

test('guided user adds all safe unmapped CEF fields with one explicit click', async ({ page }) => {
  let backendCalls = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) backendCalls++;
  });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Synthetic starter template').selectOption('cef');
  await page.getByRole('button', { name: 'Apply Synthetic Template' }).click();
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await expect(page.locator('.guided-extracted-tags')).toContainText('cef_version');
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  const add = page.getByRole('button', { name: /Add Remaining Safe Fields/ });
  await expect(add).toBeEnabled();
  await add.click();
  await expect(page.getByLabel('Source field 3')).toHaveValue('cef_version');
  await expect(page.getByLabel('Destination field 3')).toHaveValue('custom.cef_version');
  await expect(add).toBeDisabled();
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: 'Failures' }).locator('strong')).toHaveText('0');
  expect(backendCalls).toBe(0);
  await page.getByRole('button', { name: 'Save Draft' }).click();
  const stored = await page.evaluate(() => JSON.stringify(localStorage));
  expect(stored).not.toContain('CEF:0|');
});
