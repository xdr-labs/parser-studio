import { expect, test } from '@playwright/test';

test('synthetic CSV starter changes nothing until Apply and provides guided fields', async ({ page }) => {
  let backendRequests = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) backendRequests++;
  });
  await page.goto('/?workspace=guided');
  const input = page.getByLabel('Guided raw sample logs');
  const original = await input.inputValue();
  await page.getByLabel('Synthetic starter template').selectOption('csv');
  await expect(input).toHaveValue(original);
  expect(backendRequests).toBe(0);

  await page.getByRole('button', { name: 'Apply Synthetic Template' }).click();
  await expect(input).toHaveValue(/allow,198\.51\.100\.10,443/);
  await expect(page.getByLabel('Parser ID')).toHaveValue('example_csv');
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await expect(page.getByRole('button', { name: 'CSV', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Guided CSV columns')).toHaveValue('action,src_ip,dst_port');
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: 'Input Events' }).locator('strong')).toHaveText('2');
  await expect(page.locator('.guided-test-metric').filter({ hasText: 'Failures' }).locator('strong')).toHaveText('0');
  expect(backendRequests).toBe(0);
});

test('RFC5424 synthetic starter prepares field mappings and remains DRAFT-only', async ({ page }) => {
  await page.goto('/?workspace=guided');
  await page.getByLabel('Synthetic starter template').selectOption('syslog_rfc5424');
  await page.getByRole('button', { name: 'Apply Synthetic Template' }).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(/<34>1 /);
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await expect(page.getByRole('button', { name: 'RFC5424', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  await expect(page.getByLabel('Source field 0')).toHaveValue('syslog_hostname');
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: 'Failures' }).locator('strong')).toHaveText('0');
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await expect(page.getByRole('button', { name: 'Generate 2 Parser Files (Backend Required)' })).toBeDisabled();
  await expect(page.locator('.guided-pair-files')).toContainText('NOT GENERATED');
});
