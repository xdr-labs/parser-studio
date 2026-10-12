import { expect, test } from '@playwright/test';

const STEPS = [
  'Import Logs',
  'Extract Fields',
  'Map Fields',
  'Receive & Classify',
  'Test & Fix',
  'Generate Files',
] as const;
const NON_ENGLISH_COPY = /[\uAC00-\uD7A3\u3040-\u30FF\u3400-\u9FFF]/u;

test('Guided Builder presents six English-only steps, labels and accessibility metadata', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('heading', { name: /Build a custom parser/ })).toBeVisible();

  for (const [i, label] of STEPS.entries()) {
    await page.getByRole('button', { name: new RegExp(String(i + 1) + '\\. ' + label) }).click();
    const heading = page.locator('.guided-content-head h2');
    await expect(heading).toBeVisible();
    const visible = await page.locator('body').innerText();
    expect(NON_ENGLISH_COPY.test(visible), 'Visible UI must not contain untranslated product copy').toBe(false);
  }

  await expect(page.getByRole('button', { name: 'Previous' })).toBeVisible();
});

test('English-only status and errors remain clear when offline backend is unavailable', async ({ page }) => {
  await page.route('**/api/v1/parser-pairs/capabilities', (route) =>
    route.fulfill({ status: 503, body: '{"error":"unavailable"}', contentType: 'application/json' }));
  await page.goto('/');
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await page.locator('.guided-backend-synthetic summary').click();
  await page.getByRole('button', { name: 'Preview Backend Public Synthetic Sample' }).click();
  await expect(page.locator('.guided-backend-synthetic [role="alert"]')).toBeVisible();
  const error = await page.locator('.guided-backend-synthetic [role="alert"]').innerText();
  expect(error.length).toBeGreaterThan(8);
  expect(NON_ENGLISH_COPY.test(error)).toBe(false);
});
