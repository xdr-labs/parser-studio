import { expect, test } from '@playwright/test';

test('browser preview refuses known pathological regex before running untrusted backtracking', async ({page}) => {
  let backendRequests=0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) backendRequests++;
  });
  await page.goto('/');
  await page.getByRole('button',{name:'Workbench'}).click();
  await page.getByLabel('Input format').selectOption('regex');
  await page.getByLabel('Named-group regular expression').fill('(?<x>(a|aa)+)$');
  await page.locator('#sample-textarea').fill('a'.repeat(50)+'!');
  await page.getByRole('button',{name:'Run suite'}).click();
  await expect(page.getByText('Browser suite executed')).toBeVisible();
  await expect(page.locator('.report-table tbody tr')).toHaveCount(1);
  await page.locator('.report-table tbody tr').first().click();
  await expect(page.locator('.diagnostic.error')).toContainText('Regex uses an unsupported or potentially expensive construct');
  expect(backendRequests).toBe(0);
});
