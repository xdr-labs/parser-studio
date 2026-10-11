import { expect, test } from '@playwright/test';

test('guided user adds all safe unmapped CEF fields with one explicit click', async ({ page }) => {
  let backendCalls = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) backendCalls++;
  });
  await page.goto('/');
  await page.getByLabel('Synthetic starter template').selectOption('cef');
  await page.getByRole('button', { name: '합성 예제 적용' }).click();
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await expect(page.locator('.guided-extracted-tags')).toContainText('cef_version');
  await page.getByRole('button', { name: /3\. 필드 매핑/ }).click();
  const add = page.getByRole('button', { name: /안전한 남은 필드 모두 추가/ });
  await expect(add).toBeEnabled();
  await add.click();
  await expect(page.getByLabel('Source field 3')).toHaveValue('cef_version');
  await expect(page.getByLabel('Destination field 3')).toHaveValue('custom.cef_version');
  await expect(add).toBeDisabled();
  await page.getByRole('button', { name: /5\. 검사·수정/ }).click();
  await page.getByRole('button', { name: '브라우저 전체 테스트' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: '실패' }).locator('strong')).toHaveText('0');
  expect(backendCalls).toBe(0);
  await page.getByRole('button', { name: '초안 저장' }).click();
  const stored = await page.evaluate(() => JSON.stringify(localStorage));
  expect(stored).not.toContain('CEF:0|');
});
