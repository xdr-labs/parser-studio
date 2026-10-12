import { expect, test } from '@playwright/test';

test('malformed dotted output is blocked before any backend API call', async ({ page }) => {
  let requests = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) requests++;
  });
  await page.goto('/');
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: /3\. 필드 매핑/ }).click();
  await page.getByLabel('Destination field 0').fill('custom..invalid');
  await page.getByRole('button', { name: /6\. 파일 생성/ }).click();
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Invalid destination field');
  await expect(page.getByRole('button', { name: '백엔드 입력 검사' })).toBeDisabled();
  await expect(page.getByRole('button', { name: '백엔드용 프로젝트 JSON 다운로드' })).toBeDisabled();
  expect(requests).toBe(0);
});

test('prefix-overlapping output target is rejected with actionable error before backend', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await page.getByRole('button', { name: 'JSON', exact: true }).click();
  await page.getByRole('button', { name: /3\. 필드 매핑/ }).click();
  await page.getByLabel('Destination field 1').fill('custom.source_ip.child');
  await page.getByRole('button', { name: /6\. 파일 생성/ }).click();
  await expect(page.locator('.guided-contract-errors').first()).toContainText('Normalized destination collision');
  await expect(page.getByRole('button', { name: '백엔드 입력 검사' })).toBeDisabled();
});

test('unsupported floating-point mapping option cannot be selected in no-code export', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /3\. 필드 매핑/ }).click();
  await expect(page.getByLabel('Field type 0').locator('option[value="number"]')).toBeDisabled();
});
