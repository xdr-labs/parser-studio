import { expect, test } from '@playwright/test';

test('synthetic CSV starter changes nothing until Apply and provides guided fields', async ({ page }) => {
  let backendRequests = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) backendRequests++;
  });
  await page.goto('/');
  const input = page.getByLabel('Guided raw sample logs');
  const original = await input.inputValue();
  await page.getByLabel('Synthetic starter template').selectOption('csv');
  await expect(input).toHaveValue(original);
  expect(backendRequests).toBe(0);

  await page.getByRole('button', { name: '합성 예제 적용' }).click();
  await expect(input).toHaveValue(/allow,198\.51\.100\.10,443/);
  await expect(page.getByLabel('Parser ID')).toHaveValue('example_csv');
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await expect(page.getByRole('button', { name: 'CSV', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Guided CSV columns')).toHaveValue('action,src_ip,dst_port');
  await page.getByRole('button', { name: /5\. 검사·수정/ }).click();
  await page.getByRole('button', { name: '브라우저 전체 테스트' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: '입력 이벤트' }).locator('strong')).toHaveText('2');
  await expect(page.locator('.guided-test-metric').filter({ hasText: '실패' }).locator('strong')).toHaveText('0');
  expect(backendRequests).toBe(0);
});

test('RFC5424 synthetic starter prepares field mappings and remains DRAFT-only', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Synthetic starter template').selectOption('syslog_rfc5424');
  await page.getByRole('button', { name: '합성 예제 적용' }).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(/<34>1 /);
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await expect(page.getByRole('button', { name: 'RFC5424', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: /3\. 필드 매핑/ }).click();
  await expect(page.getByLabel('Source field 0')).toHaveValue('syslog_hostname');
  await page.getByRole('button', { name: /5\. 검사·수정/ }).click();
  await page.getByRole('button', { name: '브라우저 전체 테스트' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText: '실패' }).locator('strong')).toHaveText('0');
  await page.getByRole('button', { name: /6\. 파일 생성/ }).click();
  await expect(page.getByRole('button', { name: '파서 2개 파일 생성 (연결 대기)' })).toBeDisabled();
  await expect(page.locator('.guided-pair-files')).toContainText('NOT GENERATED');
});
