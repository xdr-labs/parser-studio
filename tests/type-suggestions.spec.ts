import { expect, test } from '@playwright/test';

test('typed value hint is browser-only and changes a mapping only after explicit user approval', async ({ page }) => {
  const sample = [
    '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"request_count":2}',
    '{"action":"deny","src_ip":"203.0.113.12","dst_port":22,"request_count":3}',
  ].join('\n');
  let sent = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) sent++;
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(sample);
  await page.getByRole('button', { name: /2\. 필드 추출/ }).click();
  await page.getByRole('button', { name:'JSON', exact:true }).click();
  await page.getByRole('button', { name: /3\. 필드 매핑/ }).click();
  await page.getByRole('button', { name:/안전한 남은 필드 모두 추가/ }).click();
  await expect(page.getByLabel('Source field 3')).toHaveValue('request_count');
  const suggested = page.getByLabel('Mapping type suggestion 3');
  await expect(suggested).toContainText('정수 타입 추정');
  await expect(page.getByLabel('Field type 3')).toHaveValue('string');
  await suggested.getByRole('button', { name:'Apply type suggestion 3' }).click();
  await expect(page.getByLabel('Field type 3')).toHaveValue('integer');
  await expect(suggested).toHaveCount(0);
  await page.getByRole('button', { name:/5\. 검사·수정/ }).click();
  await page.getByRole('button', { name:'브라우저 전체 테스트' }).click();
  await expect(page.locator('.guided-test-metric').filter({ hasText:'실패' }).locator('strong')).toHaveText('0');
  expect(sent).toBe(0);
});
