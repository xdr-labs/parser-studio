import { expect, test } from '@playwright/test';

test('user explicitly selects documented scalar standard fields without changing raw samples', async ({ page }) => {
  let calls = 0;
  page.on('request', request => {
    if (request.url().includes('/api/v1/parser-pairs/')) calls++;
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}\n' +
    '{"action":"deny","src_ip":"203.0.113.11","dst_port":22}',
  );
  await page.getByRole('button', { name:/2\. 필드 추출/ }).click();
  await page.getByRole('button', { name:'JSON', exact:true }).click();
  await page.getByRole('button', { name:/3\. 필드 매핑/ }).click();
  const reference = page.getByRole('link', { name:'Standard Metadata Dictionary' });
  await expect(reference).toHaveAttribute('href', 'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm');
  await expect(page.getByLabel('Destination field 0')).toHaveValue('custom.source_ip');
  await page.locator('.guided-map-card').nth(0).locator('.guided-official-field summary').click();
  await page.getByLabel('Official metadata field 0').selectOption('srcip');
  await expect(page.getByLabel('Source field 0')).toHaveValue('src_ip');
  await expect(page.getByLabel('Destination field 0')).toHaveValue('srcip');
  await expect(page.getByLabel('Field type 0')).toHaveValue('ip');
  await expect(page.getByLabel('Mapping group 0')).toHaveValue('top_fields');

  await page.locator('.guided-map-card').nth(1).locator('.guided-official-field summary').click();
  await page.getByLabel('Official metadata field 1').selectOption('dstport');
  await expect(page.getByLabel('Destination field 1')).toHaveValue('dstport');
  await expect(page.getByLabel('Field type 1')).toHaveValue('port');
  await expect(page.getByLabel('Mapping group 1')).toHaveValue('top_fields');

  await page.getByRole('button', { name:/5\. 검사·수정/ }).click();
  await page.getByRole('button', { name:'브라우저 전체 테스트' }).click();
  await expect(page.locator('.guided-test-metric').filter({hasText:'실패'}).locator('strong')).toHaveText('0');
  expect(calls).toBe(0);
});

test('standard field conflicts stay visible and do not overwrite another mapping', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name:/3\. 필드 매핑/ }).click();
  await page.locator('.guided-map-card').nth(0).locator('.guided-official-field summary').click();
  await page.getByLabel('Official metadata field 0').selectOption('srcip');
  await page.locator('.guided-map-card').nth(1).locator('.guided-official-field summary').click();
  await page.getByLabel('Official metadata field 1').selectOption('srcip');
  await expect(page.locator('.guided-map-card').nth(1).getByRole('alert')).toContainText('충돌');
  await expect(page.getByLabel('Destination field 1')).toHaveValue('custom.destination_port');
});
