import { expect, test } from '@playwright/test';

test('nondeveloper can inspect mixed JSON/KV sample families without false export readiness', async ({page})=>{
  let backendCalls=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/parser-pairs/'))backendCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}\n'+
    'action=deny src_ip=203.0.113.5 dst_port=22',
  );
  await page.getByRole('button',{name:/2\. 필드 추출/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  const coverage=page.getByLabel('Sample format distribution');
  await expect(coverage).toContainText('JSON');
  await expect(coverage).toContainText('Key / Value');
  await expect(coverage).toContainText('다른 샘플 1개');
  await expect(coverage).toContainText('별도 파서 초안으로 나눠 검증');
  await coverage.getByRole('button',{name:'다른 형식 샘플 확인'}).click();
  await expect(page.getByLabel('Guided selectable raw event')).toContainText('action=deny');
  await page.getByRole('button',{name:/5\. 검사·수정/}).click();
  await page.getByRole('button',{name:'브라우저 전체 테스트'}).click();
  await expect(page.locator('.guided-test-metric').filter({hasText:'실패'}).locator('strong')).toHaveText('1');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await expect(page.getByRole('button',{name:'파서 2개 파일 생성 (연결 대기)'})).toBeDisabled();
  expect(backendCalls).toBe(0);
});
