import { expect, test } from '@playwright/test';

test('nondeveloper can inspect mixed JSON/KV sample families without false export readiness', async ({page})=>{
  let backendCalls=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/parser-pairs/'))backendCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}\n'+
    'action=deny src_ip=203.0.113.5 dst_port=22',
  );
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  const coverage=page.getByLabel('Sample format distribution');
  await expect(coverage).toContainText('JSON');
  await expect(coverage).toContainText('Key / Value');
  await expect(coverage).toContainText('1 different-format sample');
  await expect(coverage).toContainText('test using a separate parser draft');
  await expect(page.getByRole('note', { name:'Mixed format guidance' })).toBeVisible();
  await coverage.getByRole('button',{name:'Inspect Different-Format Samples'}).click();
  await expect(page.getByLabel('Guided selectable raw event')).toContainText('action=deny');
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await page.getByRole('button',{name:'Run Full Browser Test'}).click();
  await expect(page.locator('.guided-test-metric').filter({hasText:'Failures'}).locator('strong')).toHaveText('1');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await expect(page.getByRole('button',{name:'Generate 2 Parser Files (Backend Required)'})).toBeDisabled();
  expect(backendCalls).toBe(0);
});
