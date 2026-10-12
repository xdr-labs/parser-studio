import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const logs = [
  '{"action":"allow","src_ip":"198.51.100.21","dst_port":443}',
  '{"action":"deny","src_ip":"invalid-ip-BRANCH_SECRET","dst_port":22}',
].join('\n');

test('same hashed sample report shows one improvement after correcting a type',async({page})=>{
  let backendCalls=0;
  page.on('request',req=>{if(req.url().includes('/api/v1/parser-pairs/'))backendCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(logs);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await page.getByRole('button',{name:'Run Full Browser Test'}).click();
  const save=page.getByRole('button',{name:'Download Browser Test Evidence JSON'});
  await expect(save).toBeEnabled();
  const previousDownload=page.waitForEvent('download');
  await save.click();
  const old=await previousDownload;
  const oldJson=await readFile(await old.path(),'utf8');

  await page.getByRole('button',{name:/3\. Map Fields/}).click();
  await page.getByLabel('Field type 0').selectOption('string');
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await expect(save).toBeDisabled();
  await page.getByRole('button',{name:'Run Full Browser Test'}).click();
  await expect(save).toBeEnabled();

  await page.locator('.guided-baseline-compare summary').click();
  await page.getByLabel('Previous browser evidence JSON').setInputFiles({
    name:'previous-browser-evidence.json',mimeType:'application/json',buffer:Buffer.from(oldJson),
  });
  await page.getByRole('button',{name:'Compare Same-Sample Evidence'}).click();
  const result=page.getByLabel('Browser evidence comparison result');
  await expect(result).toContainText('Improved 1');
  await expect(result).toContainText('Regressed 0');
  await expect(result).toContainText('Event #2');
  await expect(result).not.toContainText('BRANCH_SECRET');
  expect(backendCalls).toBe(0);

  // A new sample must invalidate comparison evidence tied to the prior draft + fixture.
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await page.getByLabel('Guided raw sample logs').fill(logs.replace('198.51.100.21','198.51.100.22'));
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await expect(page.getByLabel('Browser evidence comparison result')).toHaveCount(0);
  await page.locator('.guided-baseline-compare summary').click();
  await expect(page.getByRole('button',{name:'Compare Same-Sample Evidence'})).toBeDisabled();
});

test('a hostile previous report is rejected without reflecting any source content',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await page.getByRole('button',{name:'Run Full Browser Test'}).click();
  await page.locator('.guided-baseline-compare summary').click();
  const payload=JSON.stringify({reportSchema:'untrusted',raw:'SENSITIVE-CUSTOMER-PASSWORD'});
  await page.getByLabel('Previous browser evidence JSON').setInputFiles({
    name:'untrusted.json',mimeType:'application/json',buffer:Buffer.from(payload),
  });
  await page.getByRole('button',{name:'Compare Same-Sample Evidence'}).click();
  const error=page.locator('.guided-baseline-compare [role="alert"]');
  await expect(error).toContainText('Comparison failed');
  await expect(error).not.toContainText('SENSITIVE-CUSTOMER-PASSWORD');
  await expect(page.getByLabel('Browser evidence comparison result')).toHaveCount(0);
});
