import {test,expect} from '@playwright/test';

test('beginner Auto Parser cannot trigger private text grouping or raw-source transfer',async({page})=>{
  let privateRequests=0;
  await page.route(/\/api\/v1\/parser-pairs\/patterns\/drain3/,route=>{
    privateRequests++;
    return route.fulfill({status:403,contentType:'application/json',
      body:JSON.stringify({error:'NOT_AVAILABLE_TO_BEGINNER'})});
  });
  await page.goto('/');
  const raw=[
    '2026-10-23 ERROR login from 192.0.2.11 user test_a',
    '2026-10-23 ERROR login from 192.0.2.12 user test_b',
  ].join('\n');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByLabel('Known log shape matcher')).toHaveCount(0);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Group Similar Unknown Shapes'})).toHaveCount(0);
  expect(privateRequests).toBe(0);
});

test('retired private miner controls remain unavailable when switching to ChatGPT Assisted',async({page})=>{
  let attemptedPrivateRequests=0;
  page.on('request',request=>{
    if(request.url().includes('/parser-pairs/patterns/drain3')) attemptedPrivateRequests++;
  });
  await page.goto('/');
  await page.getByRole('button',{name:'ChatGPT Assisted Parser'}).click();
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
  await page.getByLabel('ChatGPT local sample logs').fill(
    'date=2026-10-23 action=deny srcip=192.0.2.10 dstip=198.51.100.5');
  await expect(page.getByLabel('Private text grouping tool')).toHaveCount(0);
  await expect(page.getByLabel('Known log shape matcher')).toHaveCount(0);
  await page.getByRole('button',{name:'Auto Parser',exact:true}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(
    'date=2026-10-23 action=deny srcip=192.0.2.10 dstip=198.51.100.5');
  expect(attemptedPrivateRequests).toBe(0);
});
