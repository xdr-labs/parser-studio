import {expect,test} from '@playwright/test';

const events=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"private":"CUSTOMER_SECRET"}',
  '{"action":"deny","src_ip":"203.0.113.12","dst_port":22,"private":"SECOND_PRIVATE"}',
].join('\n');

test('keyboard-only user can propose a raw field without mouse drag or backend access',async({page})=>{
  let backendCalls=0;
  page.on('request',req=>{if(req.url().includes('/api/v1/'))backendCalls++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(events);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();

  const alternative=page.getByLabel('Keyboard raw-value selection');
  const summary=alternative.locator('summary');
  await summary.focus();
  await page.keyboard.press('Enter');
  await expect(alternative).toHaveAttribute('open','');

  const input=alternative.getByLabel('Exact raw value to select');
  const choose=alternative.getByRole('button',{name:'Use Value for Field Proposal'});
  await expect(choose).toBeDisabled();
  await input.focus();
  await page.keyboard.type('198.51.100.10');
  await expect(choose).toBeEnabled();
  await choose.focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.guided-sample-value')).toContainText('198.51.100.10');
  await expect(page.getByLabel('Guided proposed field name')).toHaveValue('src_ip');
  await expect(page.getByRole('button',{name:'Test Across All Samples'})).toBeVisible();
  await expect(page.getByRole('button',{name:'Apply Field Rule'})).toBeDisabled();
  expect(backendCalls).toBe(0);

  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(events);
  const storage=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(storage).not.toContain('CUSTOMER_SECRET');
  expect(storage).not.toContain('198.51.100.10');
  expect(backendCalls).toBe(0);
});

test('keyboard source value must match selected event and is discarded on sample edits',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(events);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  const alternative=page.getByLabel('Keyboard raw-value selection');
  await alternative.locator('summary').click();
  const input=alternative.getByLabel('Exact raw value to select');
  const choose=alternative.getByRole('button',{name:'Use Value for Field Proposal'});
  await input.fill('NOT_IN_SOURCE');
  await expect(choose).toBeDisabled();
  await expect(page.locator('.guided-proposal')).toHaveCount(0);
  await input.fill('198.51.100.10');
  await expect(choose).toBeEnabled();
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await page.getByLabel('Guided raw sample logs').fill('{"action":"deny","src_ip":"192.0.2.9","dst_port":80}');
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await alternative.locator('summary').click();
  await expect(input).toHaveValue('');
  await expect(choose).toBeDisabled();
});

test('compact viewport keeps the keyboard selection control reachable without overflow',async({page})=>{
  await page.setViewportSize({width:390,height:844});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(events);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  const alternative=page.getByLabel('Keyboard raw-value selection');
  await alternative.locator('summary').click();
  await expect(alternative.getByLabel('Exact raw value to select')).toBeVisible();
  await expect(alternative.getByRole('button',{name:'Use Value for Field Proposal'})).toBeVisible();
  const width=await page.evaluate(()=>({actual:document.documentElement.scrollWidth,viewport:innerWidth}));
  expect(width.actual).toBeLessThanOrEqual(width.viewport+1);
});
