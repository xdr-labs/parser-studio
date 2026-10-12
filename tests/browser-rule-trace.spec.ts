import {expect,test} from '@playwright/test';

const samples=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"username":"PRIVATE_USER"}',
  '{"action":"deny","src_ip":"not-an-ip","dst_port":22,"url":"https://secret.invalid/a"}',
  '{"action":"allow","dst_port":80,"username":"HIDDEN_VALUE"}',
].join('\n');

test('local per-event rule trace distinguishes mapped, missing and invalid types without values or backend calls',async({page})=>{
  let requests=0;
  page.on('request',r=>{if(r.url().includes('/api/v1/'))requests++;});
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(samples);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  await page.getByRole('button',{name:'Run Full Browser Test'}).click();
  const panel=page.getByLabel('Browser-only per-rule event trace');
  await panel.locator('summary').click();
  await expect(panel.getByLabel('Value-free per-rule results')).toContainText('3/3 rules emitted');
  await expect(panel.getByLabel('Value-free per-rule results')).toContainText('Output written in browser preview');
  await panel.getByLabel('Trace event number').selectOption('event-2');
  await expect(panel.getByLabel('Value-free per-rule results')).toContainText('2/3');
  await expect(panel.getByLabel('Value-free per-rule results')).toContainText('TYPE_FAILED');
  await expect(panel.getByLabel('Value-free per-rule results')).not.toContainText('not-an-ip');
  await panel.getByLabel('Trace event number').selectOption('event-3');
  await expect(panel.getByLabel('Value-free per-rule results')).toContainText('SOURCE_MISSING');
  for(const privateValue of ['198.51.100.10','PRIVATE_USER','not-an-ip','https://secret.invalid/a','HIDDEN_VALUE']){
    expect(await panel.innerText()).not.toContain(privateValue);
  }
  await panel.getByRole('button',{name:'Review mapping rule 1'}).click();
  await expect(page.locator('.guided-step.active')).toContainText('Map Fields');
  await expect(page.locator('.guided-map-card[data-selected="true"]')).toHaveCount(1);
  await expect(page.locator('.guided-map-card[data-selected="true"]')).toContainText('FIELD 01');
  expect(requests).toBe(0);
});

test('source revision changes cannot reuse an old per-rule trace and never download or transmit samples',async({page})=>{
  let calls=0;
  page.on('request',r=>{if(r.url().includes('/api/v1/'))calls++;});
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(samples);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('button',{name:'JSON',exact:true}).click();
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  const panel=page.getByLabel('Browser-only per-rule event trace');
  await panel.locator('summary').click();
  await expect(panel.getByLabel('Value-free per-rule results')).toContainText('3/3');
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await page.getByLabel('Guided raw sample logs').fill('{"action":"allow","dst_port":443}');
  await page.getByRole('button',{name:/5\. Test & Fix/}).click();
  const current=page.getByLabel('Browser-only per-rule event trace');
  await current.locator('summary').click();
  await expect(current.getByLabel('Value-free per-rule results')).toContainText('SOURCE_MISSING');
  await expect(current.getByLabel('Value-free per-rule results')).toContainText('2/3');
  await expect(current.getByLabel('Trace event number').locator('option')).toHaveCount(1);
  expect(calls).toBe(0);
});
