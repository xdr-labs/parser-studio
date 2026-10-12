import {expect,test} from '@playwright/test';

const fixture=[
  '{"action":"allow","src_ip":"192.0.2.10","dst_port":443,"session_id":"PRIVATE_SESSION_983","rule_name":"Example"}',
  '{"action":"deny","src_ip":"198.51.100.22","dst_port":22,"session_id":"PRIVATE_SESSION_984","rule_name":"Example"}',
].join('\n');

test('source field chip creates only an explicitly requested safe draft mapping with keyboard',async({page})=>{
  let apiRequests=0;
  page.on('request',req=>{
    if(req.url().includes('/api/v1/'))apiRequests++;
  });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(fixture);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();
  const chip=page.getByRole('button',{name:'Add draft mapping for session_id'});
  await expect(chip).toBeVisible();
  await expect(page.getByRole('button',{name:'Add draft mapping for rule_name'})).toBeVisible();
  expect(apiRequests).toBe(0);
  await chip.focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.guided-content-head h2')).toHaveText('How should the extracted fields be normalized?');
  await expect(page.locator('.guided-map-card')).toHaveCount(4);
  const added=page.getByLabel('Mapping for session_id');
  await expect(added).toBeVisible();
  await expect(added.getByLabel('Source field 3')).toHaveValue('session_id');
  await expect(added.getByLabel('Destination field 3')).toHaveValue('custom.session_id');
  await expect(added.getByLabel('Field type 3')).toHaveValue('string');
  await expect(added.getByLabel('Mapping group 3')).toHaveValue('vendor_fields');
  expect(apiRequests).toBe(0);

  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('button',{name:'Review mapping for session_id'})).toBeVisible();
  await page.getByRole('button',{name:'Review mapping for session_id'}).click();
  await expect(page.locator('.guided-map-card')).toHaveCount(4);
  await expect(added).toHaveAttribute('data-selected','true');
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(fixture);
  const storage=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(storage).not.toContain('PRIVATE_SESSION_983');
  expect(storage).not.toContain('PRIVATE_SESSION_984');
  expect(apiRequests).toBe(0);
});

test('already mapped fields navigate to existing rule without creating duplicate or calling backend',async({page})=>{
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(fixture);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();
  const mapped=page.getByRole('button',{name:'Review mapping for src_ip'});
  await expect(mapped).toBeVisible();
  await mapped.click();
  await expect(page.locator('.guided-map-card')).toHaveCount(3);
  await expect(page.getByLabel('Mapping for src_ip')).toHaveAttribute('data-selected','true');
});

test('unsafe prototype properties are never promoted to suggested mappings',async({page})=>{
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"__proto__":"do-not-map","constructor":"not-safe","action":"allow","src_ip":"192.0.2.10","dst_port":80}\n'+
    '{"__proto__":"do-not-map","constructor":"not-safe","action":"deny","src_ip":"192.0.2.11","dst_port":22}',
  );
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'JSON',exact:true}).click();
  await expect(page.getByRole('button',{name:/draft mapping for __proto__/})).toHaveCount(0);
  await expect(page.getByRole('button',{name:/draft mapping for constructor/})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Review mapping for src_ip'})).toBeVisible();
});
