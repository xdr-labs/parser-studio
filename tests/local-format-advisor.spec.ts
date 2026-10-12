import {expect,test} from '@playwright/test';

const json=[
  '{"action":"allow","src_ip":"198.51.100.10","username":"CUSTOMER_A"}',
  '{"action":"deny","src_ip":"203.0.113.5","username":"CUSTOMER_B"}',
].join('\n');
const kv='action=allow src_ip=192.0.2.10\naction=deny src_ip=192.0.2.11';
const advisor=(page:import('@playwright/test').Page)=>
  page.getByLabel('Local sample format recommendation');

test('beginner pastes JSON without knowing its format and explicitly accepts one safe suggestion',async({page})=>{
  let backendRequests=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))backendRequests++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(json);
  const panel=advisor(page);
  await expect(panel).toContainText('Suggested: JSON');
  await expect(panel).toContainText('2/2 extracted');
  await expect(panel).toContainText('Browser Only');
  for(const secret of ['CUSTOMER_A','CUSTOMER_B','198.51.100.10','203.0.113.5'])
    expect(await panel.innerText()).not.toContain(secret);
  const apply=panel.getByRole('button',{name:'Apply recommended log format'});
  await expect(apply).toBeEnabled();
  await apply.focus();
  await page.keyboard.press('Enter');
  await expect(apply).toBeDisabled();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(json);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('button',{name:'JSON',exact:true})).toHaveAttribute('aria-pressed','true');
  await expect(advisor(page)).toContainText('Already Selected');
  await page.getByRole('button',{name:/3\. Map Fields/}).click();
  await expect(page.locator('.guided-map-card')).toHaveCount(3);
  expect(backendRequests).toBe(0);
});

test('mixed families, unknown lines, CSV and grouped multiline never get an automatic single-format choice',async({page})=>{
  let requests=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))requests++;});
  await page.goto('/');
  const input=page.getByLabel('Guided raw sample logs');
  await input.fill(json.split('\n')[0]+'\n'+kv.split('\n')[0]);
  await expect(advisor(page)).toContainText('Multiple log families');
  await expect(advisor(page).getByLabel('Detected format candidates')).toContainText('JSON: 1');
  await expect(advisor(page).getByLabel('Detected format candidates')).toContainText('Key / Value: 1');
  await expect(advisor(page).getByRole('button',{name:'Apply recommended log format'})).toHaveCount(0);
  await input.fill(json.split('\n')[0]+'\nUNKNOWN_PRIVATE_RECORD');
  await expect(advisor(page)).toContainText('Unrecognized source events remain');
  expect(await advisor(page).innerText()).not.toContain('UNKNOWN_PRIVATE_RECORD');
  await input.fill('one,two,three\nfour,five,six');
  await expect(advisor(page)).toContainText('manual configuration');
  await expect(advisor(page).getByRole('button',{name:'Apply recommended log format'})).toHaveCount(0);
  await input.fill('{\n  "action":"allow"\n}');
  await page.getByRole('button',{name:/Separate events using blank lines/}).click();
  await expect(advisor(page)).toContainText('Grouped multiline input needs manual review');
  await expect(advisor(page).getByRole('button',{name:'Apply recommended log format'})).toHaveCount(0);
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('button',{name:'Auto detect'})).toHaveAttribute('aria-pressed','true');
  expect(requests).toBe(0);
});

test('format advice updates after source edit without reusing old sample, sending source or overwriting mappings',async({page})=>{
  let requests=0;
  page.on('request',request=>{if(request.url().includes('/api/v1/'))requests++;});
  await page.goto('/');
  const input=page.getByLabel('Guided raw sample logs');
  await input.fill(json);
  await expect(advisor(page)).toContainText('Suggested: JSON');
  await input.fill(kv);
  await expect(advisor(page)).toContainText('Suggested: Key / Value');
  expect(await advisor(page).innerText()).not.toContain('JSON:');
  const apply=advisor(page).getByRole('button',{name:'Apply recommended log format'});
  await apply.click();
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('button',{name:'Key / Value',exact:true})).toHaveAttribute('aria-pressed','true');
  await expect(page.getByLabel('Guided selectable raw event')).toContainText('192.0.2.10');
  await page.getByRole('button',{name:/3\. Map Fields/}).click();
  await expect(page.locator('.guided-map-card')).toHaveCount(3);
  expect(requests).toBe(0);
});
