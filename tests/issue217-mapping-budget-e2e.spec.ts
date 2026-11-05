import {test,expect,type Page} from '@playwright/test';

test.skip(process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires an isolated Multi-Pass backend paired with this source checkout.');

function sample(ip:string){
  const fields=Array.from({length:40},(_,i)=>'vendor_field_'+String(i).padStart(2,'0')+'=data'+i);
  return [
    'action=deny type=traffic srcip=192.0.2.1 '+fields.join(' '),
    ...Array.from({length:8},(_,i)=>'action=deny type=traffic session='+i),
    'action=deny type=traffic srcip='+ip,
  ].join('\n');
}

async function prepareMapping(page:Page,lateIp:string){
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Synthetic');
  await page.getByLabel('Parser product',{exact:true}).fill('FindingBudget');
  await page.getByLabel('Auto Parser raw logs').fill(sample(lateIp));
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:30000});
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  const vendors=map.locator('details.normalization-vendor-list');
  if(await vendors.count())await vendors.locator('summary').click();
  const rows=map.locator('article.normalization-map-row');
  const srcIndex=await rows.evaluateAll(nodes=>nodes.findIndex(node=>
    (node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value==='srcip'));
  expect(srcIndex).toBeGreaterThanOrEqual(0);
  const target=rows.nth(srcIndex).locator('input[aria-label^="Stellar field "]');
  await target.fill('srcip_tmp');
  await target.fill('srcip');
  return map;
}

test('Issue #217 late invalid official IP blocks mapping despite >300 optional-field notes',async({page})=>{
  test.setTimeout(90000);
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
  const map=await prepareMapping(page,'999.999.999.999');
  const checks=map.getByLabel('Field mapping checks');
  await expect(checks).toContainText('A sample value does not fit the selected value type');
  await expect(checks).toContainText('event 10');
  await expect(checks).toContainText('Showing 300 of');
  await expect(map.getByLabel('Field mapping summary')).toContainText('Must fix before continuing');
  await expect(map.getByRole('button',{name:'Create Parser',exact:true})).toBeDisabled();
  expect(errors).toEqual([]);
});

test('Issue #217 optional fields remain nonblocking for all valid IP values',async({page})=>{
  test.setTimeout(90000);
  const map=await prepareMapping(page,'192.0.2.2');
  const checks=map.getByLabel('Field mapping checks');
  await expect(checks).toContainText('You can still continue.');
  await expect(checks).toContainText('Showing 300 of');
  await expect(map.getByRole('button',{name:'Create Parser',exact:true})).toBeEnabled();
});