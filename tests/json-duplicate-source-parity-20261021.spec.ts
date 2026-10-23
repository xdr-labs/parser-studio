import {test,expect} from '@playwright/test';

// Authored synthetic examples, with decoded-key identity collisions.
const rejected=[
  '{"src_ip":"192.0.2.11","src_ip":"203.0.113.7","action":"deny"}',
  '{"outer":{"event":"one","event":"two"}}',
  '{"\\u0061":"one","a":"two"}',
  '{"batch":[{"event":"one","event":"two"}]}',
];

test('invalid JSON object names never become complete browser events or DRAFT compiler approval',async({page})=>{
  test.setTimeout(90_000);
  const errors:string[]=[];
  const serverErrors:number[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)serverErrors.push(response.status());
  });
  for(const raw of rejected){
    await page.goto('/');
    const input=page.getByLabel('Auto Parser raw logs');
    await input.fill(raw);
    const accounting=page.getByLabel('Automatic event accounting');
    await expect(accounting).toContainText('1/1 events checked');
    await expect(accounting).toContainText('1 event unrecognized in the initial format scan');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(input).toHaveValue(raw);
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  }
  expect(errors).toEqual([]);
  expect(serverErrors).toEqual([]);
});

test('identical JSON member names in separate valid objects remain source-preserving',async({page})=>{
  const raw='{"left":{"event":"deny"},"right":{"event":"allow"},"action":"deny"}';
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(raw);
  const accounting=page.getByLabel('Automatic event accounting');
  await expect(accounting).toContainText('1/1 events checked');
  await expect(accounting).toContainText('0 events unrecognized in the initial format scan');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(input).toHaveValue(raw);
});
