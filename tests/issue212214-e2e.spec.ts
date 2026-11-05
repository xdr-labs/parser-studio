import {test,expect} from '@playwright/test';

test.skip(process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-source isolated Python Multi-Pass service.');

const malformedQuoted='<134>Nov  5 13:00:01 fw01 firewall: action="deny src=192.0.2.1 dst=198.51.100.2 proto=6';
const malformedSD=String.raw`<14>1 2026-11-05T13:00:01Z fw01 engine 10 \t0 SRC - [id@123 action="deny"] action=deny src=192.0.2.1`;

test('Issue #212 malformed Syslog returns bounded preview instead of HTTP 422',async({page})=>{
  test.setTimeout(60000);
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Synthetic');
  await page.getByLabel('Parser product',{exact:true}).fill('Malformed');
  for(const raw of [malformedQuoted,malformedSD]){
    await page.getByLabel('Auto Parser raw logs').fill(raw);
    const reply=page.waitForResponse(r=>r.url().includes('/api/v1/multipass/preview')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const result=await reply;
    expect(result.status()).toBe(200);
    const json=await result.json() as {error?:string;status?:string;events?:Array<{preview:{status:string}}>};
    expect(json.error).toBeUndefined();
    const classification=json.events?.[0]?.preview.status??json.status;
    expect(['PARTIAL','RAW_ONLY']).toContain(classification);
  }
  expect(errors).toEqual([]);
});

test('Issue #214 physical RS inside key value cannot enable false-green review',async({page})=>{
  test.setTimeout(60000);
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Synthetic');
  await page.getByLabel('Parser product',{exact:true}).fill('PhysicalControl');
  const raw='<134>Nov  5 13:00:01 fw01 firewall: action='+String.fromCharCode(30)+'deny src=192.0.2.1 dst=198.51.100.2 proto=6';
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  const reply=page.waitForResponse(r=>r.url().includes('/api/v1/multipass/preview')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const result=await reply;
  expect(result.status()).toBe(200);
  const json=await result.json() as {status?:string;events?:Array<{preview:{status:string}}>};
  const classification=json.events?.[0]?.preview.status??json.status;
  expect(['PARTIAL','RAW_ONLY']).toContain(classification);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  expect(errors).toEqual([]);
});