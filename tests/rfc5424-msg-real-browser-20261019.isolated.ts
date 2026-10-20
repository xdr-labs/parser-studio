import {test,expect} from '@playwright/test';

// Test-only synthetic source events; real loopback HTTP, no API mocks.
// The extension is intentionally not *.spec.ts: production CI has distinct
// pinned backend browser gates and cannot use this local-only server contract.
const HEAD='<134>1 2026-10-19T09:15:22.123Z fw01 application 12 audit [meta@12345 action="deny" src="192.0.2.10"] ';
const NIL='<134>1 2026-10-19T09:15:22.123Z fw01 app - evt - ';
type Preview={
  eventCount:number;
  events:Array<{preview:{
    status:string;syntax:string;fields:Record<string,unknown>;
    spans:Array<{path:string;startByte:number;endByte:number}>;
    issues:string[];nativeVerified:boolean;targetVerified:boolean;
  }}>;
};
const API='/api/v1/multipass/preview-batch';
async function livePreview(page:import('@playwright/test').Page,raw:string):Promise<Preview>{
  const http=await page.request.post(API,{data:{raw}});
  expect(http.status()).toBe(200);
  return await http.json() as Preview;
}
for(const item of [
 {id:'RFC5424 plain MSG',raw:HEAD+'firewall denied',message:'firewall denied'},
 {id:'RFC5424 UTF-8 BOM MSG',raw:NIL+'\uFEFF사용자 접근 차단',message:'사용자 접근 차단'},
] as const){
 test(item.id+' keeps byte-exact source and honestly flags draft readiness',async({page})=>{
  const pageErrors:string[]=[];const api5xx:number[]=[];
  page.on('pageerror',e=>pageErrors.push(e.message));
  page.on('response',r=>{
   if(r.url().includes('/api/')&&r.status()>=500)api5xx.push(r.status());
  });
  const response=await livePreview(page,item.raw);
  expect(response.eventCount).toBe(1);
  const source=response.events[0].preview;
  expect(source.status).toBe('SOURCE_PARSED');
  expect(source.syntax).toBe('SYSLOG_RFC5424+RFC5424_MSG');
  expect((source.fields.body as {message:string}).message).toBe(item.message);
  const span=source.spans.find(s=>s.path==='body.message');
  expect(span).toBeDefined();
  expect(Buffer.from(item.raw,'utf8').subarray(span!.startByte,span!.endByte).toString('utf8')).toBe(item.message);
  expect(source.nativeVerified).toBe(false);
  expect(source.targetVerified).toBe(false);
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  // Native parser compiler does not have a proven generic RFC5424 text MSG
  // adapter, so even completely extracted source values require review.
  await expect(summary).toContainText('Values found in 1 of 1 log event',{timeout:12000});
  const problem=page.getByLabel('Parse problem inspector');
  await expect(problem).toContainText('Fields extracted — parser rule needs review');
  await expect(problem).toContainText('Review parser-file support for these fields');
  await expect(problem).toContainText('does not verify native or Stellar Cyber parser compatibility');
  await expect(problem).not.toContainText('remaining message text');
  await expect(input).toHaveValue(item.raw);
  const next=page.getByRole('button',{name:'Review Fields',exact:true});
  if(await next.isEnabled()){
   await next.click();
   const mapping=page.getByLabel('Review Fields stage');
   const blocked=page.getByLabel('Parser draft not ready');
   await expect(mapping.or(blocked)).toBeVisible({timeout:14000});
   // A compiler block must not assert an unsupported native Parser Draft.
   if(await blocked.isVisible()){
    await expect(blocked).toContainText('No source value was discarded');
    await expect(blocked.getByRole('button',{name:'Use ChatGPT Assisted Parser'})).toBeVisible();
   }
  }else{
   await expect(problem.getByRole('button',{name:/Fix with ChatGPT|Review with ChatGPT/})).toBeVisible();
  }
  expect(pageErrors).toEqual([]);
  expect(api5xx).toEqual([]);
  console.log('RFC5424_REAL_BROWSER '+JSON.stringify({case:item.id,source:source.status,authoring:'REVIEW_REQUIRED',targetVerified:false}));
 });
}
test('malformed quoted RFC5424 body is not falsely declared source-complete',async({page})=>{
 const raw=HEAD+'action="unclosed src=192.0.2.5';
 const api=await livePreview(page,raw);
 expect(api.eventCount).toBe(1);
 expect(api.events[0].preview.status).not.toBe('SOURCE_PARSED');
 expect((api.events[0].preview.fields.body as Record<string,unknown>)?.message).toBeUndefined();
 const errors:string[]=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:12000});
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
 await expect(page.getByLabel('Parse problem inspector')).toBeVisible();
 expect(errors).toEqual([]);
});
