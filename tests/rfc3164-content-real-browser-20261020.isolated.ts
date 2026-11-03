import {test,expect,type Page} from '@playwright/test';

// Independently authored source examples. Real loopback Vite/Python/authoring;
// no HTTP mocks or claims of actual manufacturer or Stellar target oracles.
const PRI='<134>Oct 19 08:12:00 edge-fw firewall: ';
const BARE='Oct 19 08:12:00 edge-fw auth: ';
const ENDPOINT=PRI+'session denied 192.0.2.12/52333 to 198.51.100.9/80';
type SourcePreview={
  status:string;syntax:string;fields:Record<string,unknown>;
  spans:Array<{path:string;startByte:number;endByte:number}>;
  residuals:Array<{startByte:number;endByte:number}>;
  nativeVerified:boolean;targetVerified:boolean;
};
async function qualifiedPreview(page:Page,raw:string):Promise<SourcePreview>{
 const result=await page.request.post('/api/v1/multipass/preview-batch',{data:{raw}});
 expect(result.status()).toBe(200);
 const batch=await result.json() as {eventCount:number;events:Array<{preview:SourcePreview}>};
 expect(batch.eventCount).toBe(1);
 return batch.events[0]!.preview;
}
for(const item of [
 {name:'PRI RFC 3164 TAG and content',raw:PRI+'Access denied after review',
  syntax:'SYSLOG_RFC3164+RFC3164_CONTENT',msg:'Access denied after review'},
 {name:'BSD no PRI with Unicode',raw:BARE+'접근 차단 사용자 김민수',
  syntax:'BSD_SYSLOG+BSD_CONTENT',msg:'접근 차단 사용자 김민수'},
]){
 test(item.name+' preserves source while keeping parser-file approval separate',async({page})=>{
  const errors:string[]=[];const http5xx:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('response',res=>{
   if(res.url().includes('/api/')&&res.status()>=500)
    http5xx.push(String(res.status()));
  });
  const result=await qualifiedPreview(page,item.raw);
  expect(result.status).toBe('SOURCE_PARSED');
  expect(result.syntax).toBe(item.syntax);
  expect((result.fields.body as {message:string}).message).toBe(item.msg);
  const span=result.spans.find(s=>s.path==='body.message');
  expect(span).toBeDefined();
  expect(Buffer.from(item.raw).subarray(span!.startByte,span!.endByte).toString('utf8')).toBe(item.msg);
  expect(result.residuals).toEqual([]);
  expect(result.nativeVerified).toBe(false);
  expect(result.targetVerified).toBe(false);
  await page.goto('/');
  const raw=page.getByLabel('Auto Parser raw logs');
  await raw.fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toBeVisible({timeout:16000});
  await expect(summary).toContainText(/(?:Values found|structurally parsed)/);
  await expect(raw).toHaveValue(item.raw);
  await expect(page.getByText('Native verified',{exact:true})).toHaveCount(0);
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  if(await review.isEnabled()){
   await review.click();
   await expect(page.getByLabel('Review Fields stage').or(page.getByLabel('Parser draft not ready')))
    .toBeVisible({timeout:16000});
  }else{
   await expect(page.getByLabel('Parse problem inspector')).toBeVisible();
   await expect(summary).toContainText(/(?:parser|rule|fields)/i);
  }
  expect(errors).toEqual([]);
  expect(http5xx).toEqual([]);
  console.log('RFC3164_QUALIFIED_BROWSER '+JSON.stringify({case:item.name,sourceStatus:result.status,targetVerified:false}));
 });
}
test('existing network atoms and malformed KV cannot be hidden by free-form content',async({page})=>{
 const rich=await qualifiedPreview(page,ENDPOINT);
 expect(rich.status).toBe('PARTIAL');
 expect((rich.fields.body as Record<string,unknown>)?.message).toBeUndefined();
 expect(JSON.stringify(rich.fields)).toContain('192.0.2.12');
 const malformed=await qualifiedPreview(page,PRI+'action="unterminated src=192.0.2.5');
 expect(malformed.status).not.toBe('SOURCE_PARSED');
 expect((malformed.fields.body as Record<string,unknown>)?.message).toBeUndefined();
 await page.goto('/');
 const input=page.getByLabel('Auto Parser raw logs');
 await input.fill(ENDPOINT);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:16000});
 await expect(page.getByLabel('Parse problem inspector')).toBeVisible();
 await expect(input).toHaveValue(ENDPOINT);
});
