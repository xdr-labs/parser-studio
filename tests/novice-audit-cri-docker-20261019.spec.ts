import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';
// Authored protocol structures only; not physical-device wire or Stellar native proof.
const audit=[
 'type=SYSCALL msg=audit(1760870000.123:12): syscall=59 success=yes user="김민수"',
 'type=PATH msg=audit(1760870000.123:12): name="/tmp/한글"',
 'type=USER_LOGIN msg=audit(1760870000.125:13): res=failed',
].join('\n')+'\n';
const cri=[
 '2026-10-19T08:20:00.123456789Z stdout P 안녕',
 '2026-10-19T08:20:01.123456789Z stdout F 하세요',
 '2026-10-19T08:20:02Z stderr F denied',
].join('\n')+'\n';
const docker=[
 JSON.stringify({log:'user=김민수\n',stream:'stdout',time:'2026-10-19T08:20:00.123456789Z'}),
 JSON.stringify({log:'connection denied\n',stream:'stderr',time:'2026-10-19T08:20:01Z'}),
].join('\n')+'\n';
const cases=[
 {label:'Linux Audit multi-record event serial',source:audit,count:2,syntax:'LINUX_AUDIT_SERIAL_GROUP',value:'김민수',statuses:['PARTIAL','PARTIAL']},
 {label:'Kubernetes CRI P/F message boundaries',source:cri,count:2,syntax:'CRI_PARTIAL_FINAL_GROUP',value:'안녕',statuses:['PARTIAL','PARTIAL']},
 {label:'Docker JSON-file source wrapper',source:docker,count:2,syntax:'DOCKER_JSON_FILE',value:'김민수',statuses:['PARTIAL','PARTIAL']},
 {label:'Malformed CRI partial without final event fails closed',
   source:'2026-10-19T08:20:00Z stdout P insecure\n',count:1,syntax:'UNSUPPORTED_SOURCE_CONTAINER',
   value:'',statuses:['RAW_ONLY']},
] as const;
async function responseFor(page:Page,source:string){
 const batches:Record<string,unknown>[]=[];
 const errors:string[]=[];
 page.on('pageerror',error=>errors.push(error.message));
 page.on('response',async res=>{
  if(res.url().endsWith('/api/v1/multipass/preview-batch')&&res.ok())
   batches.push(await res.json() as Record<string,unknown>);
 });
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 await expect.poll(()=>batches.length,{timeout:22000}).toBe(1);
 await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
 expect(errors).toEqual([]);
 return batches[0]!;
}
for(const entry of cases){
 test(entry.label+' — exact source bytes, partial honesty, browser recovery',async({page})=>{
  const body=await responseFor(page,entry.source);
  expect(body.eventCount).toBe(entry.count);
  expect(body.sourceSha256).toBe(createHash('sha256').update(entry.source).digest('hex'));
  expect(body.sourceBytes).toBe(Buffer.byteLength(entry.source));
  const frames=body.events as Array<{
    startByte:number;endByte:number;
    preview:{status:string;syntax:string;issues:string[];nativeVerified:boolean;
     targetVerified:boolean;fields:Record<string,unknown>};
  }>;
  expect(frames.map(frame=>frame.preview.status)).toEqual(entry.statuses);
  expect(frames.map(frame=>frame.preview.syntax)).toContain(entry.syntax);
  expect(frames.every(frame=>frame.preview.nativeVerified===false&&frame.preview.targetVerified===false))
    .toBeTruthy();
  const whole=Buffer.from(entry.source);
  if(entry.value)expect(JSON.stringify(frames.map(f=>f.preview.fields))).toContain(entry.value);
  for(const frame of frames){
   expect(whole.subarray(frame.startByte,frame.endByte).length).toBeGreaterThan(0);
   if(frame.preview.status==='PARTIAL')
    expect(frame.preview.issues).toContain('FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER');
   // Values are checked across the whole batch below; the second event
   // need not contain a value present in the first event.

  }
  const separators=body.separators as Array<{startByte:number;endByte:number}>;
  const accounted=[
   ...frames.map(x=>[x.startByte,x.endByte]),
   ...separators.map(x=>[x.startByte,x.endByte])
  ].sort((a,b)=>a[0]!-b[0]!);
  let cursor=0;
  for(const [start,end] of accounted){
    expect(start).toBe(cursor);
    expect(end).toBeGreaterThan(cursor);
    cursor=end!;
  }
  expect(cursor).toBe(whole.byteLength);
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeDisabled();
  // The beginner analysis summary and exact API response replace the retired
  // advanced ledger. Event boundaries and every byte are asserted above.
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(entry.source);
 });
}
