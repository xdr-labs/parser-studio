import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const source=[
 'May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111111111 for net:10.10.10.10/53500 (81.2.69.144/53500) to fw111:192.168.2.2/53500 (81.2.69.144/53500)',
 'May  5 17:51:18 dev01: %FTD-6-302015: Built inbound UDP connection 111111112 for net:10.10.10.11/53501 (81.2.69.144/53501) to fw111:192.168.2.3/53 (81.2.69.144/53)',
].join('\n');
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');

function batch(raw:string){
 const lines=raw.split('\n');
 let cursor=0;
 const events=lines.map((line,index)=>{
  const startByte=cursor,endByte=startByte+Buffer.byteLength(line);
  cursor=endByte+(index<lines.length-1?1:0);
  const marker=line.indexOf('Built inbound');
  const startResidual=Buffer.byteLength(line.slice(0,marker));
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',
   status:'PARTIAL',syntax:'BSD_SYSLOG+UNKNOWN',
   sourceSha256:sha(line),sourceBytes:Buffer.byteLength(line),
   fields:{syslog_message_id:line.match(/%FTD-\d-(\d+)/)?.[1]??''},
   spans:[],residuals:[{startByte:startResidual,endByte:Buffer.byteLength(line)}],
   issues:['NO_SUPPORTED_GRAMMAR'],nativeVerified:false,targetVerified:false,
  }};
 });
 const separators=lines.slice(0,-1).map((line,index)=>{
  const end=events[index]!.endByte;return {startByte:end,endByte:end+1,kind:'WHITESPACE'};
 });
 return {contract:'parser-studio.multipass-source-batch-preview.v0.1',
  sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),eventCount:events.length,
  events,separators,nativeVerified:false,targetVerified:false};
}

test('beginner uses the bounded local Cisco FTD rule before unnecessary ChatGPT recovery',async({page})=>{
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(batch(source))}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('0 of 2 log events parsed completely');
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Recommended fix · Use the extracted fields');
 await expect(problem).toContainText('bounded local rule for this exact structure');
 const useExtracted=problem.getByRole('button',{name:'Use extracted fields'});
 await expect(useExtracted).toBeEnabled();
 await useExtracted.click();
 await expect(summary).toContainText('2 of 2 log events parsed completely',{timeout:10000});
 await expect(summary).toContainText('reviewed parser fix passes the current sample');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
 if(process.env.PARSER_STUDIO_LIVE_BACKEND==='1'){
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const generated=page.getByLabel('Generated Auto Parser DRAFT pair');
  await expect(generated).toContainText('Parser files created successfully');
  await expect(generated.getByLabel('Parser file verification details'))
    .toContainText('Two DRAFT files verified');
 }
});
