import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const lines=[
 'Nov 30 16:44:36 PA-220 1,2018/11/30 16:44:36,THREAT,192.0.2.10,443',
 'Nov 30 16:44:37 PA-220 1,2018/11/30 16:44:37,THREAT,192.0.2.11,8443',
];
const raw=lines.join('\n');
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
function batch(){
 let cursor=0;
 const events=lines.map((line,index)=>{
  const startByte=cursor,endByte=startByte+Buffer.byteLength(line);cursor=endByte+(index===0?1:0);
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',
   syntax:'SECURITY_SYSLOG_ENVELOPE+CSV_UNLABELED_CANDIDATE',
   sourceSha256:sha(line),sourceBytes:Buffer.byteLength(line),
   fields:{},spans:[],residuals:[],issues:['UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION'],
   nativeVerified:false,targetVerified:false,
  }};
 });
 return {contract:'parser-studio.multipass-source-batch-preview.v0.1',
  sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),eventCount:2,events,
  separators:[{startByte:events[0]!.endByte,endByte:events[0]!.endByte+1,kind:'WHITESPACE'}],
  nativeVerified:false,targetVerified:false};
}

test('source-complete PAN-OS positional CSV still asks for neutral column approval before review',async({page})=>{
 const payload=batch();
 for(const event of payload.events){
  event.preview.status='SOURCE_PARSED';
  event.preview.syntax='SYSLOG_BSD_CSV';
  event.preview.issues=[];
 }
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(payload)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('2 of 2 source events extracted');
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Syslog-wrapped positional CSV');
 await expect(problem).toContainText('Recommended fix · Keep all values with temporary field names');
 await expect(page.getByLabel('Review CSV column names')).toHaveCount(0);
 await expect(page.getByRole('button',{name:/Neutral Column Names/})).toHaveCount(0);
 const neutral=problem.getByRole('button',{name:'Keep all 5 values with temporary names'});
 await expect(neutral).toBeVisible();
 await neutral.click();
 await expect(summary).toContainText('2 of 2 log events parsed completely');
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
});

test('beginner can preserve PAN-OS positional values with neutral columns without guessing semantics',async({page})=>{
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(batch())}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('0 of 2 log events parsed completely');
 const problem=page.getByLabel('Parse problem inspector');
 await expect(problem).toContainText('Recommended fix · Keep all values with temporary field names');
 const neutral=problem.getByRole('button',{name:'Keep all 5 values with temporary names'});
 await expect(neutral).toBeVisible();
 await neutral.click();
 await expect(summary).toContainText('2 of 2 log events parsed completely');
 await expect(summary).toContainText('reviewed parser fix passes the current sample');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
 await page.getByRole('button',{name:'Advanced'}).click();
 await expect(page.getByLabel('Reviewed CSV column names')).toHaveValue('field_001,field_002,field_003,field_004,field_005');
 await expect(page.getByText('CSV field names reviewed. Automatic parser testing is ready.')).toBeVisible();
});


test('advanced CSV autofill does not approve column names until the explicit confirm action',async({page})=>{
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(batch())}));
 await page.goto('/');
 await page.getByRole('button',{name:'Advanced'}).click();
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const csv=page.getByLabel('Review CSV column names');
 await expect(csv).toBeVisible();
 await csv.getByRole('button',{name:'Fill 5 Neutral Column Names'}).click();
 await expect(page.getByLabel('Reviewed CSV column names')).toHaveValue(
  'field_001,field_002,field_003,field_004,field_005');
 await expect(csv).toContainText('Review required: confirm the CSV names and separator before creating the parser.');
 await csv.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
 await expect(csv).toContainText('CSV field names reviewed. Automatic parser testing is ready.');
});
