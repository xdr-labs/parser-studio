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
 await expect(summary).toContainText('Values found in 2 of 2 log events');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 const csvReview=page.getByLabel('Review CSV column names');
 await expect(csvReview).toContainText('Values found, but this log does not include field names');
 await expect(csvReview).toContainText('cannot safely guess what the columns mean');
 const neutral=csvReview.getByRole('button',{name:'Keep all 5 values with temporary names'});
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
 await expect(summary).toContainText('built a parser rule that passes the current sample');
 await expect(page.getByLabel('Parse problem inspector')).toHaveCount(0);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
 await expect(page.getByLabel('Reviewed CSV column names')).toHaveValue('field_001,field_002,field_003,field_004,field_005');
 await expect(page.getByText('Field names are ready. Continue to Review Fields.')).toBeVisible();
});

test('source-complete variable-width positional CSV explains that one schema cannot cover every row',async({page})=>{
 const unevenLines=[
  'Nov 30 16:44:36 PA-220 1,2018/11/30 16:44:36,THREAT,192.0.2.10,443',
  'Nov 30 16:44:37 PA-220 1,2018/11/30 16:44:37,THREAT,192.0.2.11,8443,extra',
 ];
 const unevenRaw=unevenLines.join('\n');
 let cursor=0;
 const events=unevenLines.map((line,index)=>{
  const startByte=cursor,endByte=startByte+Buffer.byteLength(line);cursor=endByte+(index===0?1:0);
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'SYSLOG_BSD_CSV',sourceSha256:sha(line),sourceBytes:Buffer.byteLength(line),
   fields:{},spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
  }};
 });
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   contract:'parser-studio.multipass-source-batch-preview.v0.1',
   sourceSha256:sha(unevenRaw),sourceBytes:Buffer.byteLength(unevenRaw),eventCount:2,events,
   separators:[{startByte:events[0]!.endByte,endByte:events[0]!.endByte+1,kind:'WHITESPACE'}],
   nativeVerified:false,targetVerified:false,
  })}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(unevenRaw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toContainText('Values found in 2 of 2 log events');
 await expect(summary).toContainText('do not share one consistent CSV shape');
 await expect(summary).not.toContainText('parsed completely');
 const csvReview=page.getByLabel('Review CSV column names');
 await expect(csvReview).toContainText('These rows contain different numbers of values');
 await expect(csvReview).toContainText('One parser would shift values into the wrong fields');
 const groups=csvReview.getByLabel('CSV row shape groups');
 await expect(groups).toContainText('5 columns · 1 event · event 1');
 await expect(groups).toContainText('6 columns · 1 event · event 2');
 await expect(groups).toContainText('No source event is discarded automatically');
 await expect(csvReview.getByRole('button',{name:'I Confirm These CSV Column Names'})).toBeDisabled();
 await expect(csvReview.getByRole('status')).toContainText('separated into matching positional shapes');
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
});

test('shape diagnostics report rows above the 100-column parser limit without enabling confirmation',async({page})=>{
 const normal=Array.from({length:5},(_,index)=>String(index)).join(',');
 const wide=Array.from({length:120},(_,index)=>String(index)).join(',');
 const source=normal+'\n'+wide;
 let cursor=0;
 const lines=[normal,wide];
 const events=lines.map((line,index)=>{
  const startByte=cursor,endByte=startByte+Buffer.byteLength(line);cursor=endByte+(index===0?1:0);
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'CSV_UNLABELED',sourceSha256:sha(line),sourceBytes:Buffer.byteLength(line),
   fields:{},spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
  }};
 });
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   contract:'parser-studio.multipass-source-batch-preview.v0.1',
   sourceSha256:sha(source),sourceBytes:Buffer.byteLength(source),eventCount:2,events,
   separators:[{startByte:events[0]!.endByte,endByte:events[0]!.endByte+1,kind:'WHITESPACE'}],
   nativeVerified:false,targetVerified:false,
  })}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const groups=page.getByLabel('CSV row shape groups');
 await expect(groups).toContainText('5 columns · 1 event · event 1');
 await expect(groups).toContainText('120 columns · 1 event · event 2 · exceeds the 100-column parser limit');
 await expect(page.getByRole('button',{name:'I Confirm These CSV Column Names'})).toBeDisabled();
});

test('shape diagnostics keep valid groups visible when another event has malformed CSV quoting',async({page})=>{
 const lines=['a,b','1,"unterminated','4,5'];
 const source=lines.join('\n');
 let cursor=0;
 const events=lines.map((line,index)=>{
  const startByte=cursor,endByte=startByte+Buffer.byteLength(line);cursor=endByte+(index<lines.length-1?1:0);
  return {index,startByte,endByte,preview:{
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'CSV_UNLABELED',sourceSha256:sha(line),sourceBytes:Buffer.byteLength(line),
   fields:{},spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
  }};
 });
 await page.route('**/api/v1/multipass/preview-batch',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   contract:'parser-studio.multipass-source-batch-preview.v0.1',
   sourceSha256:sha(source),sourceBytes:Buffer.byteLength(source),eventCount:3,events,
   separators:[
    {startByte:events[0]!.endByte,endByte:events[0]!.endByte+1,kind:'WHITESPACE'},
    {startByte:events[1]!.endByte,endByte:events[1]!.endByte+1,kind:'WHITESPACE'},
   ],nativeVerified:false,targetVerified:false,
  })}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const groups=page.getByLabel('CSV row shape groups');
 await expect(groups).toContainText('2 columns · 2 events · event 1, 3');
 await expect(groups).toContainText('Not safe CSV: event 2');
 await expect(groups).toContainText('needs separate review');
 await expect(page.getByRole('button',{name:'I Confirm These CSV Column Names'})).toBeDisabled();
});
