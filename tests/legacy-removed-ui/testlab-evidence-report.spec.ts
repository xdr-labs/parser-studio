import {expect,test,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const runId='test_run_'+'a'.repeat(32);
const revision='b'.repeat(64);
const sha=(bytes:string|Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const counts={generated:2,sendAttempted:2,sinkAccepted:1,sensorObserved:0,dpIndexed:1,fieldCompared:1};
const summary={contract:'testlab-redacted-summary.v0.1',mode:'OFFLINE_CONTRACT',
  runId,artifactRevisionId:revision,expiresAt:'2026-10-12T12:15:00.000Z',
  comparisonStatus:'OFFLINE_EVIDENCE_ONLY',counts,
  failureGroups:[{errorCode:'SEND_TIMEOUT',events:1}],
  fieldCoverage:[{field:'action',comparedEvents:1,matched:1,mismatched:0,
    missing:0,coveragePercent:100,matchPercent:100}],
  realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false};
const report={contract:'testlab-redacted-evidence.v0.1',mode:'OFFLINE_CONTRACT',
  runId,artifactRevisionId:revision,expiresAt:summary.expiresAt,counts,
  events:[
    {sequence:0,generated:true,sendAttempted:true,sinkAccepted:true,
      sensorObserved:false,dpIndexed:true,fieldComparison:'FIELDS_MATCHED',
      fields:[{field:'action',status:'MATCH'}],errorCode:null},
    {sequence:1,generated:true,sendAttempted:true,sinkAccepted:false,
      sensorObserved:false,dpIndexed:false,fieldComparison:'NOT_VERIFIED',
      fields:[],errorCode:'SEND_TIMEOUT'},
  ],realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false};
const session={runId,state:'STOPPED',sentCount:2,nextSequence:2,
  replayMode:'single',sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
  leaseExpiresAt:'2026-10-12T12:00:00.000Z',lastSentAt:null,errorCode:null,
  parserLifecycleNotModified:true,realSensorVerified:false,
  runtimeParsingVerified:false,sensorIngestVerified:false};
async function prepareOwnedRun(page:Page){
  await page.route('**/api/v1/test-lab/sessions/status*',route=>{
    expect(route.request().method()).toBe('GET');
    expect(new URL(route.request().url()).searchParams.get('runId')).toBe(runId);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(session)});
  });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('{"username":"CUSTOMER_SECRET","src_ip":"198.51.100.101"}');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-owner-testlab summary').first().click();
  await page.getByLabel('Existing Test Lab run ID').fill(runId);
  await page.getByRole('button',{name:'Look Up Test Lab Session by Run ID'}).click();
  await expect(page.getByLabel('Test Lab session status')).toContainText('STOPPED');
  await page.locator('.guided-testlab-evidence summary').click();
}
const downloadHeaders=(body:string,overrideHash?:string)=>({
  'content-type':'application/json; charset=utf-8',
  'content-disposition':'attachment; filename="testlab-evidence-'+runId+'.json"',
  'content-length':String(Buffer.byteLength(body)),
  'cache-control':'no-store',
  'x-parser-evidence-sha256':overrideHash??sha(body),
});

test('nondeveloper reviews owner-scoped offline counts, field coverage, failures and verified redacted JSON',async({page})=>{
  let summaryCalls=0,exportCalls=0;
  const body=JSON.stringify(report)+'\n';
  await page.route('**/api/v1/test-lab/sessions/evidence-summary*',route=>{
    summaryCalls++;
    expect(route.request().method()).toBe('GET');
    expect(route.request().postData()).toBe(null);
    expect(route.request().url()).toContain('runId='+runId);
    expect(route.request().url()).not.toContain('CUSTOMER_SECRET');
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(summary)});
  });
  await page.route('**/api/v1/test-lab/sessions/evidence-export*',route=>{
    exportCalls++;
    expect(route.request().method()).toBe('GET');
    expect(route.request().postData()).toBe(null);
    expect(route.request().url()).not.toContain('198.51.100.101');
    return route.fulfill({status:200,headers:downloadHeaders(body),body});
  });
  await prepareOwnedRun(page);
  expect(summaryCalls+exportCalls).toBe(0);
  const panel=page.getByLabel('Redacted Test Lab evidence review');
  await expect(panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'})).toHaveCount(0);
  await panel.getByRole('button',{name:'Load My Redacted Evidence Summary'}).click();
  const result=page.getByLabel('Verified Test Lab evidence summary');
  await expect(result).toContainText('OFFLINE EVIDENCE ONLY');
  await expect(result.getByLabel('Offline evidence stage counts')).toContainText('Offline indexed callbacks');
  await expect(result.getByLabel('Offline field coverage')).toContainText('action');
  await expect(result.getByLabel('Offline field coverage')).toContainText('100%');
  await expect(result.getByLabel('Grouped Test Lab send failures')).toContainText('SEND_TIMEOUT');
  await expect(result).not.toContainText('CUSTOMER_SECRET');
  await expect(result).not.toContainText('198.51.100.101');
  expect(summaryCalls).toBe(1);expect(exportCalls).toBe(0);
  const downloadEvent=page.waitForEvent('download');
  await panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'}).click();
  const downloaded=await downloadEvent;
  expect(downloaded.suggestedFilename()).toBe('testlab-evidence-'+runId+'.json');
  const file=await readFile(await downloaded.path());
  expect(sha(file)).toBe(sha(body));
  expect(JSON.parse(file.toString('utf8'))).toEqual(report);
  expect(file.toString('utf8')).not.toContain('CUSTOMER_SECRET');
  expect(file.toString('utf8')).not.toContain('198.51.100.101');
  await expect(panel.getByRole('status')).toContainText('SHA-256');
  expect(summaryCalls).toBe(1);expect(exportCalls).toBe(1);
  await expect(panel).toContainText('Full User E2E remain unverified');
});

test('default 403 and foreign-run response never reveal private evidence or enable export',async({page})=>{
  let mode:'403'|'foreign'='403',summaryCalls=0,exportCalls=0;
  await page.route('**/api/v1/test-lab/sessions/evidence-summary*',route=>{
    summaryCalls++;
    return mode==='403'
      ? route.fulfill({status:403,contentType:'application/json',body:JSON.stringify({error:'TESTLAB_SESSION_DENIED',raw:'customer-private'})})
      : route.fulfill({status:200,contentType:'application/json',
          body:JSON.stringify({...summary,runId:'test_run_'+'f'.repeat(32),privateValue:'CUSTOMER_SECRET'})});
  });
  await page.route('**/api/v1/test-lab/sessions/evidence-export*',route=>{
    exportCalls++;
    return route.abort();
  });
  await prepareOwnedRun(page);
  const panel=page.getByLabel('Redacted Test Lab evidence review');
  await panel.getByRole('button',{name:'Load My Redacted Evidence Summary'}).click();
  await expect(panel.getByRole('alert')).toContainText('access denied or unavailable');
  await expect(page.getByLabel('Verified Test Lab evidence summary')).toHaveCount(0);
  mode='foreign';
  await panel.getByRole('button',{name:'Load My Redacted Evidence Summary'}).click();
  await expect(panel.getByRole('alert')).toContainText('Untrusted or unsafe');
  expect(await panel.innerText()).not.toContain('CUSTOMER_SECRET');
  expect(await panel.innerText()).not.toContain('customer-private');
  expect(summaryCalls).toBe(2);
  expect(exportCalls).toBe(0);
  await expect(panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'})).toHaveCount(0);
});

test('tampered evidence SHA does not create JSON download or verification receipt',async({page})=>{
  let exportCalls=0;
  const body=JSON.stringify(report)+'\n';
  await page.route('**/api/v1/test-lab/sessions/evidence-summary*',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(summary),
  }));
  await page.route('**/api/v1/test-lab/sessions/evidence-export*',route=>{
    exportCalls++;
    return route.fulfill({status:200,headers:downloadHeaders(body,'0'.repeat(64)),body});
  });
  await prepareOwnedRun(page);
  const panel=page.getByLabel('Redacted Test Lab evidence review');
  await panel.getByRole('button',{name:'Load My Redacted Evidence Summary'}).click();
  let downloads=0;
  page.on('download',()=>downloads++);
  await panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'}).click();
  await expect(panel.getByRole('alert')).toContainText('Untrusted or unsafe');
  await expect(panel.getByRole('status')).toHaveCount(0);
  expect(downloads).toBe(0);expect(exportCalls).toBe(1);
});
