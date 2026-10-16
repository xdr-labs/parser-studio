import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

// This suite uses the REAL exact-SHA-pinned authoring backend.
// Only owner/sensor/tenant Test Lab calls are intercepted with public fixtures.
test.describe('approved offline evidence after run recovery; no target sender',()=>{
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1',
    'Needs the exact pinned backend over isolated localhost HTTP.');

  const runId='test_run_'+'a'.repeat(32);
  const revision='b'.repeat(64);
  const sha=(value:string|Uint8Array)=>createHash('sha256').update(value).digest('hex');
  const counts={
    generated:2,sendAttempted:2,sinkAccepted:1,
    sensorObserved:0,dpIndexed:1,fieldCompared:1,
  };
  const expiry='2099-01-01T12:15:00.000Z';
  const summary={
    contract:'testlab-redacted-summary.v0.1',mode:'OFFLINE_CONTRACT',
    runId,artifactRevisionId:revision,expiresAt:expiry,
    comparisonStatus:'OFFLINE_EVIDENCE_ONLY',counts,
    failureGroups:[{errorCode:'SEND_TIMEOUT',events:1}],
    fieldCoverage:[{field:'action',comparedEvents:1,matched:1,
      mismatched:0,missing:0,coveragePercent:100,matchPercent:100}],
    realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false,
  };
  const report={
    contract:'testlab-redacted-evidence.v0.1',mode:'OFFLINE_CONTRACT',
    runId,artifactRevisionId:revision,expiresAt:expiry,counts,
    events:[
      {sequence:0,generated:true,sendAttempted:true,sinkAccepted:true,
        sensorObserved:false,dpIndexed:true,fieldComparison:'FIELDS_MATCHED',
        fields:[{field:'action',status:'MATCH'}],errorCode:null},
      {sequence:1,generated:true,sendAttempted:true,sinkAccepted:false,
        sensorObserved:false,dpIndexed:false,fieldComparison:'NOT_VERIFIED',
        fields:[],errorCode:'SEND_TIMEOUT'},
    ],realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false,
  };
  const payload=JSON.stringify(report)+'\n';

  async function recoverWithoutSource(page:Page){
    await page.route('**/api/v1/test-lab/sessions/status*',route=>{
      expect(route.request().method()).toBe('GET');
      const query=new URL(route.request().url());
      expect(query.searchParams.get('runId')).toBe(runId);
      expect(route.request().postData()).toBeNull();
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify({
          runId,state:'STOPPED',sentCount:2,nextSequence:2,
          replayMode:'single',sampleFamilyCount:1,ratePerSecond:1,maxEvents:100,
          leaseExpiresAt:new Date(Date.now()-1000).toISOString(),
          lastSentAt:null,errorCode:null,parserLifecycleNotModified:true,
          realSensorVerified:false,runtimeParsingVerified:false,sensorIngestVerified:false,
        })});
    });
    await page.goto('/?workspace=chatgpt');
    await page.reload();
    await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
    await expect(page.getByLabel('Authorized Test Lab offline evidence')).toHaveCount(0);
    await page.getByRole('button',{name:'Tools & Diagnostics'}).click();
    const recovery=page.getByLabel('Authorized Test Lab session recovery');
    await recovery.locator('summary').click();
    await recovery.getByLabel('Existing authorized Test Lab run ID').fill(runId);
    await recovery.getByRole('button',{name:'Look Up My Authorized Run'}).click();
    await expect(recovery.getByLabel('Authorized terminal Test Lab session')).toContainText('STOPPED');
    const scope=page.getByLabel('Authorized Test Lab offline evidence');
    const panel=scope.getByLabel('Redacted Test Lab evidence review');
    await expect(panel).toBeVisible();
    await panel.locator('summary').click();
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
    return panel;
  }

  test('owner read of public-synthetic offline stages yields a SHA-verified JSON, even after refresh',async({page})=>{
    const capability=await page.request.get('/api/v1/parser-pairs/capabilities');
    expect(capability.status()).toBe(200);
    let summaries=0,exports=0;
    const allowed=['/api/v1/test-lab/sessions/status',
      '/api/v1/test-lab/sessions/evidence-summary',
      '/api/v1/test-lab/sessions/evidence-export'];
    await page.route('**/api/v1/test-lab/**',route=>{
      expect(allowed).toContain(new URL(route.request().url()).pathname);
      return route.abort();
    });
    await page.route('**/api/v1/test-lab/sessions/evidence-summary*',route=>{
      summaries++;
      expect(route.request().method()).toBe('GET');
      expect(route.request().postData()).toBeNull();
      expect(route.request().url()).toContain('runId='+runId);
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify(summary)});
    });
    await page.route('**/api/v1/test-lab/sessions/evidence-export*',route=>{
      exports++;
      expect(route.request().method()).toBe('GET');
      expect(route.request().postData()).toBeNull();
      expect(route.request().url()).not.toContain('apiKey');
      return route.fulfill({status:200,headers:{
        'content-type':'application/json; charset=utf-8',
        'content-disposition':'attachment; filename="testlab-evidence-'+runId+'.json"',
        'content-length':String(Buffer.byteLength(payload)),
        'cache-control':'no-store',
        'x-parser-evidence-sha256':sha(payload),
      },body:payload});
    });
    const panel=await recoverWithoutSource(page);
    expect(summaries+exports).toBe(0);
    await panel.getByRole('button',{name:'Load My Redacted Evidence Summary'}).click();
    const details=panel.getByLabel('Verified Test Lab evidence summary');
    await expect(details).toContainText('OFFLINE EVIDENCE ONLY');
    await expect(details.getByLabel('Offline field coverage')).toContainText('100%');
    await expect(details.getByLabel('Grouped Test Lab send failures')).toContainText('SEND_TIMEOUT');
    await expect(details).not.toContainText('PRIVATE_CUSTOMER_VALUE');
    expect(summaries).toBe(1);expect(exports).toBe(0);
    const downloading=page.waitForEvent('download');
    await panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'}).click();
    const download=await downloading;
    expect(download.suggestedFilename()).toBe('testlab-evidence-'+runId+'.json');
    const bytes=await readFile(await download.path());
    expect(sha(bytes)).toBe(sha(payload));
    expect(JSON.parse(bytes.toString('utf8'))).toEqual(report);
    expect(bytes.toString('utf8')).not.toContain('PRIVATE_CUSTOMER_VALUE');
    await expect(panel.getByRole('status')).toContainText('SHA-256');
    expect(exports).toBe(1);
    await expect(panel).toContainText('Full User E2E remain unverified');
    await expect(page.getByLabel('Active Test Lab session indicator')).toHaveCount(0);
  });

  test('owner 403/404, foreign raw metadata and tampered JSON SHA never leak or download evidence',async({page})=>{
    const actual=await page.request.get(
      '/api/v1/test-lab/sessions/evidence-summary?runId='+runId);
    expect(actual.status()).toBe(403);
    let kind:'deny'|'expired'|'forged'|'valid'='deny',summaries=0,exports=0;
    await page.route('**/api/v1/test-lab/**',route=>{
      const path=new URL(route.request().url()).pathname;
      expect(['/api/v1/test-lab/sessions/status',
        '/api/v1/test-lab/sessions/evidence-summary',
        '/api/v1/test-lab/sessions/evidence-export']).toContain(path);
      return route.abort();
    });
    await page.route('**/api/v1/test-lab/sessions/evidence-summary*',route=>{
      summaries++;
      if(kind==='deny')return route.fulfill({status:403,contentType:'application/json',
        body:JSON.stringify({error:'FOREIGN_OWNER',raw:'PRIVATE_CUSTOMER_VALUE'})});
      if(kind==='expired')return route.fulfill({status:404,contentType:'application/json',
        body:JSON.stringify({error:'EVIDENCE_EXPIRED'})});
      return route.fulfill({status:200,contentType:'application/json',
        body:JSON.stringify(kind==='forged'?{...summary,
          runId:'test_run_'+'f'.repeat(32),rawLog:'PRIVATE_CUSTOMER_VALUE'}:summary)});
    });
    await page.route('**/api/v1/test-lab/sessions/evidence-export*',route=>{
      exports++;
      return route.fulfill({status:200,headers:{
        'content-type':'application/json; charset=utf-8',
        'content-disposition':'attachment; filename="testlab-evidence-'+runId+'.json"',
        'content-length':String(Buffer.byteLength(payload)),
        'cache-control':'no-store',
        'x-parser-evidence-sha256':'0'.repeat(64),
      },body:payload});
    });
    const panel=await recoverWithoutSource(page);
    const inspect=panel.getByRole('button',{name:'Load My Redacted Evidence Summary'});
    for(const state of ['deny','expired','forged'] as const){
      kind=state;
      await inspect.click();
      const expected=state==='deny'?'access denied or unavailable (HTTP 403)':
        state==='expired'?'request refused (HTTP 404)':'Untrusted or unsafe';
      await expect(panel.getByRole('alert')).toContainText(expected);
      await expect(panel.getByLabel('Verified Test Lab evidence summary')).toHaveCount(0);
      expect(await panel.innerText()).not.toContain('PRIVATE_CUSTOMER_VALUE');
      await expect(panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'}))
        .toHaveCount(0);
    }
    kind='valid';
    await inspect.click();
    await expect(panel.getByLabel('Verified Test Lab evidence summary')).toBeVisible();
    let downloads=0;
    page.on('download',()=>downloads++);
    await panel.getByRole('button',{name:'Download Verified Redacted Evidence JSON'}).click();
    await expect(panel.getByRole('alert')).toContainText('Untrusted or unsafe');
    await expect(panel.getByRole('status')).toHaveCount(0);
    expect(downloads).toBe(0);
    expect(summaries).toBe(4);expect(exports).toBe(1);
    await expect(page.getByRole('complementary',{name:'Parser Studio navigation'})
      .locator('button.rail-link')).toHaveCount(2);
  });
});
