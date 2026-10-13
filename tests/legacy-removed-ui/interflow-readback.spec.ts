import { expect, test } from '@playwright/test';

const runId='test_run_'+'a'.repeat(32);
const testLab={
  offlineJsonPreview:true,requiresBackendPreviewAuthorization:true,
  liveSensorSenderEnabled:true,trustedSinkSessionControlAvailable:true,
  sessionControlRequiresBackendAuthorization:true,
  sessionMaxRatePerSecond:5,sessionMaxLeaseMs:900000,
  sessionMaxAdditionalEventsPerRenewal:3000,sessionMaxCumulativeEvents:300000,
  sessionRenewalRequiresSeparateApproval:true,sessionDurableAcrossRestart:false,
  serverInjectedUdpTcpSinkAvailable:true,sinkRequiresIpLiteralAllowlist:true,
  sinkRequiresPerDeliveryPolicyAndAudit:true,
  interflowReadClientAvailable:true,interflowBoundedPollingAvailable:true,
  interflowMaxPollAttempts:6,interflowMaxPollWindowMs:15000,
  interflowCursorVerified:false,interflowSearchPermissionsVerified:false,
  interflowRealTargetVerified:false,
  sensorIngestVerified:false,runtimeParsingVerified:false,
};
const caps={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{
    receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false,
  },
  testLab,
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const session={
  runId,state:'RUNNING',sentCount:0,nextSequence:0,replayMode:'single',sampleFamilyCount:1,
  ratePerSecond:1,maxEvents:100,leaseExpiresAt:'2026-10-12T06:30:00.000Z',
  lastSentAt:null,errorCode:null,parserLifecycleNotModified:true,
  realSensorVerified:false,runtimeParsingVerified:false,sensorIngestVerified:false,
};
const result={
  state:'MATCHED_RESPONSE_FIELDS',matchCount:2,fields:[{field:'action',status:'MATCH'}],
  sensorReceivedVerified:false,endToEndVerified:false,
  runtimeParsingVerified:false,targetImportVerified:false,
};

async function prepareOwnedRun(page:import('@playwright/test').Page) {
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/test-lab/sessions/start',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(session),
  }));
  await page.goto('/?workspace=guided');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-owner-testlab summary').first().click();
  await page.getByRole('button',{name:'Check Test Lab Delivery Requirements'}).click();
  await page.getByLabel('Test Lab approval identifier').fill('owner-approved-synthetic');
  await page.getByLabel('I confirm approved sensor test').check();
  await page.getByRole('button',{name:'Start Approved Test Lab (Max 60s / 100 Events)'}).click();
  await expect(page.getByLabel('Test Lab session status')).toContainText('RUNNING');
  await page.locator('.guided-interflow-readback summary').click();
}

test('audited Interflow field match is an explicitly requested, bounded and unverified read',async({page})=>{
  let calls=0;
  await page.route('**/api/v1/test-lab/interflow/search',route=>{
    calls++;
    expect(route.request().method()).toBe('POST');
    const body=route.request().postDataJSON();
    expect(Object.keys(body).sort()).toEqual([
      'endMs','expectedFields','index','limit','markerField','runId','startMs',
    ]);
    expect(body).toMatchObject({
      runId,index:'syslog',markerField:'test.run_id',limit:20,
      expectedFields:{action:'allow'},
    });
    expect(body.endMs-body.startMs).toBe(300000);
    for(const value of ['CUSTOMER_SECRET','apiKey','dpUrl','sensorIp','PRIVATE_TENANT']){
      expect(JSON.stringify(body)).not.toContain(value);
    }
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});
  });
  await prepareOwnedRun(page);
  await page.getByLabel('Guided raw sample logs').count().catch(()=>0);
  const group=page.locator('.guided-interflow-readback');
  const button=group.getByRole('button',{name:'Compare Fields (Read-only, Max 20 Events)'});
  await expect(button).toBeDisabled();
  expect(calls).toBe(0);
  await page.getByLabel('I confirm independent tenant read approval').check();
  await expect(button).toBeEnabled();
  await button.click();
  const evidence=page.getByLabel('Interflow field comparison result');
  await expect(evidence).toContainText('Requested Fields Matched · E2E Unverified');
  await expect(evidence).toContainText('action: MATCH');
  await expect(evidence).toContainText('sensor receipt');
  await expect(evidence).not.toContainText('CUSTOMER_SECRET');
  expect(calls).toBe(1);
});

test('Interflow readback is hidden until a separately authorized backend run exists',async({page})=>{
  let readCalls=0;
  await page.route('**/api/v1/test-lab/interflow/search',route=>{readCalls++;return route.abort();});
  await page.goto('/?workspace=guided');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-owner-testlab summary').first().click();
  await expect(page.locator('.guided-interflow-readback')).toHaveCount(0);
  expect(readCalls).toBe(0);
});

test('backend 403/404 denied tenant read never becomes a false successful no-match',async({page})=>{
  await page.route('**/api/v1/test-lab/interflow/search',route=>route.fulfill({
    status:403,contentType:'application/json',body:JSON.stringify({error:'INTERFLOW_SEARCH_DENIED'}),
  }));
  await prepareOwnedRun(page);
  await page.getByLabel('I confirm independent tenant read approval').check();
  await page.getByRole('button',{name:'Compare Fields (Read-only, Max 20 Events)'}).click();
  await expect(page.locator('.guided-interflow-readback [role="alert"]')).toContainText('denied or unavailable');
  await expect(page.getByLabel('Interflow field comparison result')).toHaveCount(0);
});

test('unexpected raw vendor record and fake E2E verified flag cannot enter the UI',async({page})=>{
  await page.route('**/api/v1/test-lab/interflow/search',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({...result,endToEndVerified:true,raw_log:'PRIVATE_VENDOR_EVENT'}),
  }));
  await prepareOwnedRun(page);
  await page.getByLabel('I confirm independent tenant read approval').check();
  await page.getByRole('button',{name:'Compare Fields (Read-only, Max 20 Events)'}).click();
  await expect(page.locator('.guided-interflow-readback [role="alert"]')).toBeVisible();
  await expect(page.locator('.guided-interflow-readback')).not.toContainText('PRIVATE_VENDOR_EVENT');
  await expect(page.getByLabel('Interflow field comparison result')).toHaveCount(0);
});

test('NO_MATCH remains unverified rather than implying the sensor received nothing',async({page})=>{
  await page.route('**/api/v1/test-lab/interflow/search',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({...result,state:'NO_MATCH',matchCount:0,
      fields:[{field:'action',status:'MISSING'}]}),
  }));
  await prepareOwnedRun(page);
  await page.getByLabel('I confirm independent tenant read approval').check();
  await page.getByRole('button',{name:'Compare Fields (Read-only, Max 20 Events)'}).click();
  await expect(page.getByLabel('Interflow field comparison result')).toContainText('No Matching Event · E2E Unverified');
});
