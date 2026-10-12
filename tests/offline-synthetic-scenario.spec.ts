import {expect,test} from '@playwright/test';

const capabilities={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{
    receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false,
  },
  testLab:{
    scenarioOfflinePreviewAvailable:true,multiSampleReplayAvailable:true,
    constantRateScenarioAvailable:true,boundedOriginalGapsScenarioAvailable:true,
    scenarioMaxSamples:12,scenarioRunMarkerRequired:true,
    requiresBackendPreviewAuthorization:true,liveSensorSenderEnabled:false,
    sensorIngestVerified:false,runtimeParsingVerified:false,
  },
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

function mockResult(mode:'constant-rate'|'original-gaps',sequence:number){
  return {
    sampleId:sequence%2===0?'allow-event':'deny-event',
    nextDelayMs:mode==='constant-rate'?500:600,
    replayMode:mode,sampleFamilyCount:2,
    safeToSendToSensor:false,sensorReceivedVerified:false,runtimeParsingVerified:false,
    preview:{
      contract:'parser-studio.synthetic-preview.v0.1',format:'json',
      sequence,generatedAt:'2026-10-12T05:20:00.000Z',
      changedPaths:['time','src_ip','username','url','run_id'],
      syntheticEvent:JSON.stringify({
        time:'2026-10-12T05:20:00Z',src_ip:'192.0.2.253',
        username:'synthetic_user_300397',
        url:'https://synthetic.invalid/synthetic/f040cef8',
        action:sequence%2===0?'allow':'deny',
        run_id:'test_run_'+'0'.repeat(32),
      }),
      safeToSendToSensor:false,runtimeParsingVerified:false,targetSensorVerified:false,
    },
  };
}

async function openScenario(page:import('@playwright/test').Page){
  await page.goto('/');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-scenario-preview summary').click();
  return page.getByRole('button',{name:'Preview Selected Synthetic Scenario Event'});
}

test('opt-in offline scenario previews two public JSON families without any sender or customer data',async({page})=>{
  let posts=0,unexpected=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities),
  }));
  await page.route('**/api/v1/test-lab/scenario/preview',route=>{
    posts++;
    const body=route.request().postDataJSON();
    expect(route.request().method()).toBe('POST');
    expect(Object.keys(body).sort()).toEqual(['ratePerSecond','scenario','sequence']);
    expect(body.ratePerSecond).toBe(2);
    expect(body.scenario.mode).toBe('constant-rate');
    expect(body.scenario.events).toHaveLength(2);
    expect(body.scenario.events[0].sample.source).toContain('192.0.2.10');
    expect(body.scenario.events[1].sample.source).toContain('198.51.100.20');
    for(const secret of ['apiKey','CUSTOMER_SECRET','PRIVATE_LOG','sensorIp','dpUrl','approvalId','runId']){
      expect(JSON.stringify(body)).not.toContain(secret);
    }
    return route.fulfill({
      status:200,contentType:'application/json',
      body:JSON.stringify(mockResult('constant-rate',body.sequence)),
    });
  });
  page.on('request',req=>{
    if(req.url().includes('/api/v1/test-lab/sessions/') ||
      req.url().includes('/api/v1/stellar/legacy/'))unexpected++;
  });
  const button=await openScenario(page);
  expect(posts).toBe(0);
  await button.click();
  const preview=page.getByLabel('Offline synthetic scenario result');
  await expect(preview).toContainText('allow-event');
  await expect(preview).toContainText('Next event gap: 500 ms');
  await expect(preview).toContainText('Not sent to a sensor');
  await expect(page.getByLabel('Public synthetic scenario event')).toContainText('synthetic_user_300397');
  await expect(preview).not.toContainText('CUSTOMER_SECRET');
  await page.getByLabel('Offline synthetic scenario sequence').selectOption('1');
  await expect(preview).toHaveCount(0);
  expect(posts).toBe(1);
  await button.click();
  await expect(page.getByLabel('Offline synthetic scenario result')).toContainText('deny-event');
  await expect(page.getByLabel('Public synthetic scenario event')).toContainText('"action":"deny"');
  expect(posts).toBe(2);
  expect(unexpected).toBe(0);
});

test('the reviewed original-gap plan is explicit, bounded and never inferred from user logs',async({page})=>{
  let posts=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities),
  }));
  await page.route('**/api/v1/test-lab/scenario/preview',route=>{
    posts++;
    const request=route.request().postDataJSON();
    expect(request.scenario.mode).toBe('original-gaps');
    expect(request.scenario.cycleMs).toBe(1200);
    expect(request.scenario.events.map((e:{offsetMs:number})=>e.offsetMs)).toEqual([0,600]);
    expect(request.sequence).toBe(3);
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify(mockResult('original-gaps',3)),
    });
  });
  const button=await openScenario(page);
  await page.getByLabel('Offline synthetic scenario mode').selectOption('original-gaps');
  await page.getByLabel('Offline synthetic scenario sequence').selectOption('3');
  await expect(page.getByLabel('Offline synthetic scenario result')).toHaveCount(0);
  expect(posts).toBe(0);
  await button.click();
  const proof=page.getByLabel('Offline synthetic scenario result');
  await expect(proof).toContainText('original-gaps');
  await expect(proof).toContainText('Next event gap: 600 ms');
  await expect(proof).toContainText('Event #4');
  expect(posts).toBe(1);
});

test('unsupported preview capability is blocked without any synthetic POST',async({page})=>{
  let posts=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({...capabilities,testLab:{
      ...capabilities.testLab,scenarioOfflinePreviewAvailable:false,
    }}),
  }));
  await page.route('**/api/v1/test-lab/scenario/preview',route=>{posts++;return route.abort();});
  const button=await openScenario(page);
  await button.click();
  await expect(page.locator('.guided-scenario-preview [role="alert"]')).toContainText('denied or cannot verify');
  await expect(page.getByLabel('Offline synthetic scenario result')).toHaveCount(0);
  expect(posts).toBe(0);
});

test('HTTP 403 denial does not produce a synthetic scenario or start a sender',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities),
  }));
  await page.route('**/api/v1/test-lab/scenario/preview',route=>route.fulfill({
    status:403,contentType:'application/json',body:JSON.stringify({error:'TESTLAB_PREVIEW_NOT_AUTHORIZED'}),
  }));
  const button=await openScenario(page);
  await button.click();
  await expect(page.locator('.guided-scenario-preview [role="alert"]')).toContainText('authorization grant');
  await expect(page.getByLabel('Offline synthetic scenario result')).toHaveCount(0);
});

test('untrusted status flags and vendor raw event are never displayed',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities),
  }));
  await page.route('**/api/v1/test-lab/scenario/preview',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({
      ...mockResult('constant-rate',0),runtimeParsingVerified:true,rawEvent:'PRIVATE_VENDOR_LOG',
    }),
  }));
  const button=await openScenario(page);
  await button.click();
  await expect(page.locator('.guided-scenario-preview [role="alert"]')).toBeVisible();
  await expect(page.locator('.guided-scenario-preview')).not.toContainText('PRIVATE_VENDOR_LOG');
  await expect(page.getByLabel('Offline synthetic scenario result')).toHaveCount(0);
});
