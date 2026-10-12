import { expect, test } from '@playwright/test';

const testLab={
  offlineJsonPreview:true,requiresBackendPreviewAuthorization:true,
  liveSensorSenderEnabled:true,trustedSinkSessionControlAvailable:true,
  sessionControlRequiresBackendAuthorization:true,
  sessionMaxRatePerSecond:5,sessionMaxLeaseMs:900000,
  sessionMaxAdditionalEventsPerRenewal:3000,sessionMaxCumulativeEvents:300000,
  sessionRenewalRequiresSeparateApproval:true,sessionDurableAcrossRestart:false,
  serverInjectedUdpTcpSinkAvailable:true,sinkRequiresIpLiteralAllowlist:true,
  sinkRequiresPerDeliveryPolicyAndAudit:true,
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
const runId='test_run_'+'a'.repeat(32);
const session={
  runId,state:'RUNNING',sentCount:0,nextSequence:0,
  replayMode:'single',sampleFamilyCount:1,ratePerSecond:2,
  maxEvents:100,leaseExpiresAt:'2026-10-12T05:01:00.000Z',
  lastSentAt:null,errorCode:null,
  parserLifecycleNotModified:true,realSensorVerified:false,
  runtimeParsingVerified:false,sensorIngestVerified:false,
};

test('disabled by default Test Lab never activates a browser session or sends sensor traffic',async({page})=>{
  let starts=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({...caps,testLab:{...testLab,liveSensorSenderEnabled:false}}),
  }));
  await page.route('**/api/v1/test-lab/sessions/*',route=>{starts++;return route.abort();});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('{"action":"deny","username":"CUSTOMER_SECRET"}');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-owner-testlab summary').click();
  await expect(page.getByRole('button',{name:'Test Lab 전송 조건 확인'})).toBeVisible();
  await expect(page.getByLabel('Test Lab approval identifier')).toHaveCount(0);
  await page.getByRole('button',{name:'Test Lab 전송 조건 확인'}).click();
  await expect(page.locator('.guided-owner-testlab [role="alert"]')).toContainText('차단');
  await expect(page.getByRole('button',{name:/승인형 Test Lab 시작/})).toHaveCount(0);
  expect(starts).toBe(0);
});

test('separately approved synthetic Test Lab session: explicit start/pause/resume/stop, no raw customer sample',async({page})=>{
  const observed:Array<{action:string;method:string;body:unknown}>=[];
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/test-lab/sessions/*',route=>{
    const action=new URL(route.request().url()).pathname.split('/').pop()??'';
    const body=route.request().postData()?route.request().postDataJSON():null;
    observed.push({action,method:route.request().method(),body});
    if(action==='start') {
      expect(body).toMatchObject({
        approvalId:'owner-approved-synthetic',ratePerSecond:2,
        leaseMs:60000,maxEvents:100,
        sample:{format:'json',runMarkerField:'test.run_id',seed:42,sequence:0},
      });
      const raw=JSON.stringify(body);
      expect(raw).not.toContain('CUSTOMER_SECRET');
      expect(raw).not.toContain('10.0.0.23');
      expect(raw).not.toContain('dpUrl');
      expect(raw).not.toContain('sensorIp');
      expect(raw).not.toContain('apiKey');
      expect((body as {sample:{source:string}}).sample.source).toContain('192.0.2.10');
    }
    return route.fulfill({
      status:200,contentType:'application/json',
      body:JSON.stringify({...session,
        state:action==='pause'?'PAUSED':action==='stop'?'STOPPED':'RUNNING',
        sentCount:action==='start'?0:2,nextSequence:action==='start'?0:2,
      }),
    });
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('{"action":"allow","username":"CUSTOMER_SECRET","src_ip":"10.0.0.23"}');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-owner-testlab summary').click();
  await page.getByRole('button',{name:'Test Lab 전송 조건 확인'}).click();
  const launch=page.getByRole('button',{name:'승인형 Test Lab 시작 (최대 60초/100건)'});
  await expect(launch).toBeDisabled();
  await page.getByLabel('Test Lab approval identifier').fill('owner-approved-synthetic');
  await page.getByLabel('Approved Test Lab rate').selectOption('2');
  await expect(launch).toBeDisabled();
  await page.getByLabel('I confirm approved sensor test').check();
  await expect(launch).toBeEnabled();
  await launch.click();
  const status=page.getByLabel('Test Lab session status');
  await expect(status).toContainText('RUNNING');
  await expect(status).toContainText(runId);
  await expect(status).toContainText('실제 센서 수신');
  await expect(status).not.toContainText('CUSTOMER_SECRET');
  await status.getByRole('button',{name:'세션 일시정지'}).click();
  await expect(status).toContainText('PAUSED');
  await status.getByRole('button',{name:'세션 재개'}).click();
  await expect(status).toContainText('RUNNING');
  await status.getByRole('button',{name:'서버 세션 중지'}).click();
  await expect(status).toContainText('STOPPED');
  expect(observed.map(x=>x.action)).toEqual(['start','pause','resume','stop']);
  expect(observed.slice(1).every(x=>JSON.stringify(x.body)===JSON.stringify({runId}))).toBe(true);
});

test('renewing a server session requires separate approval, no implicit renewal',async({page})=>{
  const inputs:unknown[]=[];
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/test-lab/sessions/*',route=>{
    const action=new URL(route.request().url()).pathname.split('/').pop();
    if(action==='renew')inputs.push(route.request().postDataJSON());
    return route.fulfill({
      status:200,contentType:'application/json',body:JSON.stringify({
        ...session,maxEvents:action==='renew'?120:100,
      }),
    });
  });
  await page.goto('/');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-owner-testlab summary').click();
  await page.getByRole('button',{name:'Test Lab 전송 조건 확인'}).click();
  await page.getByLabel('Test Lab approval identifier').fill('owner-approved-synthetic');
  await page.getByLabel('I confirm approved sensor test').check();
  await page.getByRole('button',{name:'승인형 Test Lab 시작 (최대 60초/100건)'}).click();
  const renewed=page.getByRole('button',{name:'60초·20건 추가 승인 요청'});
  await expect(renewed).toBeDisabled();
  await page.getByLabel('New Test Lab renewal approval').fill('fresh-owner-approval-2');
  await renewed.click();
  await expect(page.getByLabel('Test Lab session status')).toContainText('0/120');
  expect(inputs).toEqual([{
    runId,approvalId:'fresh-owner-approval-2',leaseMs:60000,additionalEvents:20,
  }]);
});

test('server 403 denial after capability discovery never invents an active Test Lab session',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/test-lab/sessions/start',route=>route.fulfill({
    status:403,contentType:'application/json',body:JSON.stringify({error:'TESTLAB_START_DENIED'}),
  }));
  await page.goto('/');
  await page.getByRole('button',{name:/6\. 파일 생성/}).click();
  await page.locator('.guided-owner-testlab summary').click();
  await page.getByRole('button',{name:'Test Lab 전송 조건 확인'}).click();
  await page.getByLabel('Test Lab approval identifier').fill('owner-approved-synthetic');
  await page.getByLabel('I confirm approved sensor test').check();
  await page.getByRole('button',{name:'승인형 Test Lab 시작 (최대 60초/100건)'}).click();
  await expect(page.locator('.guided-owner-testlab [role="alert"]')).toContainText('거부');
  await expect(page.getByLabel('Test Lab session status')).toHaveCount(0);
});
