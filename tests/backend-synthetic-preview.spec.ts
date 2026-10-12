import { expect, test } from '@playwright/test';

const caps = {
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{
    receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false,
  },
  testLab:{
    offlineJsonPreview:true,requiresBackendPreviewAuthorization:true,
    liveSensorSenderEnabled:false,sensorIngestVerified:false,runtimeParsingVerified:false,
  },
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const preview = {
  contract:'parser-studio.synthetic-preview.v0.1',format:'json',sequence:0,
  syntheticEvent:JSON.stringify({
    time:'2026-10-12T02:00:00Z',
    src_ip:'192.0.2.42',username:'synthetic_user_100123',
    url:'https://synthetic.invalid/synthetic/1234abcd',action:'allow',
  }),
  generatedAt:'2026-10-12T02:00:00.000Z',
  changedPaths:['time','src_ip','username','url'],
  safeToSendToSensor:false,runtimeParsingVerified:false,targetSensorVerified:false,
};

test('user-authorized fixed synthetic preview never sends customer logs, keys, or sensor traffic',async({page})=>{
  let requests=0,previewCalls=0,otherCalls=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>{
    requests++;
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(caps)});
  });
  await page.route('**/api/v1/test-lab/preview',route=>{
    previewCalls++;
    const post=route.request().postDataJSON();
    expect(route.request().method()).toBe('POST');
    expect(post).toMatchObject({
      format:'json',seed:42,sequence:0,timestampField:'time',
      variableFields:[
        {path:'src_ip',kind:'ipv4'},
        {path:'username',kind:'username'},
        {path:'url',kind:'url'},
      ],
    });
    expect(post.source).toContain('192.0.2.10');
    expect(post.source).toContain('example.invalid');
    for(const secret of ['CUSTOMER_TOP_SECRET','10.0.0.90','apiKey','approvalId','sensorIp']){
      expect(JSON.stringify(post)).not.toContain(secret);
    }
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(preview)});
  });
  page.on('request',req=>{
    if(req.url().includes('/api/v1/test-lab/sessions/'))otherCalls++;
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"action":"allow","username":"CUSTOMER_TOP_SECRET","src_ip":"10.0.0.90"}',
  );
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-backend-synthetic summary').click();
  expect(requests).toBe(0);
  expect(previewCalls).toBe(0);
  await page.getByRole('button',{name:'Preview Backend Public Synthetic Sample'}).click();
  const display=page.getByLabel('Approved synthetic sample result');
  await expect(display).toContainText('Synthetic JSON');
  await expect(display).toContainText('Sensor Delivery Disabled');
  const log=page.getByLabel('Backend public synthetic log');
  await expect(log).toContainText('192.0.2.42');
  await expect(log).toContainText('synthetic_user_100123');
  await expect(log).not.toContainText('CUSTOMER_TOP_SECRET');
  await expect(display).not.toContainText('10.0.0.90');
  expect(requests).toBe(1);
  expect(previewCalls).toBe(1);
  expect(otherCalls).toBe(0);
});

test('unsupported or unconfigured backend never sends a synthetic preview POST',async({page})=>{
  let post=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify({
      ...caps,testLab:{...caps.testLab,offlineJsonPreview:false},
    }),
  }));
  await page.route('**/api/v1/test-lab/preview',route=>{post++;return route.abort();});
  await page.goto('/');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-backend-synthetic summary').click();
  await page.getByRole('button',{name:'Preview Backend Public Synthetic Sample'}).click();
  await expect(page.locator('.guided-backend-synthetic [role="alert"]')).toContainText('Authorized Backend');
  await expect(page.getByLabel('Approved synthetic sample result')).toHaveCount(0);
  expect(post).toBe(0);
});

test('backend denies preview even when advertised, so UI does not claim successful synthesis',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/test-lab/preview',route=>route.fulfill({
    status:403,contentType:'application/json',body:JSON.stringify({error:'TESTLAB_PREVIEW_NOT_AUTHORIZED'}),
  }));
  await page.goto('/');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-backend-synthetic summary').click();
  await page.getByRole('button',{name:'Preview Backend Public Synthetic Sample'}).click();
  await expect(page.locator('.guided-backend-synthetic [role="alert"]')).toBeVisible();
  await expect(page.getByLabel('Approved synthetic sample result')).toHaveCount(0);
});

test('forged sensor ready flag or extra source data is never rendered',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(caps),
  }));
  await page.route('**/api/v1/test-lab/preview',route=>route.fulfill({
    status:200,contentType:'application/json',
    body:JSON.stringify({...preview,targetSensorVerified:true,customerSecret:'never-display-this'}),
  }));
  await page.goto('/');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-backend-synthetic summary').click();
  await page.getByRole('button',{name:'Preview Backend Public Synthetic Sample'}).click();
  await expect(page.locator('.guided-backend-synthetic [role="alert"]')).toBeVisible();
  await expect(page.locator('.guided-backend-synthetic')).not.toContainText('never-display-this');
  await expect(page.getByLabel('Approved synthetic sample result')).toHaveCount(0);
});
