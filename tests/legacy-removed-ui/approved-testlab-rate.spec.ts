import {test,expect,type Page} from '@playwright/test';

const runId='test_run_'+'a'.repeat(32);
const base={
  runId,state:'RUNNING',sentCount:3,nextSequence:3,
  replayMode:'single',sampleFamilyCount:1,ratePerSecond:1,
  maxEvents:100,leaseExpiresAt:'2026-10-13T00:01:00.000Z',
  lastSentAt:null,errorCode:null,parserLifecycleNotModified:true,
  realSensorVerified:false,runtimeParsingVerified:false,sensorIngestVerified:false,
};
async function ownedRun(page:Page,status:unknown=base){
  await page.route('**/api/v1/test-lab/sessions/status*',route=>{
    expect(route.request().method()).toBe('GET');
    expect(new URL(route.request().url()).searchParams.get('runId')).toBe(runId);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(status)});
  });
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill(
    '{"action":"allow","username":"CUSTOMER_SECRET","src_ip":"198.51.100.10"}');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-owner-testlab summary').first().click();
  await page.getByLabel('Existing Test Lab run ID').fill(runId);
  await page.getByRole('button',{name:'Look Up Test Lab Session by Run ID'}).click();
  await expect(page.getByLabel('Test Lab session status')).toContainText(runId);
}

test('nondeveloper changes only an existing approved synthetic run rate with separate opt-in',async({page})=>{
  let rateRequests=0,starts=0;
  await page.route('**/api/v1/test-lab/sessions/start',route=>{starts++;return route.abort();});
  await page.route('**/api/v1/test-lab/sessions/rate',route=>{
    rateRequests++;
    expect(route.request().method()).toBe('POST');
    const body=route.request().postDataJSON();
    expect(body).toEqual({runId,approvalId:'approved-rate-2026',ratePerSecond:0.2});
    expect(JSON.stringify(body)).not.toContain('CUSTOMER_SECRET');
    expect(JSON.stringify(body)).not.toContain('198.51.100.10');
    expect(JSON.stringify(body)).not.toContain('dpUrl');
    expect(JSON.stringify(body)).not.toContain('sensorIp');
    expect(JSON.stringify(body)).not.toContain('apiKey');
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify({...base,ratePerSecond:0.2})});
  });
  await ownedRun(page);
  expect(rateRequests+starts).toBe(0);
  const form=page.getByLabel('Approved Test Lab rate adjustment');
  await form.locator('summary').click();
  const apply=form.getByRole('button',{name:'Apply Separately Approved Rate'});
  await expect(apply).toBeDisabled();
  await form.getByLabel('New approved Test Lab rate').selectOption('0.2');
  await form.getByLabel('New Test Lab rate approval').fill('approved-rate-2026');
  await expect(apply).toBeDisabled();
  await form.getByLabel('Confirm separately approved Test Lab rate').check();
  await apply.click();
  const status=page.getByLabel('Test Lab session status');
  await expect(status).toContainText('Requested Rate 0.2/s');
  await expect(status).toContainText('3/100');
  await expect(status).toContainText(base.leaseExpiresAt);
  await expect(form.getByLabel('New Test Lab rate approval')).toHaveValue('');
  await expect(form.getByLabel('Confirm separately approved Test Lab rate')).not.toBeChecked();
  await expect(apply).toBeDisabled();
  expect(rateRequests).toBe(1);
  expect(starts).toBe(0);
  expect(await page.evaluate(()=>JSON.stringify(localStorage))).not.toContain('approved-rate-2026');
});

test('backend 403 denies rate updates without creating a new run or fabricated status',async({page})=>{
  let rates=0,starts=0;
  await page.route('**/api/v1/test-lab/sessions/start',route=>{starts++;return route.abort();});
  await page.route('**/api/v1/test-lab/sessions/rate',route=>{
    rates++;
    return route.fulfill({status:403,contentType:'application/json',
      body:JSON.stringify({error:'TESTLAB_RATE_CHANGE_DENIED',
        rawLog:'PRIVATE_CUSTOMER_SECRET'})});
  });
  await ownedRun(page);
  const form=page.getByLabel('Approved Test Lab rate adjustment');
  await form.locator('summary').click();
  await form.getByLabel('New approved Test Lab rate').selectOption('5');
  await form.getByLabel('New Test Lab rate approval').fill('approved-rate-2026');
  await form.getByLabel('Confirm separately approved Test Lab rate').check();
  await form.getByRole('button',{name:'Apply Separately Approved Rate'}).click();
  await expect(page.locator('.guided-owner-testlab [role="alert"]')).toContainText('did not authorize');
  await expect(page.getByLabel('Test Lab session status')).toContainText('Requested Rate 1/s');
  await expect(form.getByLabel('New Test Lab rate approval')).toHaveValue('');
  await expect(form.getByLabel('Confirm separately approved Test Lab rate')).not.toBeChecked();
  expect(await page.locator('.guided-owner-testlab').innerText()).not.toContain('PRIVATE_CUSTOMER_SECRET');
  expect(rates).toBe(1);
  expect(starts).toBe(0);
});

test('original-gap replay never shows rate-change action even when owned',async({page})=>{
  let rates=0;
  await page.route('**/api/v1/test-lab/sessions/rate',route=>{rates++;return route.abort();});
  await ownedRun(page,{...base,replayMode:'original-gaps'});
  await expect(page.getByLabel('Approved Test Lab rate adjustment')).toHaveCount(0);
  expect(rates).toBe(0);
});
