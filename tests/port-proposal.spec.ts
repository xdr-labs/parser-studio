import { test, expect } from '@playwright/test';

const suggestion={
  contract:'stellar-parser-listener-port-proposal.v0.1',
  recommendedPort:20000,source:'SUGGESTED',
  status:'INCOMPLETE_EVIDENCE',
  missingEvidence:['sensorBindings','localReservations'],
  occupiedPorts:[514,7501,20001],
  candidateOnly:true,deployableNow:false,
  verifiedIngestPort:false,sensorIngestPort:20000,needsFinalRecheck:true,
};

test('authorized backend port suggestion is explicitly opted into and never treated as deployment proof',async({page})=>{
  let reads=0,writes=0;
  await page.route('**/api/v1/stellar/legacy/port-proposal*',route=>{
    reads++;
    expect(route.request().method()).toBe('GET');
    expect(route.request().postData()).toBeNull();
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(suggestion)});
  });
  page.on('request',request=>{
    if(request.method()!=='GET' && request.url().includes('/api/v1/'))writes++;
  });
  await page.goto('/');
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  await expect(page.getByLabel('Receiving port')).toHaveValue('7501');
  expect(reads).toBe(0);
  await page.getByRole('button',{name:'Request Port Candidate'}).click();
  const result=page.getByLabel('Parser port proposal result');
  await expect(result).toContainText('20000');
  await expect(result).toContainText('INCOMPLETE_EVIDENCE');
  await expect(result).toContainText('not proven free');
  await expect(result).toContainText('sensorBindings');
  await expect(page.getByLabel('Receiving port')).toHaveValue('7501');
  await result.getByRole('button',{name:'Apply Candidate to Draft (recheck required)'}).click();
  await expect(page.getByLabel('Receiving port')).toHaveValue('20000');
  await expect(result).toHaveCount(0);
  expect(reads).toBe(1);
  expect(writes).toBe(0);
});

test('checking a manually edited parser port does not send credentials or switch the selected port',async({page})=>{
  let requested='';
  await page.route('**/api/v1/stellar/legacy/port-proposal*',route=>{
    requested=new URL(route.request().url()).search;
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
      ...suggestion,source:'USER_OVERRIDE',recommendedPort:22550,
      occupiedPorts:[514,7501,20001],sensorIngestPort:22550,
    })});
  });
  await page.goto('/');
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  await page.getByLabel('Receiving port').fill('22550');
  await page.getByRole('button',{name:'Review Entered Port'}).click();
  await expect(page.getByLabel('Parser port proposal result')).toContainText('User-entered Port');
  await expect(page.getByLabel('Parser port proposal result')).toContainText('not deployable');
  await expect(page.getByLabel('Receiving port')).toHaveValue('22550');
  expect(requested).toBe('?port=22550');
  await expect(page.getByRole('button',{name:/Apply Candidate to Draft Port/})).toHaveCount(0);
});

test('Syslog candidate and sensor/CONF receiving port use one value >= 6800',async({page})=>{
  let url='';
  await page.route('**/api/v1/stellar/legacy/port-proposal*',route=>{
    url=new URL(route.request().url()).search;
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify({...suggestion,recommendedPort:6800,sensorIngestPort:6800}),
    });
  });
  await page.goto('/');
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await page.getByRole('group',{name:'Guided format'}).getByRole('button',{name:'RFC5424'}).click();
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  const receiving=page.getByLabel('Receiving port');
  await expect(receiving).toHaveAttribute('min','6800');
  await receiving.fill('6799');
  await expect(page.getByText(/at least 6800/)).toBeVisible();
  await page.getByRole('button',{name:'Request Port Candidate'}).click();
  const result=page.getByLabel('Parser port proposal result');
  await expect(result).toContainText('6800');
  await expect(result).toContainText('sensor');
  expect(url).toBe('?format=syslog_rfc5424');
  await result.getByRole('button',{name:'Apply Candidate to Draft (recheck required)'}).click();
  await expect(receiving).toHaveValue('6800');
  await expect(page.getByText(/at least 6800/)).toHaveCount(0);
});

test('unconfigured backend shows a non-blocking warning, leaving manual receiver port editable',async({page})=>{
  let calls=0;
  await page.route('**/api/v1/stellar/legacy/port-proposal*',route=>{
    calls++;
    return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'LEGACY_NOT_CONFIGURED'})});
  });
  await page.goto('/');
  await page.getByRole('button',{name:/4\. Receive & Classify/}).click();
  await page.getByRole('button',{name:'Request Port Candidate'}).click();
  await expect(page.locator('.guided-port-proposal [role="alert"]')).toContainText('HTTP 503');
  await page.getByLabel('Receiving port').fill('22555');
  await expect(page.getByLabel('Receiving port')).toHaveValue('22555');
  expect(calls).toBe(1);
});
