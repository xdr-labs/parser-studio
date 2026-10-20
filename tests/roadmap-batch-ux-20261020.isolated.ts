import {test,expect,type Page,type TestInfo} from '@playwright/test';

function batch(count:number){
  return Array.from({length:count},(_,index)=>JSON.stringify({
    event_type:'connection',srcip:'192.0.2.10',action:'allow',sequence:index+1,
  })).join('\n');
}

async function analyzeBatch(page:Page,info:TestInfo,raw:string,count:number){
  const requests:string[]=[];
  page.on('request',request=>{
    if(new URL(request.url()).pathname==='/api/v1/multipass/preview-batch')
      requests.push(request.postData()??'');
  });
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(raw);
  // Observe the real UI transitions without delaying or replacing engine traffic.
  const progressHistory=await page.evaluateHandle(()=>{
    const states:Array<{phase:string;detail:string;indeterminate:boolean;cancelAvailable:boolean}>=[];
    const observer=new MutationObserver(()=>{
      const panel=document.querySelector('[aria-label="Log analysis progress"]');
      if(!panel)return;
      const bar=panel.querySelector('progress');
      const state={phase:panel.querySelector('[role="status"]')?.textContent??'',
        detail:panel.querySelector('p')?.textContent??'',
        indeterminate:Boolean(bar&&!bar.hasAttribute('value')&&!bar.hasAttribute('aria-valuenow')),
        cancelAvailable:panel.querySelector('button')?.textContent==='Cancel analysis'};
      if(JSON.stringify(states[states.length-1])!==JSON.stringify(state))states.push(state);
    });
    observer.observe(document.body,{childList:true,subtree:true,characterData:true,attributes:true});
    return {states,stop:()=>observer.disconnect()};
  });
  const response=page.waitForResponse(reply=>
    new URL(reply.url()).pathname==='/api/v1/multipass/preview-batch'&&reply.request().method()==='POST');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const actual=await response;
  expect(actual.ok()).toBe(true);
  const body=await actual.json();
  expect(body.eventCount).toBe(count);
  expect(body.sourceBytes).toBe(Buffer.byteLength(raw));
  expect(body.events).toHaveLength(count);
  expect(body.events[count-1].preview.fields.sequence).toBe(count);
  expect(requests).toHaveLength(1);
  expect(JSON.parse(requests[0]!).raw).toBe(raw);
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText(`${count} of ${count} log events parsed completely`,{timeout:30000});
  await expect(page.getByLabel('Log analysis progress')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeEnabled();
  await expect(source).toHaveValue(raw);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
  const progress=await progressHistory.evaluate(history=>{history.stop();return history.states;});
  await progressHistory.dispose();
  expect(progress.length).toBeGreaterThan(0);
  for(const state of progress){
    expect(['Analyzing source','Checking analysis results']).toContain(state.phase);
    expect(state.detail).toMatch(new RegExp(`^${Buffer.byteLength(raw).toLocaleString('en-US')} UTF-8 bytes · [0-9]+s elapsed$`));
    expect(state.indeterminate).toBe(true);
    expect(state.cancelAvailable).toBe(true);
  }
  await page.screenshot({path:info.outputPath(`batch-${count}-complete.png`),fullPage:true});
  await info.attach(`batch-${count}-evidence`,{contentType:'application/json',body:JSON.stringify({
    sourceBytes:Buffer.byteLength(raw),requestCount:requests.length,eventCount:body.eventCount,
    finalEvent:body.events[count-1],sourcePreserved:await source.inputValue()===raw,progress,
  },null,2)});
}

test('a novice analyzes 100 events in one unchanged source request',async({page},info)=>{
  test.setTimeout(90000);
  await analyzeBatch(page,info,batch(100),100);
});

test('a novice analyzes all 400 events including the final event without truncation',async({page},info)=>{
  test.setTimeout(120000);
  await analyzeBatch(page,info,batch(400),400);
});

function deferred<T>(){
  let resolve!:(value:T)=>void;
  let reject!:(reason:unknown)=>void;
  const promise=new Promise<T>((accept,fail)=>{resolve=accept;reject=fail;});
  return {promise,resolve,reject};
}

async function holdCompletedPreview(page:Page){
  const ready=deferred<{status:string;sourceSha256:string}>();
  const release=deferred<void>();
  const delivered=deferred<void>();
  await page.route('**/api/v1/multipass/preview',async route=>{
    try{
      // This race-only case delays delivery of a real completed engine result.
      // The separate 100/400 cases never intercept or delay engine traffic.
      const response=await route.fetch();
      expect(response.ok()).toBe(true);
      const value=await response.json();
      ready.resolve({status:value.status,sourceSha256:value.sourceSha256});
      await release.promise;
      await route.fulfill({response});
      delivered.resolve();
    }catch(error){ready.reject(error);delivered.reject(error);}
  },{times:1});
  return {ready:ready.promise,release:()=>release.resolve(),delivered:delivered.promise};
}

test('cancel and source edits reject delayed successful results before a fresh analysis',async({page},info)=>{
  test.setTimeout(120000);
  const original='Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="192.0.2.1",request_status="blocked",ip_client="203.0.113.210",protocol="HTTPS",date_time="2026-10-15T00:14:27+09:00",dest_port="443",dest_ip="198.51.100.25",uri="/api/login"';
  const fresh=JSON.stringify({event_type:'fresh_after_cancel',srcip:'192.0.2.44',action:'allow',sequence:1});
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  const analyze=page.getByRole('button',{name:'Analyze Logs',exact:true});
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await source.fill(original);

  const canceled=await holdCompletedPreview(page);
  await analyze.click();
  const canceledResult=await canceled.ready;
  expect(canceledResult.status).toBe('SOURCE_PARSED');
  await expect(page.getByLabel('Log analysis progress')).toBeVisible();
  await page.getByRole('button',{name:'Cancel analysis',exact:true}).click();
  await expect(page.getByText('Analysis canceled. Your logs are unchanged. You can edit them or analyze again.',{exact:true})).toBeVisible();
  await expect(source).toHaveValue(original);
  canceled.release();await canceled.delivered;
  await expect(analyze).toBeEnabled();
  await expect(page.getByLabel('Beginner analysis summary')).toHaveCount(0);
  await expect(page.getByLabel('Review Fields stage')).toHaveCount(0);
  await expect(review).toBeDisabled();

  const edited=await holdCompletedPreview(page);
  await analyze.click();
  const editedResult=await edited.ready;
  expect(editedResult.status).toBe('SOURCE_PARSED');
  await source.fill(fresh);
  await expect(page.getByText('The logs or parser settings changed, so the previous analysis was canceled. Analyze the current logs again.',{exact:true})).toBeVisible();
  edited.release();await edited.delivered;
  await expect(page.getByLabel('Log analysis progress')).toHaveCount(0);
  await expect(source).toHaveValue(fresh);
  await expect(page.getByLabel('Beginner analysis summary')).toHaveCount(0);
  await expect(review).toBeDisabled();

  await analyze.click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 1 log event parsed completely',{timeout:30000});
  await expect(source).toHaveValue(fresh);
  await expect(review).toBeEnabled();
  await review.click();
  const fields=page.getByLabel('Review Fields stage');
  await expect(fields).toBeVisible({timeout:30000});
  const inspector=fields.getByLabel('Browser-only event inspector');
  await expect(inspector).toContainText('fresh_after_cancel');
  await expect(inspector).toContainText('"sequence": 1');
  await expect(inspector).not.toContainText('bigip-waf01');
  await page.screenshot({path:info.outputPath('cancel-edit-fresh-review.png'),fullPage:true});
  await info.attach('cancel-edit-race-evidence',{contentType:'application/json',body:JSON.stringify({
    controlledResponseDelivery:true,engineResponses:[canceledResult,editedResult],
    canceledSourcePreserved:true,editedSourcePreserved:true,freshAnalysisReachedFieldReview:true,
  },null,2)});
});
