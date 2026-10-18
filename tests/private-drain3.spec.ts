import {test,expect} from '@playwright/test';

const logs=[
  'ERROR LOGIN from 192.0.2.11 user PRIVATE_ALICE',
  'ERROR LOGIN from 192.0.2.12 user PRIVATE_BOB',
].join('\n');
const held='ERROR LOGIN from 192.0.2.15 user PRIVATE_CAROL';
const capability={
 contract:'parser-studio.drain3-capabilities.v0.1',
 available:true,requiresExplicitConfirmation:true,
 engine:'Drain3 0.9.11',sameOriginRawSourceTransfer:true,
 noPersistence:true,maxTrainingEvents:500,maxHoldoutEvents:500,
 nativeParserVerified:false,targetImportVerified:false,
 noExternalLlmCalls:true,
};
const result={
 contract:'parser-studio.drain3-reviewed-hints.v0.1',
 engine:'Drain3 0.9.11',sourceCount:2,accounted:2,
 holdoutCount:1,holdoutMatched:1,groupCount:1,
 groups:[{clusterId:'cluster-1',shape:'ERROR LOGIN <WORD> <VAR> USER <VAR>',
   trainingCount:2,trainingLineNumbers:[1,2],holdoutMatches:1,reviewOnly:true}],
 persisted:false,sourceValuesIncluded:false,nativeParserVerified:false,
 targetImportVerified:false,
};
test('P1 user explicitly probes auth-only availability then consents before private Drain3 raw POST',async({page})=>{
 let probes=0,posts=0;
 await page.route(/\/api\/v1\/parser-pairs\/patterns\/drain3(?:\/capabilities)?(?:\?.*)?$/,route=>{
   const req=route.request(),url=new URL(req.url());
   expect(url.origin).toBe(new URL(page.url()).origin);
   if(req.method()==='GET'){
     probes++;
     expect(url.pathname).toBe('/api/v1/parser-pairs/patterns/drain3/capabilities');
     expect(req.postData()).toBeNull();
     return route.fulfill({status:200,contentType:'application/json',
       body:JSON.stringify(capability)});
   }
   posts++;
   expect(url.pathname).toBe('/api/v1/parser-pairs/patterns/drain3');
   expect(req.method()).toBe('POST');
   const body=req.postDataJSON();
   expect(body.confirmed).toBe(true);
   expect(body.training).toEqual(logs.split('\n'));
   expect(body.holdout).toEqual([held]);
   expect(req.headers()).not.toHaveProperty('authorization');
   expect(req.postData()).not.toContain('apiKey');
   return route.fulfill({status:200,contentType:'application/json',
     body:JSON.stringify(result)});
 });
 await page.goto('/');
 await page.getByRole('button',{name:'Advanced'}).click();
 await expect(page.getByRole('button',{name:'Return to Beginner Mode'})).toBeVisible();
 await page.getByLabel('Auto Parser raw logs').fill(logs);
 const block=page.getByLabel('Private text grouping tool');
 await expect(block).toBeVisible();
 await block.locator('summary').click();
 await expect(block.getByRole('checkbox')).toHaveCount(0);
 expect(probes).toBe(0);expect(posts).toBe(0);
 await block.getByRole('button',{name:/Check whether private grouping is available/}).click();
 await expect(block.getByRole('checkbox')).toBeVisible();
 expect(probes).toBe(1);expect(posts).toBe(0);
 const action=block.getByRole('button',{name:'Group Similar Logs'});
 await expect(action).toBeDisabled();
 await block.getByLabel('Different example logs').fill(held);
 expect(posts).toBe(0);
 await block.getByRole('checkbox').check();
 await expect(action).toBeEnabled();
 await action.click();
 const report=page.getByLabel('Private text grouping results');
 await expect(report).toContainText('2/2 events checked');
 await expect(report).toContainText('1/1 different example');
 await expect(report).toContainText('grouping hint only');
 await expect(report.getByText('Drain3 0.9.11')).not.toBeVisible();
 for(const sensitive of ['PRIVATE_ALICE','PRIVATE_BOB','PRIVATE_CAROL','192.0.2.11'])
   expect(await report.innerText()).not.toContain(sensitive);
 expect(posts).toBe(1);
 await block.getByRole('checkbox').uncheck();
 await expect(report).toHaveCount(0);
 expect(posts).toBe(1);
});
test('P1 disabled private Drain3 never presents consent or posts a source; browser-only fallback remains',async({page})=>{
 let probes=0,posts=0;
 await page.route(/\/api\/v1\/parser-pairs\/patterns\/drain3(?:\/capabilities)?(?:\?.*)?$/,route=>{
   if(route.request().method()==='POST')posts++;
   else probes++;
   return route.fulfill({status:403,contentType:'application/json',
     body:JSON.stringify({error:'DRAIN3_DISABLED'})});
 });
 await page.goto('/');
 await page.getByRole('button',{name:'Advanced'}).click();
 await expect(page.getByRole('button',{name:'Return to Beginner Mode'})).toBeVisible();
 await page.getByLabel('Auto Parser raw logs').fill(logs);
 const block=page.getByLabel('Private text grouping tool');
 await expect(block).toBeVisible();
 await block.locator('summary').click();
 await block.getByRole('button',{name:/Check whether private grouping is available/}).click();
 await expect(block).toContainText('not available');
 await expect(block.getByRole('checkbox')).toHaveCount(0);
 await expect(block.getByRole('button',{name:'Group Similar Logs'}))
   .toHaveCount(0);
 const offline=page.getByLabel('Known log shape matcher');
 await offline.locator('summary').click();
 await expect(offline.getByRole('button',{name:'Group Similar Unknown Shapes'}))
   .toBeVisible();
 expect(probes).toBe(1);expect(posts).toBe(0);
});
