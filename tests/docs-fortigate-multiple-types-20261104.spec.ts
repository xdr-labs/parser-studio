import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
const root=resolve('tests/fixtures/docs-practice-20261104');
test('published FortiGate traffic + web filter + IPS samples in one reviewed parser draft',async({page})=>{
  test.skip((process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1'||process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1'),'Pinned backend required');
  test.setTimeout(80000);
  const traffic=readFileSync(resolve(root,'04-fortigate-traffic.log'),'utf8').trimEnd();
  const threat=readFileSync(resolve(root,'04-fortigate-threat.log'),'utf8').trimEnd();
  const raw=traffic+'\n'+threat;
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Fortinet');
  await page.getByLabel('Parser product',{exact:true}).fill('FortiGate');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:25000});
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  const fields=await map.locator('.normalization-map-row').evaluateAll(nodes=>nodes.map(row=>({
    source:(row.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value,
    target:(row.querySelector('input[aria-label^="Stellar field "]') as HTMLInputElement|null)?.value,
    official:row.classList.contains('verified')
  })));
  const selected=(source:string)=>fields.find(x=>x.source===source);
  for(const [source,target] of [
    ['srcip','srcip'],['dstip','dstip'],['srcport','srcport'],
    ['dstport','dstport'],['proto','proto'],['policyid','fw_policy_id'],
  ])expect(selected(source)).toMatchObject({target,official:true});
  // Multi-type FortiOS contains traffic action=close as well as enforcement
  // dispositions. One session-end verb invalidates unconditional action mapping.
  expect(selected('action')).toMatchObject({target:'action',official:false});
  for(const source of ['type','eventtype','duration','direction','hostname']){
    if(selected(source))expect(selected(source)?.official,source+' must stay vendor-specific').toBe(false);
  }
  const summary=await map.getByLabel('Field mapping summary').innerText();
  expect(summary.split("Fields found")[1]?.trim().startsWith("66")).toBe(true);
  expect(summary.split("Left out of output")[1]?.trim().startsWith("0")).toBe(true);
  const notices=await map.getByLabel('Field mapping checks').innerText();
  console.log('DOC_MULTI_TYPE '+JSON.stringify({summary,notices,official:fields.filter(x=>x.official)}));
  await expect(map.getByRole('button',{name:'Create Parser',exact:true})).toBeEnabled();
  await map.getByRole('button',{name:'Create Parser',exact:true}).click();
  const response=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const res=await response;
  expect(res.status()).toBe(200);
  const pair=await res.json() as {manifest:{status:string},files:unknown[]};
  expect(pair.manifest.status).toBe('DRAFT');
  expect(pair.files).toHaveLength(2);
});