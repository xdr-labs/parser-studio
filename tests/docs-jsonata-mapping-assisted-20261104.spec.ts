import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

const raw=readFileSync(resolve('tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8');
test('published Juniper logs → ChatGPT JSONata mapping review → DRAFT Ruby and conf',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1','Pinned real authoring backend required.');
  test.setTimeout(90000);
  const errors:string[]=[];
  const external:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{
    if(request.method()==='POST'&&!/^https?:\/\/(127\.0\.0\.1|localhost)(:|\/)/.test(request.url()))
      external.push(request.url());
  });
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Juniper');
  await page.getByLabel('Parser product',{exact:true}).fill('SRX');
  await page.getByLabel('Auto Parser raw logs').fill(raw.trimEnd());
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const next=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(next).toBeEnabled({timeout:25000});
  await next.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  const source='syslog_sd.element_1.params.source-address';
  const rows=map.locator('article.normalization-map-row');
  const position=await rows.evaluateAll((nodes,src)=>nodes.findIndex(node=>
    (node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value===src),source);
  expect(position).toBeGreaterThan(-1);
  const target=rows.nth(position).locator('input[aria-label^="Stellar field "]');
  await expect(target).toHaveValue('srcip');
  await target.fill('temporary_vendor_source_ip');
  const assistant=map.getByLabel('ChatGPT JSONata field mapping');
  await assistant.getByRole('button',{name:'Improve mappings with ChatGPT JSONata'}).click();
  await assistant.getByRole('button',{name:'Prepare Mapping Prompt'}).click();
  const prompt=assistant.getByLabel('ChatGPT JSONata mapping prompt');
  await expect(prompt).toBeVisible();
  const promptText=await prompt.inputValue();
  expect(promptText).toContain('syslog_sd.element_1.params');
  expect(promptText).not.toContain('10.0.0.1');
  const sha=promptText.match(/"sha256":\s*"([a-f0-9]{64})"/)?.[1];
  expect(sha).toMatch(/^[a-f0-9]{64}$/);
  await assistant.getByLabel('Paste ChatGPT JSONata mapping response').fill(JSON.stringify({
    contract:'parser-studio.mapping-jsonata.v0.1',sample:{sha256:sha,events:2},
    mappings:[
      {expression:'$.syslog_sd.element_1.params.`source-address`',target:'srcip'},
      {expression:'syslog_sd.element_1.params.`nat-source-address`',target:'dstip'},
      {expression:'$number(syslog_sd.element_1.params.`source-port`)*1000',target:'srcport'},
    ],
  }));
  await assistant.getByRole('button',{name:'Check JSONata Mappings'}).click();
  const reviewed=assistant.getByLabel('Reviewed ChatGPT JSONata mappings');
  await expect(reviewed).toContainText('READY');
  await expect(reviewed).toContainText('BLOCKED');
  await expect(reviewed.locator('input[type="checkbox"]:disabled')).toHaveCount(2);
  await expect(assistant.getByRole('button',{name:'Apply 1 Reviewed Mapping'})).toBeDisabled();
  await assistant.getByLabel('I reviewed the selected JSONata mappings').check();
  await assistant.getByRole('button',{name:'Apply 1 Reviewed Mapping'}).click();
  const changed=await map.locator('article.normalization-map-row').evaluateAll((nodes,src)=>nodes
    .map(node=>({source:(node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value,
      target:(node.querySelector('input[aria-label^="Stellar field "]') as HTMLInputElement|null)?.value,
      className:node.className})).find(row=>row.source===src),source);
  expect(changed).toMatchObject({source,target:'srcip'});
  expect(changed?.className).toContain('verified');
  await expect(map.getByLabel('Field changes only')).toContainText('srcip');
  await map.getByRole('button',{name:'Create Parser',exact:true}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const response=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const compiled=await response;
  expect(compiled.status()).toBe(200);
  const pair=await compiled.json() as {manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean},files:unknown[]};
  expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
  expect(pair.files).toHaveLength(2);
  expect(errors).toEqual([]);
  expect(external).toEqual([]);
});