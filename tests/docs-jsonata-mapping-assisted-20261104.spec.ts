import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

const raw=readFileSync(resolve('tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8');
test('Juniper ChatGPT JSONata review protects a user-edited mapping and blocks unsafe proposals',async({page})=>{
  test.skip((process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1'||process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1'),'Pinned real authoring backend required.');
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
  const target=map.locator('article.normalization-map-row[data-source-path="'+source+'"] input[aria-label^="Stellar field "]');
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
  const sourceRow=reviewed.locator('label.jsonata-assist-row').filter({hasText:'source-address → srcip'});
  await expect(sourceRow).toContainText('BLOCKED');
  await expect(sourceRow).toContainText('Human mapping');
  await expect(sourceRow.locator('input[type="checkbox"]')).toBeDisabled();
  await expect(reviewed).toContainText('BLOCKED');
  await expect(reviewed.locator('input[type="checkbox"]:disabled')).toHaveCount(3);
  await expect(target).toHaveValue('temporary_vendor_source_ip');
  await expect(reviewed.locator('label.jsonata-assist-row').filter({hasText:'nat-source-address'})).toContainText('BLOCKED');
  await expect(reviewed.locator('label.jsonata-assist-row').filter({hasText:'$number'})).toContainText('BLOCKED');
  await expect(assistant.getByRole('button',{name:/Apply .* Reviewed Mapping/})).toHaveCount(0);
  // No AI proposal was selected or applied: the user-edited destination survives review.
  await expect(target).toHaveValue('temporary_vendor_source_ip');
  await expect(map.getByLabel('Field changes only')).toContainText('temporary_vendor_source_ip');
  await expect(map.getByLabel('Field changes only')).toContainText('10.0.0.1');
  expect(errors).toEqual([]);
  expect(external).toEqual([]);
});
