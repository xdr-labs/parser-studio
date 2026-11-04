import {test,expect} from '@playwright/test';

test.skip(process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1'||
  process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Requires a pinned local authoring backend and explicit scoped DRAFT-only E2E.');

test('Issue #210 rejects source events exceeding the configured 8192-byte receiver limit',async({page})=>{
 test.setTimeout(60000);
 const failures:string[]=[];
 page.on('pageerror',e=>failures.push(e.message));
 await page.goto('/');
 await page.getByLabel('Parser manufacturer').fill('Synthetic');
 await page.getByLabel('Parser product',{exact:true}).fill('SizeGuard');
 await page.getByLabel('Auto Parser raw logs').fill(JSON.stringify({action:'deny',payload:'한'.repeat(2900)}));
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled({timeout:20000});
 await expect(page.getByText('Some events could not be understood safely.')).toBeVisible();
 expect(failures).toEqual([]);
});
test('Issue #210 requires explicit TCP LF LF framing for pretty-printed JSON events',async({page})=>{
 test.setTimeout(90000);
 const errors:string[]=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('/');
 await page.getByLabel('Parser manufacturer').fill('Synthetic');
 await page.getByLabel('Parser product',{exact:true}).fill('JsonFrame');
 const source=[{action:'deny',srcip:'192.0.2.1'},{
  action:'allow',srcip:'192.0.2.2'}].map(v=>JSON.stringify(v,null,2)).join('\n\n');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 const confirm=page.getByRole('button',{name:'Confirm TCP multiline JSON LF LF framing'});
 await expect(confirm).toBeVisible();
 await confirm.click();
 await expect(confirm).not.toBeVisible();
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled({timeout:25000});
 await review.click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
 expect(errors).toEqual([]);
});
test('Issue #210 ECS root timestamp remains reviewable through the JSONata UI and DRAFT backend',async({page})=>{
 test.setTimeout(90000);
 const jsErrors:string[]=[];
 page.on('pageerror',e=>jsErrors.push(e.message));
 await page.goto('/');
 await page.getByLabel('Parser manufacturer').fill('Elastic');
 await page.getByLabel('Parser product',{exact:true}).fill('ECS');
 const raw='{"@timestamp":"2026-11-04T12:00:00Z","action":"deny","source_ip":"192.0.2.1"}';
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const next=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(next).toBeEnabled({timeout:25000});
 await next.click();
 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
 const map=page.getByLabel('Map Fields stage');
 const rows=map.locator('article.normalization-map-row');
 const src='@timestamp';
 // A dictionary-backed recommendation is shown but remains intentionally
 // unapplied until the owner approves it or reviews it in the JSONata flow.
 await expect(map.getByRole('button',{name:'Apply official mapping @timestamp'})).toBeVisible();
 const assistant=map.getByLabel('ChatGPT JSONata field mapping');
 await assistant.getByRole('button',{name:'Improve mappings with ChatGPT JSONata'}).click();
 await assistant.getByRole('button',{name:'Prepare Mapping Prompt'}).click();
 const prompt=await assistant.getByLabel('ChatGPT JSONata mapping prompt').inputValue();
 expect(prompt).toContain('`@timestamp`');
 const sha=prompt.match(/"sha256":\s*"([a-f0-9]{64})"/)?.[1];
 expect(sha).toMatch(/^[a-f0-9]{64}$/);
 await assistant.getByLabel('Paste ChatGPT JSONata mapping response').fill(JSON.stringify({
  contract:'parser-studio.mapping-jsonata.v0.1',
  sample:{sha256:sha,events:1},
  mappings:[{expression:'`@timestamp`',target:'timestamp'}],
 }));
 await assistant.getByRole('button',{name:'Check JSONata Mappings'}).click();
 await expect(assistant.getByLabel('Reviewed ChatGPT JSONata mappings')).not.toContainText('BLOCKED');
 await assistant.getByLabel('I reviewed the selected JSONata mappings').check();
 const apply=assistant.getByRole('button',{name:/Apply 1 Reviewed Mapping/});
 await expect(apply).toBeEnabled();
 await apply.click();
 const reviewedRows=await rows.evaluateAll(nodes=>nodes.map(node=>({
  source:(node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value,
  target:(node.querySelector('input[aria-label^="Stellar field "]') as HTMLInputElement|null)?.value,
 })));
 expect(reviewedRows).toContainEqual({source:src,target:'timestamp'});
 await map.getByRole('button',{name:'Create Parser',exact:true}).click();
 const response=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&r.request().method()==='POST');
 await page.getByRole('button',{name:'Create Parser Files'}).click();
 expect((await response).status()).toBe(200);
 expect(jsErrors).toEqual([]);
});
