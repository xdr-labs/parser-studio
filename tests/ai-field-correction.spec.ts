import {test,expect} from '@playwright/test';

// The retired after-generation repair panel is not reinstated. The active
// single-analysis path lets the user correct only a reviewed source mapping,
// and retains the other independently accepted Stellar 7.0 destinations.
const source=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
 '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

test('reviewed source field correction preserves independent action and port mappings',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  const review=page.getByLabel('Review Fields stage');
  await expect(review).toBeVisible();
  await expect(review.getByLabel('Browser-only event inspector')).toContainText('198.51.100.10');
  await review.getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toContainText('Stellar field dictionary 7.0.xs');
  const sourceInput=map.locator('input[aria-label^="Source field "]');
  const index=await sourceInput.evaluateAll((nodes)=>
    nodes.findIndex(el=>(el as HTMLInputElement).value==='src_ip'));
  expect(index).toBeGreaterThanOrEqual(0);
  const target=map.getByLabel('Stellar field '+index,{exact:true});
  await expect(target).toHaveValue('srcip');
  const other=await map.locator('input[aria-label^="Stellar field "]').evaluateAll((nodes)=>
    nodes.map(node=>(node as HTMLInputElement).value));
  expect(other).toContain('dstport');
  expect(other).toContain('action');
  await target.fill('custom.source_address');
  await expect(target).toHaveValue('custom.source_address');
  const retained=await map.locator('input[aria-label^="Stellar field "]').evaluateAll((nodes)=>
    nodes.map(node=>(node as HTMLInputElement).value));
  expect(retained).toContain('dstport');
  expect(retained).toContain('action');
  await target.fill('srcip');
  await expect(map.getByLabel('Field mapping checks'))
    .toContainText('All current field mappings passed the sample checks');
  await map.getByRole('button',{name:'Back to Review Fields'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Back to Logs'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});

test('untrusted ChatGPT mapping response is rejected without modifying source or creating files',async({page})=>{
  const outbound:string[]=[];
  page.on('request',request=>{
    if(request.method()==='POST' && request.url().includes('/parser-pairs/generate'))
      outbound.push(request.url());
  });
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  await expect(page.getByLabel('ChatGPT copyable prompt')).toBeVisible();
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify({
    contract:'parser-studio.recipe.v0.2',
    stages:[{op:'execute_code',source:'src_ip',target:'srcip'}],
  }));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByRole('region',{name:'ChatGPT result review'}))
    .toContainText('ChatGPT result rejected: UNTRUSTED_RECIPE');
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
  await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue(source);
  expect(outbound).toEqual([]);
});
