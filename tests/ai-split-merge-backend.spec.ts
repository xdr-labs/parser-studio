import {test,expect} from '@playwright/test';

const source=[
 '{"action":"allow:http","src_ip":"198.51.100.10","dst_port":443}',
 '{"action":"deny:ssh","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

// A single bounded split/merge can be reviewed separately. The user removed
// after-generation repair and parser-building-steps UIs; two invented combined
// operations cannot silently bypass the reviewed, deterministic recipe gate.
test('combined AI split and merge cannot alter parser without independent reviewed qualification',async({page})=>{
  const forbidden:string[]=[];
  page.on('request',request=>{
    if(request.method()==='POST' && (
      request.url().includes('/parser-pairs/generate') ||
      request.url().includes('/recipe/v0.2/generate')
    ))forbidden.push(request.url());
  });
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  const begin='----- BEGIN VALIDATED BASELINE RECIPE -----\n';
  const end='\n----- END VALIDATED BASELINE RECIPE -----';
  const first=prompt.indexOf(begin),last=prompt.indexOf(end,first+begin.length);
  expect(first,'a source-matched baseline recipe is available').toBeGreaterThanOrEqual(0);
  expect(last).toBeGreaterThan(first);
  const recipe=JSON.parse(prompt.slice(first+begin.length,last));
  const classifyAt=recipe.stages.findIndex((stage:{op:string})=>stage.op==='classify');
  expect(classifyAt).toBeGreaterThan(0);
  recipe.stages.splice(classifyAt,0,
    {op:'split_field',source:'action',delimiter:':',targets:['custom.action_kind','custom.action_detail']},
    {op:'merge_fields',sources:['custom.action_kind','custom.action_detail'],delimiter:'/',target:'custom.action_joined'});
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  // Two syntactically valid operations may be accepted as a REVIEW_ONLY
  // proposal. This does NOT mean either one has passed runtime or holdout
  // qualification, and no parser generation can be enabled at this stage.
  const review=page.getByRole('region',{name:'ChatGPT result review'});
  await expect(review).toContainText('ChatGPT result accepted for testing');
  const generate=review.getByRole('button',{name:'Apply Fix & Create Parser Files'});
  await expect(generate).toBeDisabled();
  await page.getByLabel('Additional ChatGPT test logs').fill([
    '{"action":"allow:https","src_ip":"192.0.2.10","dst_port":8443}',
    '{"action":"deny:rdp","src_ip":"192.0.2.11","dst_port":2222}',
  ].join('\n'));
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  await expect(review).toContainText('The proposed grammar cannot be translated into a supported parser:');
  await expect(generate).toBeDisabled();
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
  await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue(source);
  expect(forbidden).toEqual([]);
});
