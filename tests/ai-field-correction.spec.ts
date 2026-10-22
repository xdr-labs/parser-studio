import {test,expect,type Page} from '@playwright/test';

const source=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
 '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
const holdout=[
 '{"action":"allow","src_ip":"192.0.2.10","dst_port":8443}',
 '{"action":"deny","src_ip":"192.0.2.11","dst_port":2222}',
].join('\n');
type Recipe={projectId:string;stages:Array<{
 op:string;source?:string;target?:string;data_type?:string;group?:string;
}>};

async function prepareManualSource(page:Page):Promise<Recipe>{
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('alert')
    .filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  const button=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(button).toBeEnabled({timeout:20000});
  await button.click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toBeVisible();
  const text=await prompt.inputValue();
  expect(text).toContain(source);
  const begin='----- BEGIN VALIDATED BASELINE RECIPE -----\n';
  const end='\n----- END VALIDATED BASELINE RECIPE -----';
  const l=text.indexOf(begin),r=text.indexOf(end,l+begin.length);
  expect(l).toBeGreaterThanOrEqual(0);
  expect(r).toBeGreaterThan(l);
  return JSON.parse(text.slice(l+begin.length,r)) as Recipe;
}

test('source field correction requires independent ChatGPT test and explicit approval before any DRAFT change',async({page})=>{
  const origin=await prepareManualSource(page);
  const correction=structuredClone(origin);
  const mapping=correction.stages.find(stage=>stage.op==='map_field'&&stage.source==='src_ip');
  expect(mapping).toBeTruthy();
  const previous=mapping!.target!;
  mapping!.target='custom.source_address';
  const cast=correction.stages.find(stage=>stage.op==='cast_type'&&stage.target===previous);
  if(cast)cast.target='custom.source_address';
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(correction));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  const accepted=page.getByLabel('ChatGPT result ready for testing');
  await expect(accepted).toContainText('ChatGPT result accepted for testing');
  const apply=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
  await expect(apply).toBeDisabled();
  await page.getByLabel('Additional ChatGPT test logs').fill(holdout);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  const result=page.getByLabel('ChatGPT fix test result');
  await expect(result).toBeVisible({timeout:20000});
  await expect(result).toContainText('Original logs still pass: YES');
  await expect(result).toContainText('Additional logs tested: YES');
  await expect(result).toContainText('Overall test: PASS');
  await expect(apply).toBeDisabled();
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await expect(apply).toBeEnabled();
  await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue(source);
});

test('unsupported ChatGPT split operator fails closed without changing parsed source or creating a DRAFT',async({page})=>{
  const baseline=await prepareManualSource(page);
  const invalid=structuredClone(baseline);
  invalid.stages.splice(2,0,{op:'split_field',source:'src_ip',target:'custom.extracted'});
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(invalid));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByRole('status'))
    .toContainText('ChatGPT result rejected');
  await expect(page.getByLabel('ChatGPT result ready for testing')).toHaveCount(0);
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
  await expect(page.getByLabel('ChatGPT local sample logs')).toHaveValue(source);
});
