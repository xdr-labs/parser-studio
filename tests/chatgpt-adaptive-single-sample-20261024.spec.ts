import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const source='allow,198.51.100.10';
const recipe=()=>({
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',
  compilerMode:'REVIEW_ONLY',projectId:'draft-demo_firewall',
  sourceFormat:'csv',bodyFormat:'csv',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:1},
  stages:[
    {op:'split_event',boundary:'single-line'},
    {op:'parse_csv',columns:['action','src_ip'],delimiter:','},
    {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
    {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
    {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
    {op:'classify',defaultIndex:'syslog',rules:[]},
    {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
});
test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Run with exact-HEAD isolated real authoring backend and Multi-Pass.');

test('one security log → rejected first ChatGPT JSON → adaptive retry → source-only DRAFT native pair',async({page})=>{
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toContainText(source);
  await expect(prompt).toContainText('ParserRecipe v0.2');

  await page.getByLabel('ChatGPT result JSON').fill('{"contract":"incorrect"}');
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT adaptive repair')).toBeVisible();
  await page.getByRole('button',{name:'Copy Improved Prompt · Attempt 2 of 3'}).click();
  const improved=await prompt.inputValue();
  expect(improved).toContain('attempt 2 of 3');
  expect(improved).toContain('SCHEMA_REJECTED');
  expect(improved).toContain(source);
  expect(improved).toContain('UNTRUSTED_RECIPE');
  expect(improved).toContain('independentlyVerified":false');
  await expect(page.getByLabel('ChatGPT result JSON')).toHaveValue('');

  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe()));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toContainText('accepted for testing');
  await page.getByRole('button',{name:'Test Original Sample Only'}).click();
  const report=page.getByLabel('ChatGPT fix test result');
  await expect(report).toContainText('SAMPLE PASS (NOT GENERALIZED)');
  await expect(report).toContainText('Additional logs tested: NO');
  await expect(report).toContainText('Controlled value variation: PASS');
  await report.getByText('Review actual extracted fields before approval').click();
  await expect(report).toContainText('198.51.100.10');
  await expect(page.getByRole('button',{name:'Apply Fix & Create Parser Files'})).toBeDisabled();
  await page.getByLabel('Approve sample-only draft').check();
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  const generated=page.getByLabel('ChatGPT created parser files');
  await expect(generated).toContainText('Parser files created successfully');
  await expect(generated).toContainText('Generalization and Stellar Cyber target behavior remain NOT VERIFIED');
  const downloadPromise=page.waitForEvent('download');
  await generated.getByRole('button',{name:'Download customized_demo_firewall.conf'}).click();
  const file=await downloadPromise;
  const conf=await readFile(await file.path(),'utf8');
  expect(conf).toContain('6801');
  await expect(generated.getByRole('button',{name:'Download customized_demo_firewall',exact:true})).toBeVisible();
});
test('retry limit stops after third failed model response without changing parser',async({page})=>{
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(source);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  for(const nextAttempt of [2,3]){
    await page.getByLabel('ChatGPT result JSON').fill('{"contract":"incorrect"}');
    await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
    await page.getByRole('button',{name:'Copy Improved Prompt · Attempt '+nextAttempt+' of 3'}).click();
  }
  await page.getByLabel('ChatGPT result JSON').fill('{"contract":"incorrect"}');
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByText('Three attempts reached.',{exact:false})).toBeVisible();
  await expect(page.getByRole('button',{name:'Copy Improved Prompt · Attempt 4 of 3'})).toHaveCount(0);
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
});
