import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// Owner decision Q3-1 on the ChatGPT Assisted full-recovery path in Chromium: a log the Auto Parser cannot read ->
// prompt -> replies written by this test (ChatGPT is not called) -> result check -> test with different examples ->
// approval -> parser files. Deliberately wrong replies never reach parser files. The accepted reply maps one of the
// two columns; the other must still reach the parser output. With Q31_CHATGPT_OUT set, the downloaded Ruby parser
// and the lines to run it on are written there for the Ruby 2.4.9 runner. SYNTHETIC lines.
const SAMPLE='allow,198.51.100.10\ndeny,203.0.113.4';
const HOLDOUT='allow,192.0.2.10\ndeny,192.0.2.11';
const RUNTIME=['allow,2001:db8::7','deny,김민수-host'];
type Map=[source:string,target:string,type:'string'|'ip',group:'top_fields'|'vendor_fields'];
function reply(columns:string[],maps:Map[]){
  const stages:unknown[]=[{op:'split_event',boundary:'single-line'},{op:'parse_csv',columns,delimiter:','}];
  for(const [from,to,type,group] of maps){
    stages.push({op:'map_field',source:from,target:to,data_type:type,group});
    if(type!=='string')stages.push({op:'cast_type',target:to,data_type:type});
  }
  stages.push({op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'});
  return JSON.stringify({contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId:'draft-demo_firewall',sourceFormat:'csv',bodyFormat:'csv',
    sample:{sha256:createHash('sha256').update(SAMPLE).digest('hex'),events:2},
    stages,nativeVerified:false,targetVerified:false});
}

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' &&
  process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Requires the explicit exact-pinned or scoped loopback authoring backend.'
);

test('ChatGPT Assisted refuses wrong replies and keeps the column a reply leaves unmapped (Q3-1)',async({page})=>{
  test.setTimeout(120_000);
  await page.goto('/?workspace=chatgpt');
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
  await page.getByLabel('ChatGPT local sample logs').fill(SAMPLE);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toContainText('FULL_RECOVERY');
  for(const line of SAMPLE.split('\n'))await expect(prompt).toContainText(line);

  const result=page.getByLabel('ChatGPT result JSON');
  const ready=page.getByLabel('ChatGPT result ready for testing');
  const apply=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
  const testResult=page.getByLabel('ChatGPT fix test result');
  // Wrong replies: one column for two values, and a wrong official mapping (the action read as the source IP).
  for(const wrong of [reply(['action'],[['action','custom.action','string','top_fields']]),
    reply(['action','src_ip'],[['action','srcip','ip','top_fields']])]){
    await result.fill(wrong);
    await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
    await expect(page.getByRole('status').filter({hasText:/\S/}).first()).toBeVisible();
    if(await ready.count()){
      await page.getByLabel('Additional ChatGPT test logs').fill(HOLDOUT);
      const attest=page.getByLabel('Confirm test examples are different');
      if(!await attest.isChecked())await attest.check();
      await page.getByRole('button',{name:'Test Proposed Fix'}).click();
      await expect(testResult).toBeVisible();
      await expect(testResult).not.toContainText('Overall test: PASS');
    }
    await expect(apply).toBeDisabled();
  }

  // The accepted reply maps only the action column; src_ip stays unmapped and must still reach the output.
  await result.fill(reply(['action','src_ip'],[['action','custom.action','string','top_fields']]));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(ready).toContainText('ChatGPT result accepted for testing');
  await page.getByLabel('Additional ChatGPT test logs').fill(HOLDOUT);
  const attest=page.getByLabel('Confirm test examples are different');
  if(!await attest.isChecked())await attest.check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  await expect(testResult).toContainText('Overall test: PASS');
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await apply.click();
  const generated=page.getByLabel('ChatGPT created parser files');
  await expect(generated).toContainText('Parser files created successfully');
  const downloadPromise=page.waitForEvent('download');
  await generated.getByRole('button',{name:'Download customized_demo_firewall',exact:true}).click();
  const download=await downloadPromise;
  const ruby=await readFile(await download.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.Q31_CHATGPT_OUT){
    mkdirSync(process.env.Q31_CHATGPT_OUT,{recursive:true});
    writeFileSync(process.env.Q31_CHATGPT_OUT+'/parser.rb',ruby);
    writeFileSync(process.env.Q31_CHATGPT_OUT+'/runtime.lines',[SAMPLE,HOLDOUT,...RUNTIME].join('\n')+'\n');
  }
});
