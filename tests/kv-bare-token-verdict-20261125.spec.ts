import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// key=value text with a bare token (`evt=flow_open fragmented client=...`) behind a Syslog header (owner decision
// of 2026-11-25; independent audit of e8d8d26, C-1 and C-2). The Auto Parser used to adopt a reading that keeps the
// whole body as one message, report "structurally parsed" and offer no ChatGPT route; one more pair at run time was
// then read in another shape. Now the sample is not reported as parsed, Fix with ChatGPT is offered with the exact
// events, and a reviewed rule (written by this test; ChatGPT is not called) gives a parser whose fields keep their
// names: a run-time line with one more pair is not parsed by the rule and keeps its complete original text.
// Chromium with the real backend and Multi-Pass service. SYNTHETIC lines.
const L=(n:number,evt:string,flag:string,client:string,server:string,verdict:string,extra='')=>
  `<134>Nov 25 09:10:0${n} gw-norrland quillfw: evt=${evt} ${flag} client=${client} server=${server} verdict=${verdict}${extra}`;
const SAMPLE=[L(1,'flow_open','fragmented','10.44.7.21','198.51.100.77','permit'),
  L(2,'flow_close','reassembled','10.44.7.22','198.51.100.78','deny')].join('\n');
const HOLDOUT=[L(3,'flow_open','queued','10.44.7.23','198.51.100.79','permit'),
  L(4,'flow_reset','dropped','10.44.7.24','198.51.100.80','deny')].join('\n');
const RUNTIME=[L(5,'flow_open','fragmented','2001:db8::21','2001:db8::77','permit'),
  L(6,'flow_open','fragmented','10.44.7.26','198.51.100.82','permit',' zone=dmz')];
const PATTERN=String.raw`^<(?<pri>\d+)>(?<month>[A-Z][a-z]{2}) (?<day>\d+) (?<time>\d\d:\d\d:\d\d) (?<host>[^ ]+) (?<app>[^:]+): evt=(?<evt>[^ ]+) (?<flag>[^ ]+) client=(?<client>[^ ]+) server=(?<server>[^ ]+) verdict=(?<verdict>[^ ]+)$`;
function reply(pattern:string){
  return JSON.stringify({contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
    sample:{sha256:createHash('sha256').update(SAMPLE).digest('hex'),events:2},
    stages:[
      {op:'split_event',boundary:'single-line'},
      {op:'parse_regex',pattern},
      {op:'map_field',source:'client',target:'srcip',data_type:'ip',group:'top_fields'},
      {op:'cast_type',target:'srcip',data_type:'ip'},
      {op:'map_field',source:'server',target:'dstip',data_type:'ip',group:'top_fields'},
      {op:'cast_type',target:'dstip',data_type:'ip'},
      {op:'classify',defaultIndex:'syslog',rules:[]},
      {op:'fallback_unparsed',mode:'retain_unparsed'},
    ],nativeVerified:false,targetVerified:false});
}

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

test('key=value text with a bare token is not reported as parsed; Fix with ChatGPT gives a parser with stable fields',async({page})=>{
  test.setTimeout(240_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(SAMPLE);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText('2 of 2 log events',{timeout:30_000});
  // Keeping the message is not parsing it: no "structurally parsed", no parser rule built, no way on without a rule.
  await expect(summary).not.toContainText('structurally parsed');
  await expect(page.getByText('built a parser rule')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true}).last()).toBeDisabled();

  const problem=page.getByLabel('Parse problem inspector');
  await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
  const prompt=page.getByLabel('Generated ChatGPT repair prompt');
  for(const line of SAMPLE.split('\n'))await expect(prompt).toContainText(line);
  await expect(prompt).toContainText('Return only one ParserRecipe v0.2 JSON object');
  await expect(prompt).toContainText(createHash('sha256').update(SAMPLE).digest('hex'));

  const ai=page.getByLabel('AI result verification');
  async function test_(pattern:string){
    await ai.getByLabel('ChatGPT JSON result').fill(reply(pattern));
    await ai.getByLabel('Additional test logs').fill(HOLDOUT);
    const attest=ai.getByLabel('Confirm different test examples');
    if(!await attest.isChecked())await attest.check();
    await ai.getByRole('button',{name:'Test Proposed Fix'}).click();
  }
  // Lossy: the bare token matched but not captured.
  await test_(PATTERN.replace(' (?<flag>[^ ]+) client=',' [^ ]+ client='));
  await expect(ai.getByRole('status').filter({hasText:/Fix not applied|ChatGPT result rejected/u})).toBeVisible();
  await expect(ai.getByRole('button',{name:'Apply Verified Fix'})).toHaveCount(0);

  await test_(PATTERN);
  await expect(ai).toContainText('Fix passed');
  await ai.getByLabel('Approve tested fix').check();
  await ai.getByRole('button',{name:'Apply Verified Fix'}).click();
  await expect(summary).toContainText('2 of 2 log events structurally parsed',{timeout:30_000});

  await page.getByRole('button',{name:'Review Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await page.getByText(/Run Final Test/).first().click();
  const download=page.getByText(/Download parser logic/).first();
  await expect(download).toBeVisible({timeout:60_000});
  const [file]=await Promise.all([page.waitForEvent('download'),download.click()]);
  const ruby=await readFile(await file.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.KV_BARE_OUT){
    const dir=process.env.KV_BARE_OUT+'/kv_bare';
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby);
    writeFileSync(dir+'/runtime.lines',[SAMPLE,HOLDOUT,...RUNTIME].join('\n')+'\n');
  }
});
