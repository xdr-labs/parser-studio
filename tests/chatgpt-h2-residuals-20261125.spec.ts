import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// Final re-audit H-2 in Chromium with the real Multi-Pass backend and the real preview worker: Squid access lines
// whose unparsed regions span several tokens (" TCP_MISS/200 5120 GET "). Auto Parser -> Fix with ChatGPT -> replies
// written by this test (ChatGPT is not called) -> test with different examples -> approval -> parser files. Replies that
// read source text as literal pattern text are refused; the lossless reply that reads each region into several fields is
// applied. With H2_CHATGPT_OUT set, the downloaded Ruby parser and the lines to run it on are written there for the
// Ruby 2.4.9 runner. SYNTHETIC lines in the documented Squid native access.log layout.
const USER='김민수';
const SAMPLE='1763859723.123    245 192.0.2.51 TCP_MISS/200 5120 GET http://www.example.test/index.html - HIER_DIRECT/198.51.100.10 text/html\n'+
  '1763859724.456     12 192.0.2.52 TCP_DENIED/403 3900 CONNECT blocked.example.test:443 alice HIER_NONE/- text/html';
const HOLDOUT='1763859725.789     77 192.0.2.53 TCP_HIT/200 777 GET http://cdn.example.test/a.js - HIER_NONE/- application/javascript\n'+
  `1763859726.012      9 192.0.2.54 TCP_DENIED/407 3900 GET http://intranet.example.test/ ${USER} HIER_NONE/- text/html`;
const RUNTIME=['1763859727.345   1500 2001:db8::10 TCP_TUNNEL/200 88213 CONNECT mail.example.test:443 bob HIER_DIRECT/203.0.113.25 -',
  '1763859728.678      3 192.0.2.55 NONE_NONE/400 4012 POST http://upload.example.test/form carol HIER_NONE/- text/html'];
const PATTERN=String.raw`^(?<time>\d+\.\d{3}) +(?<elapsed>\d+) (?<client>\S+) (?<code>[A-Z_]+)/(?<status>\d{3}) (?<bytes>\d+) (?<method>[A-Z]+) (?<url>\S+) (?<user>\S+) (?<hierarchy>[A-Z_]+)/(?<peer>\S+) (?<type>\S+)$`;
function reply(pattern:string){
  return JSON.stringify({contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
    sample:{sha256:createHash('sha256').update(SAMPLE).digest('hex'),events:2},
    stages:[
      {op:'split_event',boundary:'single-line'},
      {op:'parse_regex',pattern},
      {op:'map_field',source:'client',target:'srcip',data_type:'ip',group:'top_fields'},
      {op:'cast_type',target:'srcip',data_type:'ip'},
      {op:'map_field',source:'url',target:'url',data_type:'string',group:'top_fields'},
      {op:'classify',defaultIndex:'syslog',rules:[]},
      {op:'fallback_unparsed',mode:'retain_unparsed'},
    ],nativeVerified:false,targetVerified:false});
}

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

test('Auto Parser applies a lossless ChatGPT recovery across multi-token residual regions and refuses lossy ones (H-2)',async({page})=>{
  test.setTimeout(240_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(SAMPLE);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const problem=page.getByLabel('Parse problem inspector');
  await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();
  const ai=page.getByLabel('AI result verification');
  const status=ai.getByRole('status');
  async function test_(pattern:string){
    await ai.getByLabel('ChatGPT JSON result').fill(reply(pattern));
    await ai.getByLabel('Additional test logs').fill(HOLDOUT);
    const attest=ai.getByLabel('Confirm different test examples');
    if(!await attest.isChecked())await attest.check();
    await ai.getByRole('button',{name:'Test Proposed Fix'}).click();
  }
  // Lossy replies: the HIER_ prefix, the TCP_ prefix and the decimal point of the time read as literal pattern text
  // (independent audit A-1: a decimal point is part of the value unless an enclosing capture keeps it).
  for(const lossy of [PATTERN.replace(' (?<hierarchy>[A-Z_]+)/',' HIER_(?<hierarchy>[A-Z_]+)/'),
    PATTERN.replace('(?<time>\\d+\\.\\d{3})','(?<time>\\d+)\\.(?<time_ms>\\d{3})'),
    PATTERN.replace('(?<code>[A-Z_]+)/(?<status>\\d{3})','TCP_(?<code>[A-Z_]+)/(?<status>\\d{3})')]){
    await test_(lossy);
    await expect(status.filter({hasText:'Fix not applied'})).toContainText('previously unparsed source regions outside the final parser output');
    await expect(ai.getByRole('button',{name:'Apply Verified Fix'})).toHaveCount(0);
  }
  await test_(PATTERN);
  await expect(ai).toContainText('Fix passed: full parser recovery');
  await ai.getByLabel('Approve tested fix').check();
  await ai.getByRole('button',{name:'Apply Verified Fix'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2 log events structurally parsed');

  await page.getByRole('button',{name:'Review Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).last().click();
  await page.getByRole('button',{name:'Create Parser',exact:true}).last().click();
  await page.getByText(/Run Final Test/).first().click();
  const download=page.getByText(/Download parser logic/).first();
  await expect(download).toBeVisible({timeout:60_000});
  const [file]=await Promise.all([page.waitForEvent('download'),download.click()]);
  const ruby=await readFile(await file.path(),'utf8');
  expect(ruby.length).toBeGreaterThan(1000);
  if(process.env.H2_CHATGPT_OUT){
    mkdirSync(process.env.H2_CHATGPT_OUT,{recursive:true});
    writeFileSync(process.env.H2_CHATGPT_OUT+'/parser.rb',ruby);
    writeFileSync(process.env.H2_CHATGPT_OUT+'/runtime.lines',[SAMPLE,HOLDOUT,...RUNTIME].join('\n')+'\n');
  }
});
