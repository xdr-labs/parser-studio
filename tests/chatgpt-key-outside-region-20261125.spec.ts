import {test,expect} from './support/downloadSink';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {readFile} from 'node:fs/promises';

// ChatGPT Assisted on a log the Auto Parser does not read: pipe-separated key=value behind a time stamp. The server
// analysis reads the two addresses and reports the rest as unparsed regions, so the keys `sip` and `dip` end a region
// and their values lie outside every region. Auto Parser -> Fix with ChatGPT -> replies written by this test (ChatGPT is
// not called) -> test with different examples -> approval -> parser files. Lossy replies are refused; the lossless
// reply, which keeps each key as literal text before a capture of the same name, is applied (it was refused before
// 2026-11-25). With CHATGPT_KEY_OUT set, the downloaded Ruby parser and the lines to run it on are written there for
// the Ruby 2.4.9 runner. SYNTHETIC lines.
const L=(time:string,sensor:string,sip:string,dip:string,sport:number,dport:number,proto:string,alert:string)=>
  `2026-11-25T00:${time}Z|sensor=${sensor}|sip=${sip}|dip=${dip}|sport=${sport}|dport=${dport}|proto=${proto}|alert=${alert}`;
const SAMPLE=[L('10:10','ids-4','10.80.8.8','203.0.113.80',12345,53,'UDP','DNS tunneling'),
  L('10:11','ids-4','10.80.8.9','203.0.113.81',12346,443,'TCP','TLS anomaly')].join('\n');
const HOLDOUT=[L('12:00','ids-7','10.80.9.1','203.0.113.90',40001,22,'TCP','SSH scan'),
  L('12:01','ids-8','10.80.9.2','203.0.113.91',40002,3389,'TCP','RDP brute force')].join('\n');
const RUNTIME=[L('16:00','ids-5','2001:db8::8','2001:db8::80',12347,8443,'TCP','정책 위반'),
  L('16:01','core-ids','10.80.8.11','203.0.113.83',12348,123,'UDP','NTP amplification a=b')];
// Anchored, and no two repeats can read the same text, so the Regex can be exported for the Ruby 2.4.9 target.
const PATTERN=String.raw`^(?<ts>[^|]+)\|sensor=(?<sensor>[^|]+)\|sip=(?<sip>[^|]+)\|dip=(?<dip>[^|]+)\|sport=(?<sport>\d+)\|dport=(?<dport>\d+)\|proto=(?<proto>[^|]+)\|alert=(?<alert>.+)$`;
function reply(pattern:string,sip='sip'){
  return JSON.stringify({contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
    projectId:'draft-demo_firewall',sourceFormat:'regex',bodyFormat:'regex',
    sample:{sha256:createHash('sha256').update(SAMPLE).digest('hex'),events:2},
    stages:[
      {op:'split_event',boundary:'single-line'},
      {op:'parse_regex',pattern},
      {op:'map_field',source:sip,target:'srcip',data_type:'ip',group:'top_fields'},
      {op:'cast_type',target:'srcip',data_type:'ip'},
      {op:'map_field',source:'dip',target:'dstip',data_type:'ip',group:'top_fields'},
      {op:'cast_type',target:'dstip',data_type:'ip'},
      {op:'classify',defaultIndex:'syslog',rules:[]},
      {op:'fallback_unparsed',mode:'retain_unparsed'},
    ],nativeVerified:false,targetVerified:false});
}

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' || process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the exact-pinned loopback authoring backend and the Multi-Pass preview service.'
);

test('ChatGPT Assisted reads a pipe-separated key=value log: the prompt names what failed, lossy replies are refused, the lossless reply is applied',async({page})=>{
  test.setTimeout(240_000);
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(SAMPLE);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('0 of 2 log events structurally parsed',{timeout:30_000});
  await expect(page.getByRole('button',{name:'Review Fields',exact:true}).last()).toBeDisabled();
  const problem=page.getByLabel('Parse problem inspector');
  await problem.getByRole('button',{name:'Fix with ChatGPT'}).click();

  // The prompt: the exact original events, what failed, the text that was not read and the reply contract.
  const prompt=page.getByLabel('Generated ChatGPT repair prompt');
  for(const line of SAMPLE.split('\n'))await expect(prompt).toContainText(line);
  await expect(prompt).toContainText('NO_SUPPORTED_GRAMMAR');
  await expect(prompt).toContainText('Unparsed source regions:');
  await expect(prompt).toContainText('2026-11-25T00:10:10Z|sensor=ids-4|sip=');
  await expect(prompt).toContainText('Return only one ParserRecipe v0.2 JSON object');
  await expect(prompt).toContainText('a key name directly before = and a capture spelled exactly like it may stay literal pattern text');
  await expect(prompt).toContainText('only when its pattern is anchored (^...$) and its backtracking is statically bounded');
  await expect(prompt).toContainText(createHash('sha256').update(SAMPLE).digest('hex'));

  const ai=page.getByLabel('AI result verification');
  const status=ai.getByRole('status');
  async function test_(pattern:string,sip='sip'){
    await ai.getByLabel('ChatGPT JSON result').fill(reply(pattern,sip));
    await ai.getByLabel('Additional test logs').fill(HOLDOUT);
    const attest=ai.getByLabel('Confirm different test examples');
    if(!await attest.isChecked())await attest.check();
    await ai.getByRole('button',{name:'Test Proposed Fix'}).click();
  }
  // Lossy: the "ids-" prefix of the sensor name read as pattern text (the value loses it).
  await test_(PATTERN.replace('sensor=(?<sensor>[^|]+)','sensor=ids-(?<sensor>[^|]+)'));
  await expect(status.filter({hasText:'Fix not applied'})).toContainText('previously unparsed source regions outside the final parser output');
  await expect(ai.getByRole('button',{name:'Apply Verified Fix'})).toHaveCount(0);
  // Lossy: the key sip kept as literal text before a capture of another name (the key is lost).
  await test_(PATTERN.replace('sip=(?<sip>','sip=(?<source>'),'source');
  await expect(status.filter({hasText:/Fix not applied|ChatGPT result rejected/u})).toBeVisible();
  await expect(ai.getByRole('button',{name:'Apply Verified Fix'})).toHaveCount(0);
  // Lossy: the alert text and the destination port matched but not captured.
  for(const lossy of [PATTERN.replace('alert=(?<alert>.+)$','alert=.+$'),PATTERN.replace('dport=(?<dport>\\d+)','dport=\\d+')]){
    await test_(lossy);
    await expect(status.filter({hasText:'ChatGPT result rejected'})).toContainText('UNCAPTURED_SOURCE_TEXT');
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
  if(process.env.CHATGPT_KEY_OUT){
    const dir=process.env.CHATGPT_KEY_OUT+'/pipe_kv';
    mkdirSync(dir,{recursive:true});
    writeFileSync(dir+'/parser.rb',ruby);
    writeFileSync(dir+'/runtime.lines',[SAMPLE,HOLDOUT,...RUNTIME].join('\n')+'\n');
  }
});
