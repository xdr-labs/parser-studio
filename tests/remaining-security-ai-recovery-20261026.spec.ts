import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';

const origin='https://app.parser.xdr.ooo';
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
type RuleCase={
 id:string; vendor:string; product:string; raw:string; hold:[string,string];
 format:'regex'|'csv'; pattern?:string; delimiter?:string;
 columns:Array<[string,'string'|'ip'|'integer']>;
 expected:string[];
};
test.skip(process.env.PARSER_STUDIO_PUBLIC_NOVICE_CROSS_E2E!=='1',
 'Explicit operator-only public Chromium and native test, no CI network dependency.');
const cases:RuleCase[]=[
{
 id:'ModSecurity WAF denied request',vendor:'Trustwave',product:'ModSecurity',
 raw:'[Mon Oct 19 04:12:20.001 2026] [client 192.0.2.3] ModSecurity: Access denied with code 403 (phase 2). [id "942100"] [msg "SQL Injection Attack Detected"]',
 hold:[
 '[Mon Oct 19 04:12:25.001 2026] [client 192.0.2.15] ModSecurity: Access denied with code 406 (phase 2). [id "942110"] [msg "Suspicious Protocol"]',
 '[Tue Oct 20 08:10:02.800 2026] [client 192.0.2.18] ModSecurity: Access denied with code 403 (phase 1). [id "942150"] [msg "Request Anomaly"]'
 ],
 format:'regex',
 pattern:'^\\[[^\\]]+\\] \\[client (?<srcip>[0-9.]+)\\] ModSecurity: Access denied with code (?<status>\\d{3}) \\(phase (?<phase>\\d+)\\)\\. \\[id "(?<ruleid>[^"]+)"\\] \\[msg "(?<message>[^"]+)"\\]$',
 columns:[['srcip','ip'],['status','integer'],['phase','integer'],['ruleid','string'],['message','string']],
 expected:['192.0.2.3','942100','SQL Injection Attack Detected']
},
{
 id:'Cisco ASA connection 302013',vendor:'Cisco',product:'ASA',
 raw:'<166>Oct 19 08:23:58 cisco-fw %ASA-6-302013: Built outbound TCP connection 991 for outside:198.51.100.7/443 to inside:192.0.2.16/54321',
 hold:[
 '<166>Oct 19 08:24:08 cisco-fw %ASA-6-302013: Built outbound TCP connection 998 for outside:198.51.100.15/8443 (198.51.100.15/8443) to inside:192.0.2.44/51322 (192.0.2.44/51322)',
 '<166>Oct 20 09:01:01 cisco-fw %ASA-6-302013: Built outbound TCP connection 1001 for outside:198.51.100.30/22 to inside:192.0.2.66/52222'
 ],
 format:'regex',
 pattern:'^<\\d+>[A-Z][a-z]{2} \\d+ [\\d:]+ \\S+ %ASA-\\d+-302013: Built \\w+ TCP connection (?<conn>\\d+) for outside:(?<src>[0-9.]+)/(?<spt>\\d+)(?: \\([^)]+\\))? to inside:(?<dst>[0-9.]+)/(?<dpt>\\d+)(?: \\([^)]+\\))?$',
 columns:[['conn','integer'],['src','ip'],['spt','integer'],['dst','ip'],['dpt','integer']],
 expected:['198.51.100.7','192.0.2.16']
},
{
 id:'WatchGuard Firebox firewall',vendor:'WatchGuard',product:'Firebox',
 raw:'<134>Oct 19 08:23:58 watchguard-fw firewall: deny 192.0.2.12 198.51.100.7 tcp 54234 443 policy=ProxyAction action=deny',
 hold:[
 '<134>Oct 19 09:24:58 watchguard-fw firewall: allow 192.0.2.21 198.51.100.20 udp 50001 53 policy=DNSAction action=allow',
 '<134>Oct 20 09:26:58 watchguard-fw firewall: deny 192.0.2.22 198.51.100.21 tcp 54002 22 policy=Block action=deny'
 ],
 format:'regex',
 pattern:'^<\\d+>[A-Z][a-z]{2} \\d+ [\\d:]+ \\S+ firewall: (?<decision>\\w+) (?<srcip>\\S+) (?<dstip>\\S+) (?<proto>\\w+) (?<srcport>\\d+) (?<dstport>\\d+) policy=(?<policy>\\S+) action=(?<action>\\S+)$',
 columns:[['decision','string'],['srcip','ip'],['dstip','ip'],['proto','string'],['srcport','integer'],['dstport','integer'],['policy','string'],['action','string']],
 expected:['192.0.2.12','198.51.100.7','ProxyAction','deny']
},
{
 id:'Snort diverse alert layouts',vendor:'Cisco',product:'Snort IDS',
 raw:'<134>Oct 19 09:44:01 snort01 snort[555]: [1:2024218:3] Test possible C2 beacon [Classification: Malware Command and Control] [Priority: 1] {TCP} 192.0.2.10:5055 -> 198.51.100.20:443',
 hold:[
 '10/19-08:24:05.173300 [**] [1:2010935:3] DEMO TEST IDS MALWARE [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.0.2.11:51511 -> 198.51.100.3:443',
 '10/20-08:24:06.173300 [**] [1:2010936:2] "Example detection" [**] [Classification: Attempted User Privilege Gain] [Priority: 2] [AppID: HTTP] {UDP} 192.0.2.12:50123 -> 198.51.100.4:80'
 ],
 format:'regex',
 pattern:'^.*?\\[(?<sid>\\d+:\\d+:\\d+)\\] "?(?<message>.*?)"?(?: \\[\\*\\*\\])? \\[Classification: (?<cls>[^\\]]+)\\] \\[Priority: (?<pri>\\d+)\\](?: \\[AppID: [^\\]]+\\])? \\{(?<proto>\\w+)\\} (?<src>\\S+) -> (?<dst>\\S+)$',
 columns:[['sid','string'],['message','string'],['cls','string'],['pri','integer'],['proto','string'],['src','string'],['dst','string']],
 expected:['1:2024218:3','Test possible C2 beacon','192.0.2.10:5055']
},
{
 id:'CSV quoted field with neutral columns',vendor:'Generic',product:'Security CSV',
 raw:'2026-10-19T09:15:22Z,192.0.2.10,"deny,malware",443',
 hold:[
 '2026-10-19T09:15:23Z,192.0.2.20,"allow,web",8443',
 '2026-10-20T09:15:25Z,192.0.2.21,"deny,phishing",22'
 ],
 format:'csv',delimiter:',',
 columns:[['column_1','string'],['column_2','string'],['column_3','string'],['column_4','string']],
 expected:['192.0.2.10','deny,malware','443']
}
];

function recipe(c:RuleCase,prompt:string){
 const m=prompt.match(/"projectId":"(draft-[a-z][a-z0-9_]+)","sourceHash":"([a-f0-9]{64})","sourceCount":1/);
 expect(m?.[2]).toBe(sha(c.raw));
 const parsing=c.format==='regex'?{op:'parse_regex',pattern:c.pattern!}:
   {op:'parse_csv',columns:c.columns.map(([name])=>name),delimiter:c.delimiter!};
 const stages:Array<Record<string,unknown>>=[{op:'split_event',boundary:'single-line'},parsing];
 for(const [name,type] of c.columns){
  stages.push({op:'map_field',source:name,target:name,data_type:type,group:'vendor_fields'});
  if(type!=='string')stages.push({op:'cast_type',target:name,data_type:type});
 }
 stages.push({op:'classify',defaultIndex:'syslog',rules:[]},{op:'fallback_unparsed',mode:'retain_unparsed'});
 return {contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',
  compilerMode:'REVIEW_ONLY',projectId:m![1],sourceFormat:c.format,bodyFormat:c.format,
  sample:{sha256:sha(c.raw),events:1},stages,nativeVerified:false,targetVerified:false};
}
function flatten(v:unknown,a:string[]=[]):string[]{
 if(v===null||v===undefined)return a;
 if(Array.isArray(v)){for(const z of v)flatten(z,a);return a;}
 if(typeof v==='object'){for(const z of Object.values(v))flatten(z,a);return a;}
 a.push(String(v));return a;
}
function nativeRuby(file:string,logs:string[]){
 const runner='/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby';
 const program="require 'json';k=Class.new;k.class_eval(File.read(ARGV[0]),ARGV[0]);p=k.new;out=[];JSON.parse(STDIN.read).each{|raw|p.parse(raw){|t,e|out<<e}};STDOUT.write(JSON.generate(out))";
 const run=spawnSync(runner,['-e',program,file],{
  input:JSON.stringify(logs),encoding:'utf8',timeout:20000,maxBuffer:1024*1024,
  shell:false,env:{PATH:'/usr/bin:/bin',HOME:'/tmp',LANG:'C.UTF-8'}
 });
 expect(run.status,run.stderr).toBe(0);
 const events:unknown[]=JSON.parse(run.stdout);
 return events;
}
const assertGrounded=(c:RuleCase)=>{
 expect(sha(c.raw)).not.toBe(sha(c.hold[0]));
 expect(sha(c.raw)).not.toBe(sha(c.hold[1]));
 expect(sha(c.hold[0])).not.toBe(sha(c.hold[1]));
 if(c.format==='regex'){
  expect(c.pattern!.length,'bounded regex length').toBeLessThanOrEqual(256);
  const r=new RegExp(c.pattern!);
  for(const sample of [c.raw,...c.hold]){
   expect(r.test(sample),'grounded source grammar '+c.id).toBe(true);
  }
 }
};

for(const c of cases){
 test('real novice ChatGPT recovery with 2 source-disjoint holdouts: '+c.id,async({page})=>{
  assertGrounded(c);
  const pageErrors:string[]=[],httpFailures:number[]=[],thirdParty:string[]=[];
  page.on('pageerror',e=>pageErrors.push(e.message));
  page.on('response',r=>{if(r.url().includes('/api/')&&r.status()>=500)httpFailures.push(r.status());});
  page.on('request',r=>{try{const url=new URL(r.url());if(/^https?:$/.test(url.protocol)&&url.origin!==origin)thirdParty.push(url.origin)}catch{}});
  await page.goto(origin+'/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(c.raw);
  const response=page.waitForResponse(r=>r.request().method()==='POST'&&/\/multipass\/preview/.test(new URL(r.url()).pathname));
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  expect((await response).status()).toBe(200);
  await expect(input).toHaveValue(c.raw);
  await expect(page.getByLabel('Parse problem inspector')).toBeVisible();
  const improve=page.getByLabel('Parse problem inspector').getByRole('button',{name:/Fix with ChatGPT|Review with ChatGPT/});
  await expect(improve).toBeVisible();
  await improve.click();
  const fixPrompt=page.getByLabel('Generated ChatGPT repair prompt');
  await expect(fixPrompt).toBeVisible();
  await expect(fixPrompt).toContainText(c.raw);
  await page.goto(origin+'/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(c.raw);
  await page.getByLabel('ChatGPT solution vendor').fill(c.vendor);
  await page.getByLabel('ChatGPT solution product').fill(c.product);
  await page.getByLabel('ChatGPT desired fields').fill('Preserve observed lexical values. Never assert vendor-certified semantics from this fixture.');
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  expect(prompt).toContain(c.raw);
  expect(prompt).toContain(sha(c.raw));
  const responseRecipe=recipe(c,prompt);
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(responseRecipe));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toContainText('accepted for testing',{timeout:15000});
  await page.getByLabel('Additional ChatGPT test logs').fill(c.hold.join('\n'));
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  const report=page.getByLabel('ChatGPT fix test result');
  await expect(report).toBeVisible({timeout:25000});
  const reportText=await report.innerText();
  console.log('SEC_REPAIR_UI '+JSON.stringify({id:c.id,originalSha:sha(c.raw),holdHashes:c.hold.map(sha),tested:true,
   result:reportText.slice(0,400),patternLength:c.pattern?.length??null}));
  if(c.format==='csv'){
   // The source-only neutral CSV rule would remove two existing provisional
   // browser mappings; acceptance must not silently discard accepted values.
   await expect(report).toContainText('Overall test: FAILED');
   await expect(page.getByRole('button',{name:'Apply Fix & Create Parser Files'})).toBeDisabled();
   await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
   const retry=page.getByRole('button',{name:'Copy Improved Prompt · Attempt 2 of 3'});
   await expect(retry).toBeVisible();
   await retry.click();
   const improved=await page.getByLabel('ChatGPT copyable prompt').inputValue();
   expect(improved).toContain('HOLDOUT_REGRESSION');
   expect(improved).toContain('removedFields');
   expect(improved).toContain(c.raw);
   expect(pageErrors).toEqual([]);expect(httpFailures).toEqual([]);expect(thirdParty).toEqual([]);
   console.log('CSV_FAIL_CLOSED '+JSON.stringify({id:c.id,sourceSha:sha(c.raw),
     evidence:'previous-fields-protected; revised prompt preserved',generated:false}));
   return;
  }
  await expect(report).toContainText('Original logs still pass: YES');
  await expect(report).toContainText('Additional logs tested: YES');
  await expect(report).toContainText('Overall test: PASS');
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
  const generated=page.getByLabel('ChatGPT created parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:25000});
  const files:Array<{name:string;path:string;size:number;hash:string}>=[];
  for(const name of [/Download .*\.conf$/,/^Download customized_[A-Za-z0-9_]+$/]){
   const button=generated.getByRole('button',{name}).first();
   await expect(button).toBeVisible();
   const downloadPromise=page.waitForEvent('download',{timeout:12000});
   await button.click();
   const download=await downloadPromise;
   const local=await download.path();
   const content=await readFile(local);
   expect(content.length).toBeGreaterThan(200);
   files.push({name:download.suggestedFilename(),path:local,size:content.length,hash:sha(content.toString('utf8'))});
  }
  const conf=files.find(x=>x.name.endsWith('.conf'));
  const ruby=files.find(x=>!x.name.endsWith('.conf'));
  expect(conf).toBeDefined();expect(ruby).toBeDefined();
  expect(await readFile(conf!.path,'utf8')).toContain('invert true');
  const events=nativeRuby(ruby!.path,[c.raw,...c.hold]);
  expect(events.length,'native callbacks for original+two holdouts').toBe(3);
  for(const e of events){
   expect(e).toBeTruthy();
   expect((e as Record<string,unknown>).parser_err_msg).toBeUndefined();
  }
  const scalars=flatten(events[0]);
  for(const expected of c.expected)expect(scalars).toContain(expected);
  if(c.format==='regex'){
   const negative=c.id.startsWith('ModSecurity')?c.raw.replace('Access denied','Access permitted')
     :c.id.startsWith('Cisco ASA')?c.raw.replace('302013','302014')
     :c.id.startsWith('WatchGuard')?c.raw.replace('firewall:','unknown_event:')
     :c.raw.replace('[Classification:','[EventCategory:');
   expect(negative).not.toBe(c.raw);
   expect(new RegExp(c.pattern!).test(negative),'unsupported variant must not be silently accepted').toBe(false);
   const rejected=nativeRuby(ruby!.path,[negative]);
   expect(rejected.every(event=>Boolean((event as {parser_err_msg?:string}).parser_err_msg)),
     'unmatched native variant must fail closed').toBe(true);
   console.log('SEC_NATIVE_FAIL_CLOSED '+JSON.stringify({id:c.id,negativeSha:sha(negative),parsedSuccess:0}));
  }
  if(c.format==='regex'){
   const regexp=new RegExp(c.pattern!);
   for(let i=0;i<3;i++){
    const m=regexp.exec([c.raw,...c.hold][i]);
    expect(m).not.toBeNull();
    const actual=flatten(events[i]);
    for(const value of Object.values(m!.groups||{})){
     expect(actual,'native original source capture: '+c.id).toContain(String(value));
    }
   }
  }
  expect(pageErrors).toEqual([]);expect(httpFailures).toEqual([]);expect(thirdParty).toEqual([]);
  console.log('SEC_NATIVE_PASS '+JSON.stringify({id:c.id,sourceSha:sha(c.raw),
   nativeCallbacks:events.length,files:files.map(({name,size,hash})=>({name,size,hash})),
   extractedScalars:scalars.length,expectedVerified:c.expected.length,independentVendorSources:0,
   externalModelCompletions:0}));
 });
}
