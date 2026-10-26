import {test,expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

const valid=[
 {name:'Fortinet KV',vendor:'Fortinet',product:'FortiGate',raw:'date=2026-10-23 time=12:10:10 action=deny srcip=192.0.2.10 dstip=198.51.100.10 srcport=50000 dstport=443'},
 {name:'CEF security event',vendor:'ArcSight',product:'CEF Security',raw:'CEF:0|Example|IPS|1.0|1001|Blocked Request|8|src=192.0.2.11 dst=198.51.100.11 spt=50001 dpt=443 act=blocked'},
 {name:'LEEF authentication',vendor:'IBM',product:'QRadar',raw:'LEEF:2.0|IBM|QRadar|7.5|login|^|src=192.0.2.12^dst=198.51.100.12^usrName=user^cat=Authentication^sev=5'},
 {name:'Suricata JSON',vendor:'OISF',product:'Suricata',raw:JSON.stringify({timestamp:'2026-10-23T12:00:01Z',event_type:'alert',src_ip:'192.0.2.13',dest_ip:'198.51.100.13',alert:{signature_id:30001,severity:2}})},
 {name:'Defender XDR JSON',vendor:'Microsoft',product:'Defender XDR',raw:JSON.stringify({Timestamp:'2026-10-23T12:00:02Z',DeviceName:'HOST-01',ActionType:'AntivirusDetection',RemoteIP:'192.0.2.14',FileName:'test.exe'})},
 {name:'CloudTrail JSON',vendor:'Amazon',product:'CloudTrail',raw:JSON.stringify({eventTime:'2026-10-23T12:00:03Z',eventName:'CreateUser',eventSource:'iam.amazonaws.com',sourceIPAddress:'192.0.2.15',userIdentity:{userName:'alice'}})},
 {name:'Korean JSON values',vendor:'Example Security',product:'Korean EDR',raw:JSON.stringify({timestamp:'2026-10-23T12:00:04Z',action:'deny',username:'김민수',hostname:'서울-보안장비',src_ip:'192.0.2.16'})},
] as const;
const PREFIX='----- BEGIN VALIDATED BASELINE RECIPE -----\n';
const SUFFIX='\n----- END VALIDATED BASELINE RECIPE -----';

for(const item of valid){
 test('controlled baseline-model answer and actual UI compiler: '+item.name,async({page})=>{
  const failedHTTP:string[]=[],scriptErrors:string[]=[];let genPosts=0;
  page.on('pageerror',e=>scriptErrors.push(e.message));
  page.on('response',r=>{if(r.url().includes('/api/')&&r.status()>=500)failedHTTP.push(r.url())});
  page.on('request',r=>{if(r.url().includes('/parser-pairs/generate')&&r.method()==='POST')genPosts++;});
  await page.goto('/');await page.getByLabel('Auto Parser raw logs').fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('parsed completely',{timeout:20000});
  await page.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
  await page.getByLabel('Parser manufacturer').fill(item.vendor);
  await page.getByLabel('Parser product',{exact:true}).fill(item.product);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toBeVisible({timeout:20000});
  const text=await prompt.inputValue();
  const l=text.indexOf(PREFIX),r=text.indexOf(SUFFIX,l+PREFIX.length);
  expect(l,'No validated baseline for source').toBeGreaterThanOrEqual(0);
  expect(r).toBeGreaterThan(l);
  const recipe=JSON.parse(text.slice(l+PREFIX.length,r));
  expect(recipe.sample.sha256).toBe(createHash('sha256').update(item.raw).digest('hex'));
  // Controlled answer is the exact baseline JSON, not a claim of live model accuracy.
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  const accepted=page.getByLabel('ChatGPT result ready for testing');
  await expect(accepted).toContainText('accepted for testing',{timeout:16000});
  const apply=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
  await expect(apply).toBeEnabled();
  await apply.click();
  const downloads=page.getByLabel('ChatGPT created parser files');
  await expect(downloads).toContainText('Parser files created successfully',{timeout:23000});
  await expect(downloads).toContainText('No different holdout examples were tested');
  await expect(downloads).not.toContainText('additional examples passed');
  const btn=downloads.getByRole('button',{name:/Download .*\.conf$/});
  const filePromise=page.waitForEvent('download');await btn.click();const file=await filePromise;
  const conf=await readFile(await file.path(),'utf8');
  expect(conf).toContain('port 6801');
  expect(conf).toContain('NOT INSTALLED');
  expect(genPosts).toBeGreaterThan(0);
  expect(scriptErrors).toEqual([]);expect(failedHTTP).toEqual([]);
  const result={name:item.name,mode:'CONTROLLED_BASELINE_RESPONSE',jsonValid:true,draftCompiled:true,confName:file.suggestedFilename(),sourceHashMatch:true,htmlClaimsHoldoutPassed:await downloads.innerText().then(s=>s.includes('additional examples passed')),javascriptErrors:scriptErrors};
  console.log('AI_RECIPE_MATRIX '+JSON.stringify(result));
 });
}

const csvSource='allow,198.51.100.10\ndeny,203.0.113.4';
const csvHoldout='allow,192.0.2.10\ndeny,192.0.2.11';
const recovery=()=>({
 contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
 projectId:'draft-demo_firewall',sourceFormat:'csv',bodyFormat:'csv',
 sample:{sha256:createHash('sha256').update(csvSource).digest('hex'),events:2},
 stages:[
  {op:'split_event',boundary:'single-line'},
  {op:'parse_csv',columns:['action','src_ip'],delimiter:','},
  {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
  {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
  {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
  {op:'classify',defaultIndex:'syslog',rules:[]},
  {op:'fallback_unparsed',mode:'retain_unparsed'},
 ],nativeVerified:false,targetVerified:false
});

test('controlled Full Recovery CSV candidate undergoes independent holdout and explicit approval',async({page})=>{
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill(csvSource);
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 await expect(page.getByLabel('ChatGPT copyable prompt')).toContainText('FULL_RECOVERY');
 await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recovery()));
 await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
 await expect(page.getByLabel('ChatGPT result ready for testing')).toContainText('accepted for testing');
 const apply=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
 await expect(apply).toBeDisabled();
 await page.getByLabel('Additional ChatGPT test logs').fill(csvHoldout);
 await page.getByLabel('Confirm test examples are different').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(page.getByLabel('ChatGPT fix test result')).toContainText('Overall test: PASS',{timeout:25000});
 await expect(apply).toBeDisabled();
 await page.getByLabel('Approve tested ChatGPT fix').check();
 await apply.click();
 await expect(page.getByLabel('ChatGPT created parser files')).toContainText('Parser files created successfully',{timeout:23000});
 console.log('AI_RECIPE_MATRIX '+JSON.stringify({name:'two-column CSV Full Recovery',mode:'CONTROLLED_RECOVERY_RECIPE',holdout:true,explicitApproval:true,draftCompiled:true}));
});

test('unsupported Windows XML accepts precise human REVIEW_REQUIRED diagnosis but never creates a parser',async({page})=>{
 const xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID></System></Event>';
 await page.goto('/?workspace=chatgpt');await page.getByLabel('ChatGPT local sample logs').fill(xml);
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 await expect(page.getByLabel('ChatGPT copyable prompt')).toContainText('FULL_RECOVERY');
 await page.getByLabel('ChatGPT result JSON').fill('REVIEW_REQUIRED: Windows Event XML is unsupported; export these same events as valid JSON without inventing field names or values.');
 await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
 await expect(page.getByRole('region',{name:'ChatGPT result review'})).toContainText('diagnosis, not a parser recipe');
 await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
 console.log('AI_RECIPE_MATRIX '+JSON.stringify({name:'Windows XML refusal',mode:'CONTROLLED_REVIEW_REQUIRED',safeRefusal:true,generated:false}));
});
