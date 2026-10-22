import {test,expect,type Page} from '@playwright/test';

const PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy';
const ASA='<166>Oct 15 2026 00:05:03 ASA-EDGE01 : %ASA-6-302013: Built outbound TCP connection 18745213 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)';
const BIGIP='Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="10.1.1.10",http_class_name="/Common/prod_https",web_application_name="/Common/Production_Web",policy_name="/Common/prod_policy",policy_apply_date="2026-10-01 11:20:00",violations="Attack signature detected,Illegal parameter",support_id="1234567890123456789",request_status="blocked",response_code="0",ip_client="203.0.113.210",route_domain="0",method="POST",protocol="HTTPS",query_string="",x_forwarded_for_header_value="203.0.113.210",sig_ids="200003475",sig_names="Apache Log4j JNDI Remote Code Execution",date_time="2026-10-15T00:14:27+09:00",dest_port="443",dest_ip="10.20.1.25",uri="/api/login",request="POST /api/login HTTP/1.1"';

async function analyze(page:Page,raw:string){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event parsed completely',{timeout:15_000});
  await expect(page.getByRole('button',{name:'Use extracted fields'})).toHaveCount(0);
  await expect(page.getByText('Fields extracted — parser rule needs review')).toHaveCount(0);
  await expect(page.getByText(/Some events could not be understood safely/)).toHaveCount(0);
}

async function openMappings(page:Page){
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:10_000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await expect(page.getByLabel('Adjust detected field mapping')).toHaveCount(0);
  await expect(page.getByText('Need to correct a field name or value type?')).toHaveCount(0);
  const map=page.getByRole('button',{name:'Map Fields',exact:true});
  await expect(map).toBeEnabled({timeout:10_000});
  await map.click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
}

test('common PAN-OS traffic syslog is parsed automatically and maps core fields',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Palo Alto Networks');
  await page.getByRole('textbox',{name:'Parser product',exact:true}).fill('PA Firewall');
  await page.getByRole('textbox',{name:'Parser product version',exact:true}).fill('11.1');
  await expect(page.getByLabel('Parser product identity'))
    .toContainText('customized_palo_alto_networks_pa_firewall');

  await page.getByLabel('Auto Parser raw logs').fill(PAN);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event parsed completely',{timeout:15_000});
  await openMappings(page);
  const editor=page.getByLabel('Field mapping editor');
  const expectMapping=async(source:string,target:string)=>{
    const inputs=editor.locator('input[aria-label^="Source field "]');
    const index=await inputs.evaluateAll((nodes,wanted)=>
      nodes.findIndex(node=>(node as HTMLInputElement).value===wanted),source);
    expect(index,'source field '+source+' should be visible').toBeGreaterThanOrEqual(0);
    await expect(editor.getByLabel('Stellar field '+index,{exact:true})).toHaveValue(target);
  };
  await expectMapping('parserstudio_source.generic.fields.src','srcip');
  await expectMapping('parserstudio_source.generic.fields.dst','dstip');
  await expectMapping('parserstudio_source.generic.fields.sport','srcport');
  await expectMapping('parserstudio_source.generic.fields.dport','dstport');
  await expectMapping('parserstudio_source.generic.fields.protocol','proto_name');
  await expectMapping('parserstudio_source.generic.fields.action','action');
});


test('entered manufacturer product and version control generated parser names and metadata',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Parser manufacturer').fill('Palo Alto Networks');
  await page.getByRole('textbox',{name:'Parser product',exact:true}).fill('PA Firewall');
  await page.getByRole('textbox',{name:'Parser product version',exact:true}).fill('11.1');
  await page.getByLabel('Auto Parser raw logs').fill(PAN);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event parsed completely',{timeout:15_000});
  await openMappings(page);
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  const response=page.waitForResponse(r=>
    r.url().endsWith('/api/v1/parser-pairs/generate')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const generated=await response;
  expect(generated.status()).toBe(200);
  const pair=await generated.json();
  const names=pair.files.map((file:{name:string})=>file.name).sort();
  expect(names).toEqual([
    'customized_palo_alto_networks_pa_firewall',
    'customized_palo_alto_networks_pa_firewall.conf',
  ]);
  const conf=pair.files.find((file:{name:string})=>file.name.endsWith('.conf')).content as string;
  expect(conf).toContain('# Vendor: Palo Alto Networks');
  expect(conf).toContain('# Product: PA Firewall');
  expect(conf).toContain('# Product version: 11.1');
  expect(conf).toContain('# Parser name: customized_palo_alto_networks_pa_firewall');
  expect(conf).toContain('tag customized_palo_alto_networks_pa_firewall');
  await expect(page.getByLabel('Generated parser files'))
    .toContainText('customized_palo_alto_networks_pa_firewall.conf');
});

test('year-bearing Cisco ASA wrapper is parsed before the ASA body',async({page})=>{
  await analyze(page,ASA);
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  const inspector=page.getByLabel('Browser-only event inspector');
  await expect(inspector).toContainText('"year": "2026"');
  await expect(inspector).toContainText('"connection_id": "18745213"');
  await expect(inspector).toContainText('"src_ip": "203.0.113.50"');
  await expect(inspector).toContainText('"dst_ip": "10.1.15.27"');
});

test('BIG-IP ASM KV is auto-promoted and nested leaf names map to Stellar',async({page})=>{
  await analyze(page,BIGIP);
  await openMappings(page);
  const editor=page.getByLabel('Field mapping editor');
  const expectMapping=async(source:string,target:string)=>{
    const inputs=editor.locator('input[aria-label^="Source field "]');
    const index=await inputs.evaluateAll((nodes,wanted)=>
      nodes.findIndex(node=>(node as HTMLInputElement).value===wanted),source);
    expect(index,'source field '+source+' should be visible').toBeGreaterThanOrEqual(0);
    await expect(editor.getByLabel('Stellar field '+index,{exact:true})).toHaveValue(target);
  };
  await expectMapping('parserstudio_source.generic.fields.ip_client','srcip');
  await expectMapping('parserstudio_source.generic.fields.dest_ip','dstip');
  await expectMapping('parserstudio_source.generic.fields.dest_port','dstport');
  await expectMapping('parserstudio_source.generic.fields.protocol','proto_name');
});


test('common EDR JSON gets automatic Stellar mappings instead of leaving every field vendor-only',async({page})=>{
  const raw=JSON.stringify({
    timestamp:'2026-10-15T00:07:33.425+09:00',
    eventType:'DetectionSummaryEvent',
    severity:80,
    severityName:'High',
    hostname:'WS-FINANCE-023',
    localIP:'10.30.5.23',
    userName:'CORP\\jsmith',
    processName:'powershell.exe',
    commandLine:'powershell.exe -NoProfile -EncodedCommand REDACTED',
    parentProcess:'WINWORD.EXE',
    sha256:'6f5902ac237024bdd0c176cb93063dc4',
    tactic:'Execution',technique:'PowerShell',techniqueId:'T1059.001',
    action:'Detection',
  });
  await analyze(page,raw);
  await openMappings(page);
  const editor=page.getByLabel('Field mapping editor');
  const expectMapping=async(source:string,target:string)=>{
    const inputs=editor.locator('input[aria-label^="Source field "]');
    const index=await inputs.evaluateAll((nodes,wanted)=>
      nodes.findIndex(node=>(node as HTMLInputElement).value===wanted),source);
    expect(index,'source field '+source+' should be visible').toBeGreaterThanOrEqual(0);
    await expect(editor.getByLabel('Stellar field '+index,{exact:true})).toHaveValue(target);
  };
  await expectMapping('timestamp','timestamp');
  await expectMapping('eventType','event_type');
  await expectMapping('severity','severity');
  await expectMapping('hostname','hostname');
  await expectMapping('localIP','hostip');
  await expectMapping('userName','username');
  await expectMapping('processName','process_name');
  await expectMapping('commandLine','command');
  await expectMapping('parentProcess','parent_proc_name');
  await expectMapping('sha256','sha256');
  await expectMapping('action','action');
});

test('single-line logs retain accurate event accounting without an obsolete multi-line tool',async({page})=>{
  const raw='date=2026-10-15 time=00:04:12 devname="FGT-EDGE01" action="blocked" srcip=192.0.2.10 dstip=198.51.100.20 dstport=443';
  await analyze(page,raw);
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toContainText('1 of 1 log event parsed completely');
  await expect(summary).not.toContainText('REVIEW REQUIRED');
  await expect(page.getByLabel('Multi-line event boundary tool')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Analyze Logs',exact:true})).toBeVisible();
});

test('ChatGPT Assisted keeps original user logs and provides warning instead of fake redaction example',async({page})=>{
  await page.goto('/');
  const nav=page.getByRole('complementary',{name:'Parser Studio navigation'});
  await expect(nav.locator('button.rail-link')).toHaveCount(2);
  await nav.getByRole('button',{name:'ChatGPT Assisted Parser',exact:true}).click();
  await expect(page.getByRole('main',{name:'ChatGPT Assisted Parser'})).toBeVisible();
  const original='action=deny src_ip=192.0.2.20 dst_ip=198.51.100.20 dst_port=443';
  await page.getByLabel('ChatGPT local sample logs').fill(original);
  await expect(page.getByLabel('ChatGPT redacted examples')).toHaveCount(0);
  await expect(page.getByRole('alert').filter({hasText:'The ChatGPT prompt includes your original log text'})).toBeVisible();
  const prepare=page.getByRole('button',{name:'Prepare ChatGPT Prompt'});
  await expect(prepare).toBeEnabled({timeout:10000});
  await prepare.click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');
  await expect(prompt).toBeVisible({timeout:20000});
  const source=await prompt.inputValue();
  expect(source).toContain(original);
  expect(source).not.toContain('EXAMPLE-FW');
});
