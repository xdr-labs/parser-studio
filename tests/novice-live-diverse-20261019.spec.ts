import {test,expect} from '@playwright/test';

// These are authored, non-sensitive vendor-style examples, not original device captures.
// Calls reach a real loopback Vite UI, authoring API and Multi-Pass source engine; no API mocks.
const cases=[
 {id:'AWS WAF nested JSON',raw:JSON.stringify({timestamp:1760833000000,formatVersion:1,webaclId:'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/demo',terminatingRuleId:'BadBot',action:'BLOCK',httpRequest:{clientIp:'203.0.113.21',country:'KR',uri:'/login',headers:[{name:'User-Agent',value:'curl/8.0'}]}})},
 {id:'Suricata IPS EVE JSON',raw:JSON.stringify({timestamp:'2026-10-19T08:03:15.123+0000',event_type:'alert',src_ip:'192.0.2.3',dest_ip:'198.51.100.10',src_port:55012,dest_port:443,alert:{signature_id:2024218,signature:'Test malware activity',severity:2,category:'Attempted Administrator Privilege Gain'}})},
 {id:'CrowdStrike EDR JSON',raw:JSON.stringify({metadata:{eventType:'DetectionSummaryEvent'},event:{ComputerName:'WORKSTATION-01',UserName:'analyst',ProcessName:'powershell.exe',Severity:70,LocalIP:'192.0.2.4'}})},
 {id:'Microsoft Defender XDR JSON',raw:JSON.stringify({Timestamp:'2026-10-19T08:02:15Z',DeviceName:'laptop-01',ActionType:'AntivirusDetection',FileName:'suspicious.exe',RemoteIP:'203.0.113.44',ReportId:1234})},
 {id:'Fortinet FortiGate KV syslog',raw:'<189>date=2026-10-19 time=08:10:23 devname="FGT-A" devid="FG0001" type="traffic" subtype="forward" level="notice" srcip=192.0.2.10 dstip=198.51.100.12 srcport=54320 dstport=443 action="accept" service="HTTPS"'},
 {id:'Palo Alto PAN-OS positional CSV',raw:'<14>Oct 19 08:12:21 PA-FW01 1,2026/10/19 08:12:21,012345678901,TRAFFIC,end,2561,2026/10/19 08:12:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/19 08:12:21,123456,1,51234,443'},
 {id:'IBM QRadar LEEF',raw:'LEEF:2.0|IBM|QRadar|7.5|login|^|src=192.0.2.10^dst=198.51.100.13^usrName=bob^cat=Authentication^sev=5'},
 {id:'ArcSight CEF',raw:'CEF:0|Acme|IDS|3.2|1001|Exploit Detected|8|src=192.0.2.11 dst=198.51.100.5 spt=443 dpt=9443 act=blocked msg=Known exploit signature'},
 {id:'Juniper SRX syslog',raw:'<134>Oct 19 08:24:00 juniper-srx RT_FLOW: RT_FLOW_SESSION_DENY: session denied 192.0.2.12/52333->198.51.100.9/80 0x0 None 6(0) policy-deny trust untrust 0 0'},
 {id:'WatchGuard Firebox syslog',raw:'<134>Oct 19 08:23:58 watchguard-fw firewall: deny 192.0.2.12 198.51.100.7 tcp 54234 443 policy=ProxyAction action=deny'},
 {id:'Checkpoint KV syslog',raw:'<134>Oct 19 08:22:22 cp-fw log: action=Drop src=192.0.2.1 dst=198.51.100.2 service=https product=Firewall rule=Default_Rule origin=cp-fw'},
 {id:'RFC5424 generic KV',raw:'<134>1 2026-10-19T08:23:58Z proxy01 waf 882 WAF-110 - action=blocked srcip=192.0.2.11 dstip=198.51.100.7 port=443'},
 {id:'Zeek TSV with schema header',raw:'#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp\n1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp'},
 {id:'Quoted multiline CSV',raw:'id,action,detail\n1,deny,"multi line\nmessage"\n2,allow,"normal"'},
 {id:'Windows Security Event XML',raw:'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><Computer>HOST01</Computer></System><EventData><Data Name="TargetUserName">sample</Data></EventData></Event>'},
] as const;
for(const item of cases){
 test(item.id,async({page})=>{
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(String(e.message)));
  await page.goto('/');
  await expect(page.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
  await page.getByLabel('Auto Parser raw logs').fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toBeVisible({timeout:20000});
  const detail=(await summary.innerText()).replace(/\s+/g,' ').slice(0,290);
  const problems=await page.getByLabel('Parse problem inspector').count();
  if(item.id==='Quoted multiline CSV'){
   await expect(summary).toContainText('0 of 3 log events parsed completely');
   await expect(summary.getByLabel('Multiline CSV recovery')).toBeVisible();
  }
  if(item.id==='Zeek TSV with schema header')
   await expect(page.getByLabel('Parse problem inspector')).toContainText('Zeek');
  if(item.id==='Windows Security Event XML')
   await expect(page.getByLabel('Parse problem inspector')).toContainText('Export Windows Event logs as JSON');
  console.log('LIVE_NOVICE',JSON.stringify({vendor:item.id,summary:detail,problemCount:problems,pageErrors:errors}));
  await test.info().attach('novice-status',{body:JSON.stringify({vendor:item.id,summary:detail,problems,errors},null,2),contentType:'application/json'});
  expect(errors).toEqual([]);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeVisible();
 });
}
test('beginner follows AWS WAF fields into mapping review',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(cases[0].raw);
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 await expect(page.getByLabel('Beginner analysis summary')).toContainText('parsed completely',{timeout:20000});
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled();
 await review.click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
 await page.getByRole('button',{name:'Map Fields',exact:true}).click();
 await expect(page.getByLabel('Map Fields stage')).toBeVisible();
});

test('novice prepares Zeek field schema, confirms source boundaries and reverses them',async({page})=>{
 const source=cases.find(item=>item.id==='Zeek TSV with schema header')!.raw;
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 const offer=page.getByLabel('Zeek schema preparation');
 await expect(offer).toContainText('2 data events');
 await expect(offer).toContainText('2 lines beginning with #');
 await offer.getByRole('button',{name:'Prepare Zeek data rows and field names'}).click();
 const prepared=page.getByLabel('Auto Parser raw logs');
 await expect(prepared).not.toContainText('#fields');
 await expect(prepared).toHaveValue(/1760832000.*Cw01/);
 await expect(page.getByLabel('Prepared Zeek source context')).toContainText('original sample');
 await page.getByRole('button',{name:'Analyze Logs'}).click();
 const csv=page.getByLabel('Review CSV column names');
 await expect(csv).toBeVisible({timeout:20000});
 await expect(csv.getByLabel('Reviewed CSV column names')).toHaveValue('ts,uid,id_orig_h,id_resp_h,proto');
 await expect(csv.getByLabel('Reviewed CSV data separator')).toHaveValue('\t');
 await csv.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
 await expect(csv).toContainText('Field names are ready');
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled();
 await review.click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
 await expect(page.getByLabel('Map Fields stage')).toBeVisible();
 await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
 await expect(page.getByLabel('Create Parser stage')).toBeVisible();
 const generateButton=page.getByRole('button',{name:'Create Parser Files'});
 await expect(generateButton).toBeEnabled();
 const generated=page.waitForResponse(response=>
   response.url().endsWith('/api/v1/parser-pairs/generate')&&response.request().method()==='POST');
 await generateButton.click();
 expect((await generated).status()).toBe(200);
 await expect(page.getByLabel('Generated parser files')).toBeVisible();
 await page.getByRole('button',{name:'Add Logs'}).click();
 await page.getByLabel('Prepared Zeek source context').getByRole('button',{name:'Restore original Zeek sample'}).click();
 await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
 await expect(page.getByLabel('Zeek schema preparation')).toBeVisible();
});
