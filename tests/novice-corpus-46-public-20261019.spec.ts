import {test,expect} from '@playwright/test';
// Authorized authored fixtures, not manufacturer or native/target ground truth.
const expandedCases=[
 ['Cisco ASA TCP connection','<166>Oct 19 09:06:01 asa-fw %ASA-6-302013: Built outbound TCP connection 39482 for outside:198.51.100.20/443 (198.51.100.20/443) to inside:192.0.2.13/54002 (192.0.2.13/54002)'],
 ['Cisco FTD intrusion','<166>Oct 19 09:06:13 ftd-01 %FTD-4-430003: Intrusion Event: Rule 2024218 policy MyPolicy src 192.0.2.4 dst 198.51.100.9'],
 ['F5 ASM CEF wrapped','<134>Oct 19 09:06:13 bigip-01 ASM:CEF:0|F5|ASM|17.1.0|Blocked Request|Blocked Request|8|src=192.0.2.7 dst=198.51.100.7 spt=45124 dpt=443 act=blocked request=/login'],
 ['F5 ASM KV reporting','<134>Oct 19 09:07:00 bigip-01 ASM:unit_hostname="bigip-01",management_ip_address="192.0.2.1",policy_name="public-waf",request_status="blocked",ip_client="198.51.100.20",response_code="403"'],
 ['Sophos XG firewall','<189>Oct 19 09:10:01 sophos-fw device_name="XG-01" log_id=0101016001 log_type="Firewall" log_component="Firewall Rule" src_ip=192.0.2.10 dst_ip=198.51.100.3 src_port=55666 dst_port=443 status="Deny"'],
 ['SonicWall firewall','<189>Oct 19 09:10:03 sw-fw id=firewall sn=0011 msg="Connection dropped" src=192.0.2.11:55000 dst=198.51.100.8:443 proto=tcp rule="block-test"'],
 ['Zscaler NSS LEEF','LEEF:2.0|Zscaler|NSS|1.0|web-block|\tusrName=alice\tsrc=192.0.2.6\tdst=198.51.100.4\turl=https://example.test/login\taction=blocked'],
 ['Cloudflare WAF JSON',JSON.stringify({Datetime:'2026-10-19T08:20:01Z',Action:'block',ClientIP:'198.51.100.20',ClientCountryName:'KR',RayID:'7a800001',Source:'waf',WAFRuleID:'10001',URIPath:'/admin'})],
 ['Okta auth JSON',JSON.stringify({published:'2026-10-19T08:20:01Z',eventType:'user.session.start',displayMessage:'User session started',actor:{alternateId:'alice@example.test'},client:{ipAddress:'192.0.2.44'},outcome:{result:'SUCCESS'}})],
 ['AWS CloudTrail JSON',JSON.stringify({eventVersion:'1.08',userIdentity:{type:'IAMUser',userName:'security-demo'},eventTime:'2026-10-19T08:20:00Z',eventSource:'signin.amazonaws.com',eventName:'ConsoleLogin',sourceIPAddress:'198.51.100.40',responseElements:{ConsoleLogin:'Failure'}})],
 ['AWS GuardDuty finding JSON',JSON.stringify({type:'Recon:EC2/PortProbeUnprotectedPort',severity:8.0,createdAt:'2026-10-19T08:20:00Z',service:{action:{networkConnectionAction:{remoteIpDetails:{ipAddressV4:'203.0.113.21'},remotePortDetails:{port:22}}}},resource:{instanceDetails:{instanceId:'i-demo'}}})],
 ['Azure sign-in JSON',JSON.stringify({createdDateTime:'2026-10-19T08:20:01Z',userPrincipalName:'alice@example.test',ipAddress:'203.0.113.45',appDisplayName:'TestApp',status:{errorCode:50126,failureReason:'Invalid credentials'},location:{city:'Seoul',countryOrRegion:'KR'}})],
 ['SentinelOne EDR JSON',JSON.stringify({event_time:'2026-10-19T08:20:01Z',agent:{computer_name:'lab-host'},threat:{name:'Demo.Unsafe',classification:'malicious',mitigation_status:'mitigated'},src_ip:'192.0.2.8'})],
 ['Suricata DNS EVE JSON',JSON.stringify({timestamp:'2026-10-19T08:20:01Z',event_type:'dns',src_ip:'192.0.2.20',dest_ip:'198.51.100.53',dns:{type:'query',rrname:'example.test',rrtype:'A'}})],
 ['Wazuh alert JSON',JSON.stringify({timestamp:'2026-10-19T08:20:01Z',rule:{level:10,description:'Authentication failure',id:'5716'},agent:{id:'001',name:'linux-demo'},data:{srcip:'192.0.2.55',dstuser:'root'}})],
 ['Vectra NDR JSON',JSON.stringify({timestamp:'2026-10-19T08:20:01Z',detection:{type:'Command and Control',score:91},src_ip:'192.0.2.31',dest_ip:'198.51.100.21',protocol:'tcp'})],
 ['Linux auditd keyed','type=USER_LOGIN msg=audit(1792398000.317:221): pid=432 uid=0 auid=1000 ses=4 subj=unconfined msg=\'op=login id=1000 exe="/usr/bin/sshd" hostname=? addr=192.0.2.5 terminal=ssh res=failed\''],
 ['Snort fast alert','10/19-08:24:05.173300 [**] [1:2010935:3] DEMO TEST IDS MALWARE [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.0.2.11:51511 -> 198.51.100.3:443'],
 ['W3C with header','#Version: 1.0\n#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-19 08:20:01 192.0.2.6 GET /login 403'],
 ['Zeek with tabs','#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n1792398000.000\tCxyz\t192.0.2.6\t198.51.100.9\ttcp'],
 ['Malformed CEF escape','CEF:0|Example|WAF|1|42|Test|5|src=192.0.2.1 msg=foo\\bar=bad request=/admin'],
 ['Malformed LEEF header','LEEF:2.0|Vendor|Prod|1.0|Event|0xZZ|src=192.0.2.3 dst=198.51.100.7'],
 ['Quoted multiline CSV','time,src_ip,action,detail\n2026-10-19,192.0.2.1,deny,"bad request\nsecond line"\n2026-10-19,192.0.2.2,allow,"fine"'],
 ['UTF8 mixed vendor KV','<165>Oct 19 09:21:33 relay device user="김민수" location="서울" action="차단" srcip=192.0.2.1 dstip=198.51.100.3'],
 ['JSON threat-user-asset family',JSON.stringify({event_type:'threat',src_ip:'192.0.2.5',action:'blocked'})+'\n'+JSON.stringify({event_type:'user',username:'alice',action:'login'})+'\n'+JSON.stringify({event_type:'asset',hostname:'fw01',action:'found'})],
 ['mixed JSON KV CEF','{"event_type":"threat","src_ip":"192.0.2.5","action":"deny"}\nsrc_ip=192.0.2.6 action=allow dst_ip=198.51.100.1\nCEF:0|Acme|IDS|1.0|99|Test|5|src=192.0.2.7 act=blocked'],
 ['duplicate keys','<134>Oct 19 09:25:01 fw action=allow action=deny src=192.0.2.3 dst=198.51.100.2'],
 ['unrecognized plain text','A demo device says a blue bird flew across the event at 09:31'],
 ['unclosed KV quoted field','<134>Oct 19 09:20:01 fw action="blocked src=192.0.2.3 dst=198.51.100.2'],
 ['CSV unlabelled positions','192.0.2.1,198.51.100.2,deny,443\n192.0.2.3,198.51.100.5,allow,80'],
 ['CEF + syslog with bad PRI','<999>Oct 19 09:25:01 fw CEF:0|Acme|IDS|1|9|Demo|5|src=192.0.2.1 act=deny'],
];
const diverseCases=[
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
const joined=[
 ...expandedCases.map(([id,raw])=>({id:'Expanded: '+id,raw,origin:'31-expanded-synthetic'})),
 ...diverseCases.map(x=>({id:'Earlier: '+x.id,raw:x.raw,origin:'15-diverse-synthetic'}))
];
for(const item of joined){
 test(item.id,async({page})=>{
  const pageErrors:string[]=[];
  const serverFailures:string[]=[];
  page.on('pageerror',err=>pageErrors.push(err.message));
  page.on('response',res=>{if(res.url().includes('/api/')&&res.status()>=500)
   serverFailures.push(res.status()+' '+new URL(res.url()).pathname);});
  await page.goto('/');
  await expect(page.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toBeVisible({timeout:20000});
  const status=(await summary.innerText()).replace(/\s+/g,' ').slice(0,450);
  await expect(source).toHaveValue(item.raw.replace(/\r\n/g,'\n'));
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  const enabled=await review.isEnabled();
  const issues=await page.getByLabel('Parse problem inspector').count();
  let traversed='Analysis';
  if(enabled){
   await review.click();
   const mappingStage=page.getByLabel('Review Fields stage');
   const blocked=page.getByLabel('Parser draft not ready');
   await expect(mappingStage.or(blocked)).toBeVisible({timeout:18000});
   if(await blocked.isVisible()){
    await expect(blocked).toContainText('No source value was discarded');
    await expect(blocked.getByRole('button',{name:'Use ChatGPT Assisted Parser'})).toBeVisible();
    traversed+=' > Source only (compiler blocked, retained)';
   }else{
    traversed+=' > Review Fields';
    const map=mappingStage.getByRole('button',{name:'Map Fields',exact:true});
    if(await map.isEnabled()){
     await map.click();
     await expect(page.getByLabel('Map Fields stage')).toBeVisible();
     traversed+=' > Map Fields';
    }
   }
  }
  const result={id:item.id,origin:item.origin,sourceBytes:Buffer.byteLength(item.raw,'utf8'),
   status,issues,reviewEnabled:enabled,traversed,pageErrors,serverFailures};
  console.log('NOVICE_CORPUS_E2E '+JSON.stringify(result));
  await test.info().attach('case-result',{body:JSON.stringify(result),contentType:'application/json'});
  expect(pageErrors).toEqual([]);
  expect(serverFailures).toEqual([]);

 });
}
