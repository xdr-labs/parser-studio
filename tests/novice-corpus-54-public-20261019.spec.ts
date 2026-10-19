import {test,expect} from '@playwright/test';

// Deliberately authored test-only security logs. No original captures,
// no manufacturer/firmware attestation, and no Stellar normalization oracle.
type Scenario={id:string;family:string;raw:string};
const scenarios:Scenario[]=[
 {id:'01 AWS WAF rule decision',family:'waf/json',raw:JSON.stringify({timestamp:1792368000000,formatVersion:1,webaclId:'arn:aws:wafv2:us-east-1:123:regional/webacl/demo',action:'BLOCK',httpRequest:{clientIp:'192.0.2.21',country:'KR',uri:'/login',headers:[{name:'User-Agent',value:'curl/8.1'}]},terminatingRuleId:'SQLiRule'})},
 {id:'02 Cloudflare WAF request',family:'waf/json',raw:JSON.stringify({datetime:'2026-10-19T04:12:20Z',ClientIP:'198.51.100.5',ClientCountry:'KR',ClientRequestURI:'/wp-admin',WAFAction:'block',Source:'waf',RuleID:'abc',RayID:'aabb123'})},
 {id:'03 F5 ASM WAF syslog',family:'waf/syslog',raw:'<134>Oct 19 04:12:20 f5-asm ASM: attack_type="SQL Injection",support_id="12345",src=192.0.2.9,dst=198.51.100.40,request="/index.php",action="blocked"'},
 {id:'04 Akamai edge JSON',family:'waf/json',raw:JSON.stringify({type:'waf',eventTime:'2026-10-19T04:12:20Z',clientIP:'192.0.2.6',ruleId:'1234',policyId:'abcd',action:'deny'})},
 {id:'05 ModSecurity audit-style',family:'waf/text',raw:'[Mon Oct 19 04:12:20.001 2026] [client 192.0.2.3] ModSecurity: Access denied with code 403 (phase 2). [id "942100"] [msg "SQL Injection Attack Detected"]'},
 {id:'06 Palo Alto PAN-OS traffic CSV',family:'ngfw/csv',raw:'<14>Oct 19 08:12:21 PA-FW01 1,2026/10/19 08:12:21,012345678901,TRAFFIC,end,2561,2026/10/19 08:12:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/19 08:12:21,123456,1,51234,443'},
 {id:'07 Fortinet FortiGate KV',family:'ngfw/kv',raw:'<189>date=2026-10-19 time=08:10:23 devname="FGT-A" devid="FG0001" type="traffic" subtype="forward" level="notice" srcip=192.0.2.10 dstip=198.51.100.12 srcport=54320 dstport=443 action="accept" service="HTTPS"'},
 {id:'08 Check Point firewall KV',family:'ngfw/syslog-kv',raw:'<134>Oct 19 08:22:22 cp-fw log: action=Drop src=192.0.2.1 dst=198.51.100.2 service=https product=Firewall rule=Default_Rule origin=cp-fw'},
 {id:'09 Cisco ASA message ID',family:'ngfw/syslog',raw:'<166>Oct 19 08:23:58 cisco-fw %ASA-6-302013: Built outbound TCP connection 991 for outside:198.51.100.7/443 to inside:192.0.2.16/54321'},
 {id:'10 Cisco FTD threat',family:'ngfw/syslog',raw:'<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected signature=1000123 src=192.0.2.40 dst=198.51.100.5 action=block'},
 {id:'11 Juniper SRX RT_FLOW',family:'ngfw/syslog',raw:'<134>Oct 19 08:24:00 juniper-srx RT_FLOW: RT_FLOW_SESSION_DENY: session denied 192.0.2.12/52333->198.51.100.9/80 0x0 None 6(0) policy-deny trust untrust 0 0'},
 {id:'12 WatchGuard Firebox',family:'ngfw/syslog',raw:'<134>Oct 19 08:23:58 watchguard-fw firewall: deny 192.0.2.12 198.51.100.7 tcp 54234 443 policy=ProxyAction action=deny'},
 {id:'13 SonicWall firewall',family:'ngfw/syslog',raw:'<134>Oct 19 07:45:12 sonicwall id=firewall sn=123456 time="2026-10-19 07:45:12" fw=192.0.2.2 pri=5 c=1024 m=123 msg="Deny TCP" src=192.0.2.13 dst=198.51.100.17'},
 {id:'14 Sophos Firewall',family:'ngfw/kv',raw:'device_name="XGS01" timestamp="2026-10-19T08:23:45Z" log_type="Firewall" log_subtype="Denied" src_ip="192.0.2.13" dst_ip="198.51.100.2" dst_port=443 status="Deny"'},
 {id:'15 pfSense filterlog',family:'ngfw/csv',raw:'<134>Oct 19 08:12:00 pfsense filterlog: 24,,,1000000103,em0,match,block,in,4,0x0,,64,40021,0,none,6,tcp,60,192.0.2.10,198.51.100.2,50100,443,0,S,1234,,65535,,'},
 {id:'16 OPNsense filterlog',family:'ngfw/csv',raw:'<134>Oct 19 08:12:01 opnsense filterlog: 32,,,1000000104,vtnet0,match,pass,in,4,0x0,,64,33333,0,none,17,udp,90,192.0.2.10,198.51.100.53,49000,53,0'},
 {id:'17 Barracuda firewall',family:'ngfw/syslog-kv',raw:'<134>Oct 19 08:13:22 barracuda-fw firewall: action=DENY src=192.0.2.10 dst=198.51.100.1 proto=TCP dport=22 rule=default'},
 {id:'18 Suricata EVE alert',family:'ids/json',raw:JSON.stringify({timestamp:'2026-10-19T08:03:15.123+0000',event_type:'alert',src_ip:'192.0.2.3',dest_ip:'198.51.100.10',src_port:55012,dest_port:443,alert:{signature_id:2024218,signature:'Test malware activity',severity:2,category:'Attempted Administrator Privilege Gain'}})},
 {id:'19 Snort alert syslog',family:'ids/syslog',raw:'<134>Oct 19 09:44:01 snort01 snort[555]: [1:2024218:3] Test possible C2 beacon [Classification: Malware Command and Control] [Priority: 1] {TCP} 192.0.2.10:5055 -> 198.51.100.20:443'},
 {id:'20 CrowdStrike Falcon',family:'edr/json',raw:JSON.stringify({metadata:{eventType:'DetectionSummaryEvent'},event:{ComputerName:'DESKTOP01',UserName:'analyst',ProcessName:'powershell.exe',Severity:70,LocalIP:'192.0.2.4',SHA256String:'0123456789'}})},
 {id:'21 Microsoft Defender XDR',family:'edr/json',raw:JSON.stringify({Timestamp:'2026-10-19T08:02:15Z',DeviceName:'laptop-01',ActionType:'AntivirusDetection',FileName:'suspicious.exe',RemoteIP:'203.0.113.44',ReportId:1234})},
 {id:'22 SentinelOne agent event',family:'edr/json',raw:JSON.stringify({eventType:'ThreatDetected',agentId:'test-agent',computerName:'endpoint-01',initiatedBy:'machine',threatInfo:{confidenceLevel:'malicious',classification:'Trojan',filePath:'C:\\temp\\demo.exe'}})},
 {id:'23 VMware Carbon Black',family:'edr/json',raw:JSON.stringify({type:'alert',process_guid:'00001',device_name:'host01',process_name:'cmd.exe',event_time:'2026-10-19T08:21:07Z',remote_ip:'203.0.113.22',watchlists:[{name:'Demo Rule',id:'watch1'}]})},
 {id:'24 Sophos endpoint detection',family:'edr/json',raw:JSON.stringify({id:'event-123',severity:'high',name:'Malware detected',type:'Event::Endpoint::Threat::Detected',endpoint:{hostname:'laptop2',id:'endpoint1'},created_at:'2026-10-19T08:23:00Z'})},
 {id:'25 Trend Micro Vision One',family:'xdr/json',raw:JSON.stringify({eventName:'SUSPICIOUS_PROCESS',eventTime:'2026-10-19T09:01:00Z',endpointName:'host2',srcIp:'192.0.2.60',processName:'wscript.exe',riskLevel:'high'})},
 {id:'26 Zeek conn TSV with headers',family:'ndr/tsv',raw:'#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp\n1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp'},
 {id:'27 Corelight Zeek JSON',family:'ndr/json',raw:JSON.stringify({'@timestamp':'2026-10-19T08:12:13Z','_path':'conn',uid:'Cq123',id:{orig_h:'192.0.2.7',resp_h:'198.51.100.10'},proto:'tcp',service:'ssl'})},
 {id:'28 Vectra Detect alert',family:'ndr/json',raw:JSON.stringify({category:'Botnet',detection:'Suspicious Beaconing',source:'192.0.2.10',destination:'198.51.100.4',certainty:65,threat:72,first_timestamp:'2026-10-19T08:15:00Z'})},
 {id:'29 Darktrace model breach',family:'ndr/json',raw:JSON.stringify({model:{name:'Anomalous SMB Activity',category:'Lateral Movement'},device:{ip:'192.0.2.5',hostname:'client01'},breachTime:'2026-10-19T08:00:00Z',score:83})},
 {id:'30 ExtraHop Reveal(x)',family:'ndr/json',raw:JSON.stringify({type:'detections',riskScore:70,participants:[{ipaddr:'192.0.2.4'},{ipaddr:'198.51.100.2'}],properties:{description:'Unusual outbound connections'}})},
 {id:'31 Cisco Umbrella DNS',family:'dns/csv',raw:'2026-10-19 08:22:12,192.0.2.10,evil.example.test,Blocked,Malware,Internal Networks'},
 {id:'32 Infoblox DNS security',family:'dns/kv',raw:'<134>Oct 19 08:23:58 dns01 query: client=192.0.2.44 domain="example.test" qtype=A response=NXDOMAIN policy=block'},
 {id:'33 Zscaler ZIA proxy',family:'proxy/tsv',raw:'2026-10-19 08:30:21\t192.0.2.10\talice@example.test\tBLOCK\twww.example.test\tmalware\t403'},
 {id:'34 Netskope CASB',family:'casb/json',raw:JSON.stringify({timestamp:1792392021,event_type:'page',user:'alice@example.test',srcip:'192.0.2.10',app:'Box',activity:'Download',severity:'high',action:'block'})},
 {id:'35 Proofpoint TAP',family:'email/json',raw:JSON.stringify({eventTime:'2026-10-19T08:50:00Z',threatType:'url',threatStatus:'active',sender:'sender@example.test',recipient:'alice@example.test',clickIP:'192.0.2.30',messageID:'msg-1'})},
 {id:'36 Mimecast email security',family:'email/json',raw:JSON.stringify({timestamp:'2026-10-19T08:59:01Z',aCode:'policy',sender:'sender@example.test',recipient:'alice@example.test',subject:'Example only',action:'reject'})},
 {id:'37 Okta system log',family:'iam/json',raw:JSON.stringify({published:'2026-10-19T08:23:59Z',eventType:'user.session.start',outcome:{result:'SUCCESS'},actor:{alternateId:'alice@example.test'},client:{ipAddress:'192.0.2.42'},target:[]})},
 {id:'38 Azure Entra sign-in',family:'iam/json',raw:JSON.stringify({createdDateTime:'2026-10-19T08:41:00Z',userPrincipalName:'alice@example.test',ipAddress:'192.0.2.8',status:{errorCode:0},appDisplayName:'Demo Portal',conditionalAccessStatus:'success'})},
 {id:'39 Ping Identity audit',family:'iam/kv',raw:'timestamp=2026-10-19T08:10:21Z category=AUTHN action=LOGIN principal=alice@example.test client_ip=192.0.2.10 outcome=SUCCESS'},
 {id:'40 AWS CloudTrail',family:'cloud/json',raw:JSON.stringify({eventVersion:'1.09',eventTime:'2026-10-19T08:20:00Z',eventSource:'iam.amazonaws.com',eventName:'CreateUser',sourceIPAddress:'192.0.2.10',userIdentity:{type:'IAMUser',userName:'demo'},requestParameters:{userName:'test1'}})},
 {id:'41 Azure Activity Log',family:'cloud/json',raw:JSON.stringify({eventTimestamp:'2026-10-19T09:00:00Z',operationName:{value:'Microsoft.Compute/virtualMachines/write'},category:{value:'Administrative'},caller:'alice@example.test',claims:{ipaddr:'192.0.2.7'},status:{value:'Succeeded'}})},
 {id:'42 Google Cloud audit',family:'cloud/json',raw:JSON.stringify({logName:'projects/demo/logs/cloudaudit.googleapis.com%2Factivity',timestamp:'2026-10-19T08:04:00Z',protoPayload:{methodName:'SetIamPolicy',authenticationInfo:{principalEmail:'alice@example.test'},requestMetadata:{callerIp:'192.0.2.2'}}})},
 {id:'43 Kubernetes audit',family:'cloud/json',raw:JSON.stringify({kind:'Event',apiVersion:'audit.k8s.io/v1',level:'Metadata',auditID:'00000000',stage:'ResponseComplete',requestURI:'/api/v1/pods',verb:'create',user:{username:'system:serviceaccount:default:demo'},sourceIPs:['192.0.2.5'],responseStatus:{code:201}})},
 {id:'44 ArcSight CEF escaped message',family:'cef',raw:'CEF:0|Acme|IDS|1.0|1001|Test \\| Escaped|8|src=192.0.2.1 dst=198.51.100.5 spt=1122 dpt=443 act=blocked msg=Demo\\=blocked cs1Label=rule cs1=test'},
 {id:'45 IBM QRadar LEEF custom delimiter',family:'leef',raw:'LEEF:2.0|IBM|QRadar|7.5|login|^|src=192.0.2.10^dst=198.51.100.13^usrName=bob^cat=Authentication^sev=5'},
 {id:'46 Generic RFC5424 SD',family:'syslog/rfc5424',raw:'<134>1 2026-10-19T09:15:22.123Z fw01 application 12 audit [meta@12345 action="deny" src="192.0.2.10"] firewall denied'},
 {id:'47 W3C IIS WAF access',family:'w3c',raw:'#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-19 08:44:01 192.0.2.10 GET /login 403'},
 {id:'48 CSV quoted delimiter',family:'csv',raw:'2026-10-19T09:15:22Z,192.0.2.10,"deny,malware",443'},
 {id:'49 Unclosed CSV quote',family:'csv/malformed',raw:'2026-10-19T09:15:22Z,192.0.2.10,"deny,malware'},
 {id:'50 Windows Event XML unsupported',family:'windows/xml',raw:'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><Computer>HOST01</Computer></System><EventData><Data Name="TargetUserName">sample</Data></EventData></Event>'},
 {id:'51 Windows Event JSON',family:'windows/json',raw:JSON.stringify({EventID:4625,TimeCreated:'2026-10-19T08:00:00Z',Computer:'HOST01',EventData:{TargetUserName:'alice',IpAddress:'192.0.2.10',Status:'0xc000006d'}})},
 {id:'52 UTF8 Korean values',family:'unicode/json',raw:JSON.stringify({timestamp:'2026-10-19T08:10:01Z',action:'deny',user:'김민수',host:'서울-보안장비',comment:'접근이 차단되었습니다'})},
 {id:'53 Mixed three JSON event types',family:'mixed/json',raw:'{"event_type":"threat","action":"deny","src_ip":"192.0.2.10"}\n{"event_type":"user","username":"alice","action":"login"}\n{"event_type":"asset","hostname":"fw01","action":"found"}'},
 {id:'54 Mixed JSON and KV',family:'mixed/json-kv',raw:'{"action":"deny","src_ip":"192.0.2.10"}\n<134>Oct 19 08:21:00 firewall log: action=allow src=192.0.2.20 dst=198.51.100.2'},
];
const bad=new Set(['09 Cisco ASA message ID','11 Juniper SRX RT_FLOW','12 WatchGuard Firebox','26 Zeek conn TSV with headers','44 ArcSight CEF escaped message','48 CSV quoted delimiter','49 Unclosed CSV quote','50 Windows Event XML unsupported']);
for(const entry of scenarios){
 test(entry.id,async({page})=>{
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  const failedResponses:Array<{url:string,status:number}>=[];
  page.on('response',r=>{
   if(r.url().startsWith('https://app.parser.xdr.ooo/api/')&&r.status()>=500)
    failedResponses.push({url:r.url(),status:r.status()});
  });
  await page.goto('/');
  await expect(page.getByRole('heading',{name:/Paste security logs/})).toBeVisible();
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(entry.raw);
  await expect(source).toHaveValue(entry.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  const summary=page.getByLabel('Beginner analysis summary');
  await expect(summary).toBeVisible({timeout:20000});
  const headline=((await summary.locator('.beginner-analysis-head strong').first().textContent())||'').trim();
  const summaryText=(await summary.innerText()).replace(/\s+/g,' ').slice(0,620);
  const problem=page.getByLabel('Parse problem inspector');
  const hasProblem=(await problem.count())>0;
  const recover=hasProblem ? await problem.getByRole('button',{name:/Fix with ChatGPT|Review with ChatGPT/}).count()>0:false;
  const csvReview=await page.getByLabel('Review CSV column names').count()>0;
  const zeekPrep=await page.getByLabel('Zeek schema preparation').count()>0;
  const reviewEnabled=await page.getByRole('button',{name:'Review Fields',exact:true}).isEnabled();
  const reviewedNotice=hasProblem?(await problem.innerText()).replace(/\s+/g,' ').slice(0,390):'';
  const sampleStatuses={name:entry.id,family:entry.family,headline,problem:hasProblem,recover,csvReview,zeekPrep,reviewEnabled,explanation:reviewedNotice,summary:summaryText,pageErrors:errors,http5xx:failedResponses};
  console.log('NOVICE_MATRIX '+JSON.stringify(sampleStatuses));
  await test.info().attach('real-public-user-journey',{body:JSON.stringify(sampleStatuses,null,2),contentType:'application/json'});
  if(bad.has(entry.id))await test.info().attach('beginner-screenshot',{body:await page.screenshot({fullPage:true}),contentType:'image/png'});
  expect(errors).toEqual([]);
  expect(failedResponses).toEqual([]);
  expect(headline).not.toBe('');
  // The Analyze action must retain the source exactly, whether parser success or review.
  await expect(source).toHaveValue(entry.raw);
  if(reviewEnabled){
   await page.getByRole('button',{name:'Review Fields',exact:true}).click();
   const mappingStage=page.getByLabel('Review Fields stage');
   const blocked=page.getByLabel('Parser draft not ready');
   await expect(mappingStage.or(blocked)).toBeVisible({timeout:18000});
   if(await blocked.isVisible()){
    await expect(blocked).toContainText('No source value was discarded');
    await expect(blocked.getByRole('button',{name:'Use ChatGPT Assisted Parser'})).toBeVisible();
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
   }else{
    const mapping=mappingStage.getByRole('button',{name:'Map Fields',exact:true});
    if(await mapping.isEnabled()){
     await mapping.click();
     await expect(page.getByLabel('Map Fields stage')).toBeVisible();
    }
   }
  }else{
   expect(hasProblem||csvReview||zeekPrep||summaryText.includes('review')).toBeTruthy();
  }

 });
}
