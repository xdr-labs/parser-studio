import {test,expect,type Page} from '@playwright/test';

const cap={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],rfc5424AdjacentStructuredDataSubset:true,
    rfc5424StructuredDataMaxBytes:1024,leefHexSeparatorSubset:true,
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

const cases=[
  {
    family:'NGFW',product:'PAN-OS-style named JSON traffic',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname'],
    rows:[
      '{"src_ip":"192.0.2.101","dst_ip":"198.51.100.101","src_port":51001,"dst_port":443,"action":"allow","hostname":"pa-fw-01","rule":"internet-out"}',
      '{"src_ip":"192.0.2.102","dst_ip":"198.51.100.102","src_port":51002,"dst_port":53,"action":"deny","hostname":"pa-fw-02","rule":"dns-block"}',
      '{"src_ip":"192.0.2.103","dst_ip":"198.51.100.103","src_port":51003,"dst_port":8443,"action":"allow","hostname":"pa-fw-03","rule":"app-proxy"}',
    ],
  },
  {
    family:'Firewall',product:'FortiGate-style traffic KV',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname'],
    rows:[
      'srcip=192.0.2.110 dstip=198.51.100.110 srcport=52010 dstport=443 action=accept hostname=fg-01 policyid=10',
      'srcip=192.0.2.111 dstip=198.51.100.111 srcport=52011 dstport=22 action=deny hostname=fg-02 policyid=11',
      'srcip=192.0.2.112 dstip=198.51.100.112 srcport=52012 dstport=53 action=accept hostname=fg-03 policyid=12',
    ],
  },
  {
    family:'NGFW',product:'Cisco Secure Firewall CEF',
    expectTargets:['srcip','dstip','srcport','dstport','action'],
    rows:[
      'CEF:0|Cisco|Secure Firewall|7.6|430002|Connection Blocked|7|src=192.0.2.120 dst=198.51.100.120 spt=53000 dpt=443 act=blocked cs1=policy-a',
      'CEF:0|Cisco|Secure Firewall|7.6|430003|Connection Allowed|4|src=192.0.2.121 dst=198.51.100.121 spt=53001 dpt=80 act=allowed cs1=policy-b',
      'CEF:0|Cisco|Secure Firewall|7.6|430004|Connection Blocked|8|src=192.0.2.122 dst=198.51.100.122 spt=53002 dpt=22 act=blocked cs1=policy-c',
    ],
  },
  {
    family:'Email Security',product:'Proofpoint-style CEF',
    expectTargets:['srcip','dstip','dstport','action'],
    rows:[
      'CEF:0|Proofpoint|Email Security|1|malware|Malware Blocked|8|src=192.0.2.130 dst=198.51.100.130 dpt=25 act=blocked msg=attachment',
      'CEF:0|Proofpoint|Email Security|1|spam|Spam Quarantined|5|src=192.0.2.131 dst=198.51.100.131 dpt=25 act=quarantine msg=bulk',
      'CEF:0|Proofpoint|Email Security|1|clean|Message Allowed|2|src=192.0.2.132 dst=198.51.100.132 dpt=25 act=allowed msg=clean',
    ],
  },
  {
    family:'Firewall',product:'SonicWall-style LEEF',
    expectTargets:['srcip','dstip','srcport','dstport','action'],
    rows:[
      'LEEF:1.0|SonicWall|Firewall|7|1001|src=192.0.2.140\tdst=198.51.100.140\tsrcPort=54000\tdstPort=443\taction=deny',
      'LEEF:1.0|SonicWall|Firewall|7|1002|src=192.0.2.141\tdst=198.51.100.141\tsrcPort=54001\tdstPort=80\taction=allow',
      'LEEF:1.0|SonicWall|Firewall|7|1003|src=192.0.2.142\tdst=198.51.100.142\tsrcPort=54002\tdstPort=53\taction=allow',
    ],
  },
  {
    family:'SWG',product:'Zscaler ZIA-style JSON',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname','url'],
    rows:[
      '{"sourceIp":"192.0.2.150","destinationIp":"198.51.100.150","sourcePort":55000,"destinationPort":443,"action":"allowed","deviceName":"zia-01","url":"https://example.invalid/a"}',
      '{"sourceIp":"192.0.2.151","destinationIp":"198.51.100.151","sourcePort":55001,"destinationPort":8443,"action":"blocked","deviceName":"zia-02","url":"https://example.invalid/b"}',
      '{"sourceIp":"192.0.2.152","destinationIp":"198.51.100.152","sourcePort":55002,"destinationPort":80,"action":"allowed","deviceName":"zia-03","url":"https://example.invalid/c"}',
    ],
  },
  {
    family:'CASB',product:'Netskope-style transaction JSON',
    expectTargets:['srcip','dstip','srcport','dstport','action','url','username'],
    rows:[
      '{"srcip":"192.0.2.160","dstip":"198.51.100.160","srcport":56000,"dstport":443,"action":"allow","url":"https://saas.invalid/login","username":"alice"}',
      '{"srcip":"192.0.2.161","dstip":"198.51.100.161","srcport":56001,"dstport":443,"action":"block","url":"https://saas.invalid/admin","username":"bob"}',
      '{"srcip":"192.0.2.162","dstip":"198.51.100.162","srcport":56002,"dstport":443,"action":"allow","url":"https://saas.invalid/files","username":"carol"}',
    ],
  },
  {
    family:'CDN/WAF',product:'Cloudflare-style HTTP JSON',
    expectTargets:['srcip'],
    rows:[
      '{"ClientIP":"192.0.2.170","ClientRequestHost":"app.example.invalid","ClientRequestURI":"/login","EdgeResponseStatus":403}',
      '{"ClientIP":"192.0.2.171","ClientRequestHost":"api.example.invalid","ClientRequestURI":"/v1/items","EdgeResponseStatus":200}',
      '{"ClientIP":"192.0.2.172","ClientRequestHost":"shop.example.invalid","ClientRequestURI":"/checkout","EdgeResponseStatus":429}',
    ],
  },
  {
    family:'IAM',product:'Okta-style system audit JSON',
    expectTargets:['srcip'],
    rows:[
      '{"client":{"ipAddress":"192.0.2.180"},"actor":{"alternateId":"alice@example.invalid"},"eventType":"user.session.start","outcome":{"result":"SUCCESS"}}',
      '{"client":{"ipAddress":"192.0.2.181"},"actor":{"alternateId":"bob@example.invalid"},"eventType":"user.authentication.auth_via_mfa","outcome":{"result":"SUCCESS"}}',
      '{"client":{"ipAddress":"192.0.2.182"},"actor":{"alternateId":"carol@example.invalid"},"eventType":"user.session.end","outcome":{"result":"SUCCESS"}}',
    ],
  },
  {
    family:'Windows',product:'Windows Event-style JSON',
    expectTargets:['hostname','source_name','record_number','task','opcode','keywords','log_name','username','severity'],
    rows:[
      '{"hostname":"win-01","source_name":"Microsoft-Windows-Security-Auditing","record_number":"10001","task":"Logon","opcode":"Info","keywords":"Audit Success","log_name":"Security","username":"alice","severity":10}',
      '{"hostname":"win-02","source_name":"Microsoft-Windows-Security-Auditing","record_number":"10002","task":"Account Lockout","opcode":"Info","keywords":"Audit Failure","log_name":"Security","username":"bob","severity":60}',
      '{"hostname":"win-03","source_name":"Microsoft-Windows-PowerShell","record_number":"10003","task":"Execute","opcode":"Start","keywords":"Classic","log_name":"Microsoft-Windows-PowerShell/Operational","username":"carol","severity":40}',
    ],
  },
  {
    family:'Firewall',product:'Check Point-style KV',
    expectTargets:['srcip','dstip','action'],
    rows:[
      'src=192.0.2.190 dst=198.51.100.190 s_port=57000 service=https action=Drop rule=Internet_Block',
      'src=192.0.2.191 dst=198.51.100.191 s_port=57001 service=http action=Accept rule=Web_Allow',
      'src=192.0.2.192 dst=198.51.100.192 s_port=57002 service=dns action=Accept rule=DNS_Allow',
    ],
  },
  {
    family:'WAF',product:'F5 BIG-IP ASM-style JSON',
    expectTargets:['srcip','dstip','dstport','action','hostname'],
    rows:[
      '{"client_ip":"192.0.2.200","server_ip":"198.51.100.200","destination_port":443,"action":"blocked","host_name":"waf-01","violation":"sql-injection"}',
      '{"client_ip":"192.0.2.201","server_ip":"198.51.100.201","destination_port":443,"action":"allowed","host_name":"waf-02","violation":"none"}',
      '{"client_ip":"192.0.2.202","server_ip":"198.51.100.202","destination_port":8443,"action":"blocked","host_name":"waf-03","violation":"xss"}',
    ],
  },
  {
    family:'NAC',product:'Cisco ISE-style JSON',
    expectTargets:['srcip','dstip','action','hostname','username'],
    rows:[
      '{"source_ip":"192.0.2.210","destination_ip":"198.51.100.210","event_action":"permit","device_name":"ise-01","username":"alice","auth_method":"EAP-TLS"}',
      '{"source_ip":"192.0.2.211","destination_ip":"198.51.100.211","event_action":"deny","device_name":"ise-02","username":"bob","auth_method":"PEAP"}',
      '{"source_ip":"192.0.2.212","destination_ip":"198.51.100.212","event_action":"permit","device_name":"ise-03","username":"carol","auth_method":"EAP-TLS"}',
    ],
  },
  {
    family:'ECS',product:'ECS-style normalized security JSON',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname','timestamp'],
    rows:[
      '{"source":{"address":"192.0.2.220","port":58000},"destination":{"address":"198.51.100.220","port":443},"event":{"action":"allow","timestamp":"2026-10-16T01:00:00Z"},"host":{"name":"ecs-01"}}',
      '{"source":{"address":"192.0.2.221","port":58001},"destination":{"address":"198.51.100.221","port":22},"event":{"action":"deny","timestamp":"2026-10-16T01:00:01Z"},"host":{"name":"ecs-02"}}',
      '{"source":{"address":"192.0.2.222","port":58002},"destination":{"address":"198.51.100.222","port":53},"event":{"action":"allow","timestamp":"2026-10-16T01:00:02Z"},"host":{"name":"ecs-03"}}',
    ],
  },
  {
    family:'EDR',product:'Trend Micro-style camelCase JSON',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname','timestamp'],
    rows:[
      '{"sourceIp":"192.0.2.230","destinationIp":"198.51.100.230","sourcePort":59000,"destinationPort":443,"eventAction":"block","deviceName":"vision-01","eventTime":"2026-10-16T02:00:00Z"}',
      '{"sourceIp":"192.0.2.231","destinationIp":"198.51.100.231","sourcePort":59001,"destinationPort":80,"eventAction":"allow","deviceName":"vision-02","eventTime":"2026-10-16T02:00:01Z"}',
      '{"sourceIp":"192.0.2.232","destinationIp":"198.51.100.232","sourcePort":59002,"destinationPort":22,"eventAction":"block","deviceName":"vision-03","eventTime":"2026-10-16T02:00:02Z"}',
    ],
  },
] as const;

async function openMapping(page:Page,rows:readonly string[]){
  const sample=rows.join('\n');
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(sample);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText(rows.length+'/'+rows.length+' events analyzed locally');
  const review=page.getByRole('button',{name:'Review Detected Results'});
  await expect(review).toBeEnabled();
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  return page.getByLabel('Map Fields stage');
}

for(const scenario of cases){
  test('expanded normalization E2E · '+scenario.family+' · '+scenario.product,async({page})=>{
    await page.route('**/api/v1/parser-pairs/capabilities',route=>
      route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));

    const map=await openMapping(page,scenario.rows);
    const suggestions=map.getByLabel('Recommended field matches');
    await expect(suggestions,scenario.family+' suggestions').toBeVisible();
    for(const target of scenario.expectTargets)
      await expect(suggestions,scenario.family+' '+target).toContainText(target);

    const bulk=map.getByRole('button',{name:/Apply \d+ recommended match/});
    await expect(bulk,scenario.family+' bulk apply').toBeEnabled();
    await bulk.click();
    await expect(map.getByLabel('Field mapping checks'),scenario.family+' validation')
      .toContainText('All current field mappings passed the sample checks');
    await expect(map.getByLabel('Field changes only'),scenario.family+' comparison')
      .toBeVisible();
    await expect(map.getByRole('button',{name:'Create Parser'}),scenario.family+' create')
      .toBeEnabled();
  });
}
