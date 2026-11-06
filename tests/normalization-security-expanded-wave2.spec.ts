import {test,expect,type Page} from '@playwright/test';
import {verifyOfficialMappings} from './normalizationAcceptance';

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
  {family:'EDR',product:'SentinelOne-style endpoint network JSON',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname','username'],
    rows:[
      '{"sourceIp":"192.0.2.10","destinationIp":"198.51.100.10","sourcePort":61000,"destinationPort":443,"eventAction":"block","deviceName":"s1-01","username":"alice","event_name":"Network Control"}',
      '{"sourceIp":"192.0.2.11","destinationIp":"198.51.100.11","sourcePort":61001,"destinationPort":80,"eventAction":"allow","deviceName":"s1-02","username":"bob","event_name":"Network Control"}',
      '{"sourceIp":"192.0.2.12","destinationIp":"198.51.100.12","sourcePort":61002,"destinationPort":22,"eventAction":"block","deviceName":"s1-03","username":"carol","event_name":"Network Control"}',
    ]},
  {family:'EDR',product:'Microsoft Defender-style endpoint JSON',
    expectTargets:['srcip','dstip','action','hostname','username','file_name','event_name'],
    rows:[
      '{"src_ip":"192.0.2.20","dst_ip":"198.51.100.20","action":"quarantine","hostname":"mde-01","username":"alice","file_name":"tool.exe","event_name":"MalwareDetected","event_type":"alert"}',
      '{"src_ip":"192.0.2.21","dst_ip":"198.51.100.21","action":"block","hostname":"mde-02","username":"bob","file_name":"script.ps1","event_name":"SuspiciousScript","event_type":"alert"}',
      '{"src_ip":"192.0.2.22","dst_ip":"198.51.100.22","action":"allow","hostname":"mde-03","username":"carol","file_name":"clean.exe","event_name":"FileObserved","event_type":"telemetry"}',
    ]},
  {family:'NDR',product:'Darktrace-style network detection JSON',
    expectTargets:['srcip','dstip','srcport','dstport','proto_name','severity'],
    rows:[
      '{"sourceIp":"192.0.2.30","destinationIp":"198.51.100.30","sourcePort":62000,"destinationPort":443,"proto_name":"tcp","severity":70}',
      '{"sourceIp":"192.0.2.31","destinationIp":"198.51.100.31","sourcePort":62001,"destinationPort":53,"proto_name":"udp","severity":35}',
      '{"sourceIp":"192.0.2.32","destinationIp":"198.51.100.32","sourcePort":62002,"destinationPort":22,"proto_name":"tcp","severity":85}',
    ]},
  {family:'NDR',product:'Vectra-style detection JSON',
    expectTargets:['srcip','dstip','hostname','severity','event_name'],
    rows:[
      '{"sourceAddress":"192.0.2.40","destinationAddress":"198.51.100.40","host_name":"vectra-01","severity":80,"event_name":"Command and Control"}',
      '{"sourceAddress":"192.0.2.41","destinationAddress":"198.51.100.41","host_name":"vectra-02","severity":50,"event_name":"Reconnaissance"}',
      '{"sourceAddress":"192.0.2.42","destinationAddress":"198.51.100.42","host_name":"vectra-03","severity":20,"event_name":"Policy"}',
    ]},
  {family:'DNS Security',product:'Cisco Umbrella-style DNS JSON',
    expectTargets:['srcip','action','hostname','username'],
    rows:[
      '{"client_ip":"192.0.2.50","action":"blocked","hostname":"dns-client-01","username":"alice","event_type":"dns","query":"bad.example.invalid"}',
      '{"client_ip":"192.0.2.51","action":"allowed","hostname":"dns-client-02","username":"bob","event_type":"dns","query":"good.example.invalid"}',
      '{"client_ip":"192.0.2.52","action":"blocked","hostname":"dns-client-03","username":"carol","event_type":"dns","query":"sink.example.invalid"}',
    ]},
  {family:'WAF',product:'Imperva-style CEF',
    expectTargets:['srcip','dstip','dstport','action','url'],
    rows:[
      'CEF:0|Imperva|WAF|1|100|SQL Injection|9|src=192.0.2.60 dst=198.51.100.60 dpt=443 act=blocked url=https://app.example.invalid/login',
      'CEF:0|Imperva|WAF|1|101|Allowed Request|2|src=192.0.2.61 dst=198.51.100.61 dpt=443 act=allowed url=https://app.example.invalid/health',
      'CEF:0|Imperva|WAF|1|102|XSS|8|src=192.0.2.62 dst=198.51.100.62 dpt=8443 act=blocked url=https://app.example.invalid/search',
    ]},
  {family:'CDN/WAF',product:'Akamai-style web security JSON',
    expectTargets:['srcip','action','hostname','url','severity'],
    rows:[
      '{"client_ip":"192.0.2.70","action":"deny","host_name":"edge-01","url":"https://shop.example.invalid/login","severity":75}',
      '{"client_ip":"192.0.2.71","action":"allow","host_name":"edge-02","url":"https://shop.example.invalid/static","severity":10}',
      '{"client_ip":"192.0.2.72","action":"deny","host_name":"edge-03","url":"https://shop.example.invalid/api","severity":90}',
    ]},
  {family:'Firewall',product:'Sophos XG-style KV',
    expectTargets:['srcip','dstip','srcport','dstport','action','hostname','username'],
    rows:[
      'src_ip=192.0.2.80 dst_ip=198.51.100.80 src_port=63000 dst_port=443 action=drop hostname=xg-01 username=alice',
      'src_ip=192.0.2.81 dst_ip=198.51.100.81 src_port=63001 dst_port=80 action=allow hostname=xg-02 username=bob',
      'src_ip=192.0.2.82 dst_ip=198.51.100.82 src_port=63002 dst_port=53 action=allow hostname=xg-03 username=carol',
    ]},
  {family:'Firewall',product:'Juniper SRX-style KV',
    expectTargets:['srcip','dstip','srcport','dstport','action','proto_name'],
    rows:[
      'src=192.0.2.90 dst=198.51.100.90 srcport=64000 dstport=443 action=deny proto_name=tcp policy=internet-deny',
      'src=192.0.2.91 dst=198.51.100.91 srcport=64001 dstport=80 action=permit proto_name=tcp policy=web-allow',
      'src=192.0.2.92 dst=198.51.100.92 srcport=64002 dstport=53 action=permit proto_name=udp policy=dns-allow',
    ]},
  {family:'SaaS Audit',product:'Google Workspace-style audit JSON',
    expectTargets:['srcip','username','event_name'],
    rows:[
      '{"sourceIPAddress":"192.0.2.100","username":"alice@example.invalid","event_name":"login_success","event_type":"authentication"}',
      '{"sourceIPAddress":"192.0.2.101","username":"bob@example.invalid","event_name":"drive_download","event_type":"data_access"}',
      '{"sourceIPAddress":"192.0.2.102","username":"carol@example.invalid","event_name":"admin_change","event_type":"admin"}',
    ]},
  {family:'Cloud Network',product:'Azure NSG-style flow JSON',
    expectTargets:['srcip','dstip','srcport','dstport','action','proto_name'],
    rows:[
      '{"src_ip":"192.0.2.110","dst_ip":"198.51.100.110","src_port":65000,"dst_port":443,"action":"allow","proto_name":"tcp"}',
      '{"src_ip":"192.0.2.111","dst_ip":"198.51.100.111","src_port":65001,"dst_port":22,"action":"deny","proto_name":"tcp"}',
      '{"src_ip":"192.0.2.112","dst_ip":"198.51.100.112","src_port":65002,"dst_port":53,"action":"allow","proto_name":"udp"}',
    ]},
  {family:'SIEM',product:'Rapid7 InsightIDR-style normalized JSON',
    expectTargets:['srcip','dstip','srcmac','dstmac','hostname','username','action','severity'],
    rows:[
      '{"srcip":"192.0.2.120","dstip":"198.51.100.120","srcmac":"02:00:00:00:00:01","dstmac":"02:00:00:00:10:01","hostname":"idr-01","username":"alice","action":"deny","severity":65}',
      '{"srcip":"192.0.2.121","dstip":"198.51.100.121","srcmac":"02:00:00:00:00:02","dstmac":"02:00:00:00:10:02","hostname":"idr-02","username":"bob","action":"allow","severity":15}',
      '{"srcip":"192.0.2.122","dstip":"198.51.100.122","srcmac":"02:00:00:00:00:03","dstmac":"02:00:00:00:10:03","hostname":"idr-03","username":"carol","action":"deny","severity":90}',
    ]},
] as const;

async function openMapping(page:Page,rows:readonly string[]){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(rows.join('\n'));
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText(rows.length+'/'+rows.length+' events analyzed locally');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  return page.getByLabel('Map Fields stage');
}

for(const scenario of cases){
  test('expanded wave2 normalization E2E · '+scenario.family+' · '+scenario.product,async({page})=>{
    await page.route('**/api/v1/parser-pairs/capabilities',route=>
      route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
    const map=await openMapping(page,scenario.rows);
    await verifyOfficialMappings(map,scenario.expectTargets,scenario.family);
    // A producer's event category is not the Stellar 7.0 ML-job event_type.
    // Preserve this source field, but never auto-promote it to a false official target.
    if(['Microsoft Defender-style endpoint JSON','Cisco Umbrella-style DNS JSON',
      'Google Workspace-style audit JSON'].includes(scenario.product)){
      const official=await map.locator('article.normalization-map-row.verified input[aria-label^="Source field "]')
        .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
      expect(official).not.toContain('event_type');
      const vendor=await map.locator('article.normalization-map-row.custom input[aria-label^="Source field "]')
        .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
      expect(vendor).toContain('event_type');
    }
  });
}
