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
    family:'EDR',
    product:'CrowdStrike-style endpoint network event',
    expectTargets:['srcip','dstip','dstport','hostname','action'],
    sample:[
      '{"event_simpleName":"NetworkConnectIP4","src_ip":"192.0.2.10","dst_ip":"198.51.100.20","dst_port":443,"hostname":"edr-01","action":"blocked"}',
      '{"event_simpleName":"NetworkConnectIP4","src_ip":"192.0.2.11","dst_ip":"198.51.100.21","dst_port":8443,"hostname":"edr-02","action":"allowed"}',
    ].join('\n'),
  },
  {
    family:'XDR',
    product:'Cortex-style nested network event',
    expectTargets:['srcip','dstip','srcport','dstport','hostname','action'],
    sample:[
      '{"event":{"action":"alert"},"source":{"ip":"192.0.2.30","port":51000},"destination":{"ip":"203.0.113.30","port":443},"host":{"name":"xdr-01"}}',
      '{"event":{"action":"allow"},"source":{"ip":"192.0.2.31","port":51001},"destination":{"ip":"203.0.113.31","port":8443},"host":{"name":"xdr-02"}}',
    ].join('\n'),
  },
  {
    family:'NDR',
    product:'Zeek-style flow event',
    expectTargets:['srcip','dstip','srcport','dstport','proto_name'],
    sample:[
      '{"source":{"ip":"192.0.2.40","port":53000},"destination":{"ip":"198.51.100.40","port":53},"proto_name":"udp"}',
      '{"source":{"ip":"192.0.2.41","port":53001},"destination":{"ip":"198.51.100.41","port":443},"proto_name":"tcp"}',
    ].join('\n'),
  },
  {
    family:'EPP',
    product:'Defender-style endpoint prevention event',
    expectTargets:['srcip','dstip','hostname','action'],
    sample:[
      '{"src_ip":"192.0.2.50","dst_ip":"203.0.113.50","hostname":"epp-01","action":"quarantine"}',
      '{"src_ip":"192.0.2.51","dst_ip":"203.0.113.51","hostname":"epp-02","action":"block"}',
    ].join('\n'),
  },
  {
    family:'AWS',
    product:'CloudTrail-style audit event',
    expectTargets:['srcip'],
    sample:[
      '{"eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.60","awsRegion":"ap-northeast-2","userIdentity":{"type":"IAMUser"}}',
      '{"eventName":"AssumeRole","sourceIPAddress":"203.0.113.61","awsRegion":"ap-northeast-2","userIdentity":{"type":"AssumedRole"}}',
    ].join('\n'),
  },
  {
    family:'AWS WAF',
    product:'AWS WAF-style HTTP event',
    expectTargets:['srcip','action'],
    sample:[
      '{"action":"BLOCK","httpRequest":{"clientIp":"198.51.100.70","country":"KR","uri":"/login"}}',
      '{"action":"ALLOW","httpRequest":{"clientIp":"198.51.100.71","country":"KR","uri":"/health"}}',
    ].join('\n'),
  },
  {
    family:'IPS',
    product:'Suricata-style alert event',
    expectTargets:['srcip','dstip','srcport','dstport','proto_name'],
    sample:[
      '{"event_type":"alert","src_ip":"192.0.2.80","src_port":52000,"dest_ip":"203.0.113.80","dest_port":443,"proto_name":"tcp"}',
      '{"event_type":"alert","src_ip":"192.0.2.81","src_port":52001,"dest_ip":"203.0.113.81","dest_port":53,"proto_name":"udp"}',
    ].join('\n'),
  },
  {
    family:'VPN',
    product:'FortiGate-style VPN KV event',
    expectTargets:['srcip','dstip','srcport','dstport','hostname','action'],
    sample:[
      'action=tunnel-up srcip=192.0.2.90 dstip=203.0.113.90 srcport=4500 dstport=4500 hostname=vpn-01 tunnelid=101',
      'action=tunnel-down srcip=192.0.2.91 dstip=203.0.113.91 srcport=4500 dstport=4500 hostname=vpn-02 tunnelid=102',
    ].join('\n'),
  },
] as const;

async function openMapping(page:Page,sample:string){
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(sample);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
  const review=page.getByRole('button',{name:'Review Detected Results'});
  await expect(review).toBeEnabled();
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  return page.getByLabel('Map Fields stage');
}

for(const scenario of cases){
  test('normalization Full User E2E · '+scenario.family+' · '+scenario.product,async({page})=>{
    await page.route('**/api/v1/parser-pairs/capabilities',route=>
      route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));

    const map=await openMapping(page,scenario.sample);
    const suggestions=map.getByLabel('Automatic normalization suggestions');
    await expect(suggestions,scenario.family+' suggestions').toBeVisible();
    for(const target of scenario.expectTargets)
      await expect(suggestions,scenario.family+' '+target).toContainText(target);

    const bulk=map.getByRole('button',{name:/Apply \d+ high-confidence suggestion/});
    await expect(bulk,scenario.family+' bulk apply').toBeEnabled();
    const before=await map.getByLabel('Normalization mapping summary').textContent();
    expect(before,scenario.family+' starts with generated custom mappings').toContain('Custom mappings');
    await bulk.click();

    await expect(map.getByLabel('Normalization mapping summary'),scenario.family+' official mappings')
      .not.toContainText('Official mappings0');
    await expect(map.getByLabel('Normalization validation'),scenario.family+' validation')
      .toContainText('No local mapping issues detected');
    await expect(map.getByLabel('Normalization changes only'),scenario.family+' before/after')
      .toBeVisible();
    await expect(map).toContainText('Catalog verified · target runtime not verified');

    // Result remains editable instead of auto-promoted to a target-verified state.
    await expect(map.getByRole('button',{name:'Find Stellar field'}).first()).toBeEnabled();
    await expect(map.getByRole('button',{name:'Create Parser'})).toBeEnabled();
  });
}
