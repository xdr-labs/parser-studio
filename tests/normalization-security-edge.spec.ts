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

async function openMap(page:Page,rows:readonly string[]){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(rows.join('\n'));
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText(rows.length+'/'+rows.length+' events analyzed locally');
  const review=page.getByRole('button',{name:'Review Detected Results'});
  await expect(review).toBeEnabled();
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  return map;
}

test('RFC5424 wrapped CEF maps body fields plus host/time without flattening source',async({page})=>{
  const rows=[
    '<165>1 2026-10-16T03:10:00Z edge-01 security 12 EV01 - CEF:0|Vendor|NGFW|1|100|Blocked|8|src=192.0.2.10 dst=198.51.100.10 spt=51000 dpt=443 act=deny',
    '<165>1 2026-10-16T03:10:01Z edge-02 security 12 EV02 - CEF:0|Vendor|NGFW|1|101|Allowed|4|src=192.0.2.11 dst=198.51.100.11 spt=51001 dpt=80 act=allow',
    '<165>1 2026-10-16T03:10:02Z edge-03 security 12 EV03 - CEF:0|Vendor|NGFW|1|102|Blocked|9|src=192.0.2.12 dst=198.51.100.12 spt=51002 dpt=22 act=deny',
  ];
  const map=await openMap(page,rows);
  const suggestions=map.getByLabel('Recommended field matches');
  for(const target of ['srcip','dstip','srcport','dstport','action','hostname','timestamp'])
    await expect(suggestions).toContainText(target);
  await map.getByRole('button',{name:/Apply \d+ recommended match/}).click();
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
  await expect(map.getByLabel('Field changes only')).toContainText('192.0.2.10');
});

test('RFC5424 wrapped LEEF maps standard body aliases',async({page})=>{
  const rows=[
    '<165>1 2026-10-16T03:11:00Z edge-11 security 12 EV11 - LEEF:2.0|Vendor|Firewall|1|100|^|src=192.0.2.20^dst=198.51.100.20^srcPort=52000^dstPort=443^action=deny',
    '<165>1 2026-10-16T03:11:01Z edge-12 security 12 EV12 - LEEF:2.0|Vendor|Firewall|1|101|^|src=192.0.2.21^dst=198.51.100.21^srcPort=52001^dstPort=80^action=allow',
    '<165>1 2026-10-16T03:11:02Z edge-13 security 12 EV13 - LEEF:2.0|Vendor|Firewall|1|102|^|src=192.0.2.22^dst=198.51.100.22^srcPort=52002^dstPort=53^action=allow',
  ];
  const map=await openMap(page,rows);
  const suggestions=map.getByLabel('Recommended field matches');
  for(const target of ['srcip','dstip','srcport','dstport','action'])
    await expect(suggestions).toContainText(target);
  await map.getByRole('button',{name:/Apply \d+ recommended match/}).click();
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
});

test('IPv6 addresses are high-confidence when runtime conversion accepts them',async({page})=>{
  const map=await openMap(page,[
    '{"src_ip":"2001:db8::10","dst_ip":"2001:db8:1::10","action":"allow"}',
    '{"src_ip":"2001:db8::11","dst_ip":"2001:db8:1::11","action":"deny"}',
    '{"src_ip":"2001:db8::12","dst_ip":"2001:db8:1::12","action":"allow"}',
  ]);
  const suggestions=map.getByLabel('Recommended field matches');
  await expect(suggestions.filter({hasText:'src_ip'})).toContainText('Recommended');
  await expect(suggestions.filter({hasText:'dst_ip'})).toContainText('Recommended');
  await map.getByRole('button',{name:/Apply \d+ recommended match/}).click();
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
});

test('timezone-less timestamp stays REVIEW and is never bulk-applied',async({page})=>{
  const map=await openMap(page,[
    '{"event_time":"2026-10-16T03:20:00","action":"allow"}',
    '{"event_time":"2026-10-16T03:20:01","action":"deny"}',
    '{"event_time":"2026-10-16T03:20:02","action":"allow"}',
  ]);
  const suggestions=map.getByLabel('Recommended field matches');
  await expect(suggestions.filter({hasText:'event_time'})).toContainText('Check first');
  const bulk=map.getByRole('button',{name:/Apply \d+ recommended match/});
  await expect(bulk).toBeEnabled();
  await bulk.click();
  await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar1');
  await expect(map.getByLabel('Source field 0')).toHaveValue('event_time');
  await expect(map.getByLabel('Stellar field 0')).toHaveValue(/^custom\./);
});

test('out-of-range L4 destination port stays REVIEW',async({page})=>{
  const map=await openMap(page,[
    'CEF:0|Vendor|FW|1|1|Bad Port|5|src=192.0.2.40 dst=198.51.100.40 dpt=65536 act=deny',
    'CEF:0|Vendor|FW|1|2|Bad Port|5|src=192.0.2.41 dst=198.51.100.41 dpt=65536 act=deny',
    'CEF:0|Vendor|FW|1|3|Bad Port|5|src=192.0.2.42 dst=198.51.100.42 dpt=65536 act=deny',
  ]);
  const dpt=map.getByLabel('Recommended field matches').filter({hasText:'dpt'});
  await expect(dpt).toContainText('dstport');
  await expect(dpt).toContainText('Check first');
});

test('severity outside documented 0-100 range stays REVIEW',async({page})=>{
  const map=await openMap(page,[
    '{"hostname":"sensor-01","severity":101,"action":"alert"}',
    '{"hostname":"sensor-02","severity":150,"action":"alert"}',
    '{"hostname":"sensor-03","severity":999,"action":"alert"}',
  ]);
  const severity=map.getByLabel('Recommended field matches').filter({hasText:'severity'});
  await expect(severity).toContainText('Check first');
});

test('array-valued source IP is preserved in extracted JSON but not falsely scalar-mapped',async({page})=>{
  const map=await openMap(page,[
    '{"sourceIPs":["192.0.2.60","198.51.100.60"],"action":"allow"}',
    '{"sourceIPs":["192.0.2.61"],"action":"deny"}',
    '{"sourceIPs":["192.0.2.62","198.51.100.62"],"action":"allow"}',
  ]);
  const suggestions=map.getByLabel('Recommended field matches');
  await expect(suggestions).not.toContainText('sourceIPs');
  await expect(map.getByText('Full selected-event comparison')).toBeVisible();
  await map.getByText('Full selected-event comparison').click();
  await expect(map).toContainText('sourceIPs');
});

test('duplicate source aliases do not create duplicate official destinations',async({page})=>{
  const map=await openMap(page,[
    '{"src":"192.0.2.70","source_ip":"192.0.2.70","action":"allow"}',
    '{"src":"192.0.2.71","source_ip":"192.0.2.71","action":"deny"}',
    '{"src":"192.0.2.72","source_ip":"192.0.2.72","action":"allow"}',
  ]);
  const suggestions=map.getByLabel('Recommended field matches');
  await expect(suggestions.getByText('srcip',{exact:true})).toHaveCount(1);
  await map.getByRole('button',{name:/Apply \d+ recommended match/}).click();
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
});
