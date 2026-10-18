import {test,expect,type Page} from '@playwright/test';
import {verifyOfficialMappings,requireSourceMapping,requireUnappliedSourceMapping} from './normalizationAcceptance';

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

async function openMapping(page:Page,rows:string[]){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(rows.join('\n'));
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText(rows.length+'/'+rows.length+' events analyzed locally');
  await page.getByRole('button',{name:'Review Detected Results'}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  return page.getByLabel('Map Fields stage');
}

test('IPv6 source addresses remain HIGH-confidence and bulk-applicable',async({page})=>{
  const map=await openMapping(page,[
    '{"src_ip":"2001:db8::10","dst_ip":"2001:db8:1::10","dst_port":443,"action":"allow"}',
    '{"src_ip":"2001:db8::11","dst_ip":"2001:db8:1::11","dst_port":8443,"action":"deny"}',
  ]);
  await verifyOfficialMappings(map,['srcip','dstip','dstport','action'],'IPv6 boundary');
});

test('out-of-range L4 port is REVIEW-only and not silently bulk mapped',async({page})=>{
  const map=await openMapping(page,[
    '{"src_ip":"192.0.2.10","dst_port":65536,"action":"deny"}',
    '{"src_ip":"192.0.2.11","dst_port":443,"action":"allow"}',
  ]);
  const suggestions=map.getByLabel('Recommended field matches');
  await expect(suggestions).toContainText('dstport');
  await expect(suggestions).toContainText('Check first');
  // Trusted source/action aliases are already auto-applied, but one bad port
  // value must stay review-only even when the rest of the event is valid.
  await expect(map.getByRole('button',{name:'Apply 0 recommended matches'})).toBeDisabled();
  await requireSourceMapping(map,'src_ip','srcip');
  await requireUnappliedSourceMapping(map,'dst_port','dstport');
  await expect(suggestions).toContainText('dstport');
});

test('timestamp without explicit timezone is REVIEW-only, Z timestamps are HIGH',async({page})=>{
  const mixed=await openMapping(page,[
    '{"event_time":"2026-10-16T12:30:00","src_ip":"192.0.2.20"}',
    '{"event_time":"2026-10-16T12:31:00Z","src_ip":"192.0.2.21"}',
  ]);
  await expect(mixed.getByLabel('Recommended field matches')).toContainText('timestamp');
  await expect(mixed.getByLabel('Recommended field matches')).toContainText('Check first');
  await requireUnappliedSourceMapping(mixed,'event_time','timestamp');

  await page.reload();
  const good=await openMapping(page,[
    '{"event_time":"2026-10-16T12:30:00Z","src_ip":"192.0.2.20"}',
    '{"event_time":"2026-10-16T12:31:00+09:00","src_ip":"192.0.2.21"}',
  ]);
  await verifyOfficialMappings(good,['timestamp','srcip'],'timezone-qualified timestamps');
  await requireSourceMapping(good,'event_time','timestamp');
});

test('CEF alias with a non-IP value is REVIEW-only rather than falsely normalized',async({page})=>{
  const map=await openMapping(page,[
    'CEF:0|Demo|FW|1|1|Bad Source|5|src=unknown dst=198.51.100.30 dpt=443 act=deny',
    'CEF:0|Demo|FW|1|2|Good Source|5|src=192.0.2.31 dst=198.51.100.31 dpt=443 act=allow',
  ]);
  const suggestions=map.getByLabel('Recommended field matches');
  await expect(suggestions).toContainText('srcip');
  await expect(suggestions).toContainText('Check first');
  await requireUnappliedSourceMapping(map,'src','srcip');
  await requireSourceMapping(map,'dst','dstip');
});
