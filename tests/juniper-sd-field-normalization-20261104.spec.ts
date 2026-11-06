import {test,expect} from '@playwright/test';

const raw=[
  '<14>1 2019-11-14T09:37:51.184+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_CREATE '+
    '[junos@67.43.156.15 source-address="10.0.0.1" source-port="594" '+
    'destination-address="67.43.156.13" destination-port="10400" '+
    'protocol-id="1" service-name="icmp" policy-name="vpn_trust_permit-all" '+
    'username="N/A" nat-source-address="10.0.0.1" source-zone-name="vpn" destination-zone-name="trust"]',
  '<14>1 2019-11-14T09:39:51.184+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_DENY '+
    '[junos@67.43.156.15 source-address="10.0.0.2" source-port="34333" '+
    'destination-address="67.43.156.13" destination-port="443" '+
    'protocol-id="6" service-name="junos-https" policy-name="vpn_trust_permit-all" '+
    'username="N/A" nat-source-address="10.0.0.2" source-zone-name="vpn" destination-zone-name="trust"]',
].join('\n');

const cap={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],
    extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],
    rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:1024,
    leefHexSeparatorSubset:true,formatCoverage:'reviewed-bounded-subset',
    httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

test('Juniper RFC5424 novice flow maps source/destination IPs to actual Stellar names',async({page})=>{
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  const rows=await map.locator('article.normalization-map-row').evaluateAll(nodes=>
    nodes.map(node=>({
      source:(node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value,
      target:(node.querySelector('input[aria-label^="Stellar field "],input[aria-label^="Vendor field "]') as HTMLInputElement|null)?.value,
      className:node.className,
    })));
  const get=(suffix:string)=>rows.find(row=>row.source==='syslog_sd.element_1.params.'+suffix);
  expect(get('source-address')).toMatchObject({target:'srcip'});
  expect(get('destination-address')).toMatchObject({target:'dstip'});
  expect(get('protocol-id')).toMatchObject({target:'proto'});
  expect(get('policy-name')).toMatchObject({target:'rule.name'});
  for(const key of ['source-address','destination-address','protocol-id','policy-name']){
    expect(get(key)?.className).toContain('verified');
  }
  for(const key of ['source-port','destination-port','nat-source-address','service-name']){
    expect(rows.some(row=>row.source==='syslog_sd.element_1.params.'+key&&
      row.className.includes('custom'))).toBe(true);
  }
  const conditional=rows.filter(row=>row.className.includes('verified')&&
    ['srcport','dstport'].includes(row.target??''));
  expect(conditional.map(row=>row.target).sort()).toEqual(['dstport','srcport']);
  await expect(map.getByText(/Conditional official field:/)).toHaveCount(2);
  await expect(map.getByLabel('Field changes only')).toContainText('srcip');
  await expect(map.getByLabel('Field changes only')).toContainText('dstip');
  expect(errors).toEqual([]);
});
