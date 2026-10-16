import {test,expect} from '@playwright/test';

const input=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

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

test('beginner can review official Stellar mappings, compare output and correct a target',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(input);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events analyzed locally');
  await page.getByRole('button',{name:'Review Detected Results'}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();

  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  await expect(map).toContainText('Stellar field dictionary 7.0.xs');
  await expect(map.getByLabel('Recommended field matches')).toContainText('src_ip');
  await expect(map.getByLabel('Recommended field matches')).toContainText('srcip');
  await expect(map.getByLabel('Recommended field matches')).toContainText('dstport');

  await map.getByRole('button',{name:/Apply 3 recommended matches/}).click();
  await expect(map.getByLabel('Field mapping summary')).toContainText('Matched to Stellar3');
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
  await expect(map.getByLabel('Field changes only')).toContainText('198.51.100.10');
  await expect(map.getByLabel('Field changes only')).toContainText('srcip');

  const firstTarget=map.getByLabel('Stellar field 0');
  await firstTarget.fill('not_a_stellar_field');
  await expect(map.getByLabel('Field mapping checks'))
    .toContainText('This destination is not in the checked Stellar field list');
  await expect(map.getByRole('button',{name:'Create Parser'})).toBeDisabled();

  await firstTarget.fill('srcip');
  await expect(map.getByLabel('Field mapping checks')).toContainText('All current field mappings passed the sample checks');
  await expect(map.getByRole('button',{name:'Create Parser'})).toBeEnabled();

  await map.getByRole('button',{name:'Choose Stellar field'}).first().click();
  const catalog=page.getByLabel('Stellar field chooser');
  await expect(catalog).toBeVisible();
  await catalog.getByLabel('Search Stellar field list').fill('timestamp');
  await expect(catalog).toContainText('timestamp');
  await catalog.getByRole('button',{name:'Close'}).click();

  await map.getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
});
