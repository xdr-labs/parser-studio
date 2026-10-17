import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

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

test('first-time user is guided back to the required flow after clicking ahead',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');

  await expect(page.locator('body')).toContainText('AUTO PARSER · GUIDED MODE');
  await expect(page.getByRole('button',{name:/Advanced Tools & Diagnostics/})).toContainText('Tools & Diagnostics');

  // A curious first-time user clicks ahead before adding any log.
  await page.getByRole('button',{name:/Map Fields/}).click();
  await expect(page.getByLabel('Add Logs stage')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('Start with Add Logs');

  await page.getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Add Logs stage')).toBeVisible();
  await expect(page.getByRole('status')).toContainText('Analyze the sample');

  // Context help explains the advanced tools without forcing the user into them.
  const help=page.getByRole('button',{name:'Help: When should I open Tools & Diagnostics?'});
  await help.click();
  await expect(help).toHaveAttribute('aria-expanded','true');
  await expect(page.getByRole('tooltip')).toContainText('Open this only when normal Auto Parser guidance is not enough');

  // The normal beginner surface should not expose internal implementation names.
  await expect(page.getByText('Run Local Multi-Pass Source Preview')).toHaveCount(0);
  await expect(page.getByText('Real Drain3 pattern mining')).toHaveCount(0);
  await expect(page.getByText('Native parser NOT VERIFIED')).toHaveCount(0);

  const sample=[
    '{"src_ip":"192.0.2.10","dst_ip":"198.51.100.10","dst_port":443,"action":"allow"}',
    '{"src_ip":"192.0.2.11","dst_ip":"198.51.100.11","dst_port":22,"action":"deny"}',
  ].join('\n');
  // Browser-only navigation must not depend on an unrelated live backend.
  // Source and event hashes are exact, and all source values are retained.
  const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
  const rows=sample.split('\n');
  let position=0;
  const events=rows.map((raw,index)=>{
    const startByte=position,endByte=startByte+Buffer.byteLength(raw);
    position=endByte+(index<rows.length-1?1:0);
    return {index,startByte,endByte,preview:{
      contract:'parser-studio.multipass-source-preview.v0.1',
      status:'SOURCE_PARSED',syntax:'JSON',
      sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),
      fields:JSON.parse(raw) as Record<string,unknown>,
      spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
    }};
  });
  const batch={
    contract:'parser-studio.multipass-source-batch-preview.v0.1',
    sourceSha256:sha(sample),sourceBytes:Buffer.byteLength(sample),
    eventCount:rows.length,events,
    separators:events.slice(0,-1).map(event=>({
      startByte:event.endByte,endByte:event.endByte+1,kind:'WHITESPACE',
    })),nativeVerified:false,targetVerified:false,
  };
  await page.route('**/api/v1/multipass/preview-batch',route=>{
    const requested=(route.request().postDataJSON() as {raw:string}).raw;
    expect(requested).toBe(sample);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(batch)});
  });
  await page.getByLabel('Auto Parser raw logs').fill(sample);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('2 of 2 log events parsed completely');
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled();
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();

  // Trying to jump straight to Create Parser now routes to mapping instead.
  await page.getByRole('button',{name:/Create Parser/}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await expect(page.locator('.beginner-navigation-hint')).toContainText('moved you to Map Fields');
});

test('troubleshooting tools use plain-language names and when-to-use guidance',async({page})=>{
  await page.goto('/');
  await page.getByRole('button',{name:/Advanced Tools & Diagnostics/}).click();

  await expect(page.locator('body')).toContainText('Troubleshooting tools');
  await expect(page.locator('body')).toContainText('Deeper local log analysis');
  await expect(page.locator('body')).toContainText('Check where multi-line events begin and end');
  await expect(page.locator('body')).toContainText('Group similar text logs');
  await expect(page.locator('body')).toContainText('Find a similar known log shape');
  await expect(page.locator('.beginner-tool-when')).toHaveCount(5);

  await expect(page.getByText('Run Local Multi-Pass Source Preview')).toHaveCount(0);
  await expect(page.getByText('Optional · Real Drain3 pattern mining')).toHaveCount(0);
  await expect(page.getByText('Advanced · Review Existing Parser or Project')).toHaveCount(0);
});
