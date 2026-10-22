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

const rows=(count:number)=>Array.from({length:count},(_,i)=>JSON.stringify({
  src_ip:'192.0.2.'+(i%250+1),dst_port:i%2?443:80,action:i%3?'allow':'deny',
}));

async function open(page:Page,count:number){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(rows(count).join('\n'));
}

test('exact 500-event normalization batch remains reviewable with no truncation',async({page})=>{
  await open(page,500);
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('500/500 events analyzed locally',{timeout:20000});
  await expect(page.getByLabel('Auto Parser sample limit')).toHaveCount(0);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await verifyOfficialMappings(map,['srcip','dstport','action'],'500-event limit');
});

test('501 events fail closed with an explicit beginner-readable limit explanation',async({page})=>{
  await open(page,501);
  const warning=page.getByLabel('Auto Parser sample limit');
  await expect(warning).toBeVisible();
  await expect(warning).toContainText('Use at most 500 logical events and 64 KiB');
  await expect(warning).toContainText('will not silently drop the extra events');
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText('0/501 events analyzed locally');
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
});
