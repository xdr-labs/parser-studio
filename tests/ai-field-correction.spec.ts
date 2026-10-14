import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const source=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
 '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
const holdout=[
 '{"action":"allow","src_ip":"192.0.2.10","dst_port":8443}',
 '{"action":"deny","src_ip":"192.0.2.11","dst_port":2222}',
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
function correctionRecipe(){
 return {
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'json',bodyFormat:'json',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
  stages:[
   {op:'split_event',boundary:'single-line'},{op:'parse_json'},
   {op:'map_field',source:'src_ip',target:'custom.source_address',data_type:'ip',group:'top_fields'},
   {op:'cast_type',target:'custom.source_address',data_type:'ip'},
   {op:'map_field',source:'dst_port',target:'custom.destination_port',data_type:'port',group:'ns_fields'},
   {op:'cast_type',target:'custom.destination_port',data_type:'port'},
   {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
   {op:'classify',defaultIndex:'syslog',rules:[
    {field:'custom.action',operator:'equals',value:'deny',index:'threat'},
    {field:'custom.action',operator:'equals',value:'allow',index:'session'},
   ]},
   {op:'fallback_unparsed',mode:'retain_unparsed'},
  ],nativeVerified:false,targetVerified:false,
 };
}
async function reachReview(page:import('@playwright/test').Page){
 await page.route('**/api/v1/parser-pairs/capabilities',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 if(await page.getByRole('button',{name:'Advanced'}).count())
  await page.getByRole('button',{name:'Advanced'}).click();
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByLabel('Fix Problems stage')).toBeVisible();
}
test('already parsed field correction can be rejected or explicitly applied without changing unrelated mappings',async({page})=>{
 await reachReview(page);
 await page.getByText('Paste AI Recipe for strict review').click();
 const recipe=JSON.stringify(correctionRecipe());
 const recipeBox=page.getByLabel('AI Recipe JSON');
 const holdoutBox=page.getByLabel('AI candidate holdout logs');
 await recipeBox.fill(recipe);await holdoutBox.fill(holdout);
 await page.getByLabel('Confirm independent AI holdout provenance').check();
 await page.getByRole('button',{name:'Validate Proposal (Review Only)'}).click();
 await expect(page.getByText(/Ready for explicit approval: one corrected mapping/)).toBeVisible();
 await page.getByRole('button',{name:'Reject Candidate'}).click();
 await expect(page.getByText(/AI candidate rejected by the user/)).toBeVisible();
 await expect(page.getByLabel('Suggested field mappings')).toContainText('custom.source_ip');
 await expect(page.getByLabel('Suggested field mappings')).not.toContainText('custom.source_address');

 await recipeBox.fill(recipe);await holdoutBox.fill(holdout);
 await page.getByLabel('Confirm independent AI holdout provenance').check();
 await page.getByRole('button',{name:'Validate Proposal (Review Only)'}).click();
 await page.getByLabel('Approve verified inline AI candidate').check();
 await page.getByRole('button',{name:'Apply Approved Mapping Correction'}).click();
 await expect(page.getByLabel('Suggested field mappings')).toContainText('custom.source_address');
 await expect(page.getByLabel('Suggested field mappings')).toContainText('custom.destination_port');
 await expect(page.getByLabel('Suggested field mappings')).toContainText('custom.action');
});

test('unsupported split or merge AI operators fail closed and never create a candidate',async({page})=>{
 await reachReview(page);
 await page.getByText('Paste AI Recipe for strict review').click();
 const unsafe=correctionRecipe();
 unsafe.stages.splice(2,0,{op:'split_field',source:'src_ip',delimiter:':',targets:['custom.ip','custom.port']} as never);
 await page.getByLabel('AI Recipe JSON').fill(JSON.stringify(unsafe));
 await page.getByRole('button',{name:'Validate Proposal (Review Only)'}).click();
 await expect(page.getByText(/Rejected AI proposal: UNTRUSTED_RECIPE/)).toBeVisible();
 await expect(page.getByRole('button',{name:'Reject Candidate'})).toHaveCount(0);
 await expect(page.getByLabel('Suggested field mappings')).toContainText('custom.source_ip');
});
