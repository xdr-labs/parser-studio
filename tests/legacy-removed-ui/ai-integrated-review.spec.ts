import {test,expect} from '@playwright/test';

const raw=[
 '{"action":"allow","src_ip":"192.0.2.11","dst_port":443,"user":"PRIVATE_ALICE"}',
 '{"action":"deny","src_ip":"203.0.113.4","dst_port":22,"user":"SECRET_BOB"}',
].join('\n');
const parserCapability={
 contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
 authoring:{
  receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','cef','leef'],
  formatCoverage:'reviewed-bounded-subset',
  httpReceiver:false,multipleDistinctReceiverPorts:false,
  multiline:false,arbitraryRuby:false,
 },
 import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,
  structuralInspectionOnly:true},
 verification:{engineVerified:false,targetImportVerified:false,
  liveListenerVerified:false,proprietaryLoaderVerified:false},
 downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
  requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
 limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const aiCapability={
 contract:'parser-studio.ai-capabilities.v0.1',
 available:true,providerId:'public-synthetic-test-provider',
 modelId:'configured-model',
 externalTransfer:'METADATA_ONLY',
 noRawLogs:true,requiresExplicitConfirmation:true,
 requiresBudgetConfirmation:true,auditBeforeProvider:true,
 requiresServerBudgetReservation:true,maxOutputTokens:512,
 userApprovalRequired:true,nativeParserVerified:false,targetImportVerified:false,
};
async function prepared(page:import('@playwright/test').Page){
 await page.route('**/api/v1/parser-pairs/capabilities',route=>
  route.fulfill({status:200,contentType:'application/json',
   body:JSON.stringify(parserCapability)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByLabel('Review Results stage')).toBeVisible();
 const details=page.getByLabel('Optional privacy-safe AI recipe exchange');
 await details.locator('summary').first().click();
 await details.getByRole('button',{name:'Prepare Privacy-Safe AI Prompt'}).click();
 await expect(details.getByLabel('Privacy-safe AI prompt')).toContainText('SCHEMA-ONLY');
 const integrated=page.getByLabel('Optional integrated AI review');
 await integrated.locator('summary').click();
 return integrated;
}
test('P1 AP6 data-free GET then two unchecked approvals before metadata-only provider POST',async({page})=>{
 let probes=0,posts=0;
 await page.route(/\/api\/v1\/parser-pairs\/ai\/v0\.1\/(capabilities|review)$/,route=>{
  const path=new URL(route.request().url()).pathname;
  if(path.endsWith('capabilities')){
   probes++;
   expect(route.request().method()).toBe('GET');
   expect(route.request().postData()).toBeNull();
   return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(aiCapability)});
  }
  posts++;
  expect(route.request().method()).toBe('POST');
  const post=route.request().postData()!;
  expect(post).not.toContain('PRIVATE_ALICE');
  expect(post).not.toContain('SECRET_BOB');
  expect(post).not.toContain('192.0.2.11');
  expect(post).not.toContain('src_ip');
  expect(post).not.toContain('apiKey');
  const req=route.request().postDataJSON();
  expect(req.confirmedExternalTransfer).toBe(true);
  expect(req.confirmedEstimatedTokenBudget).toBe(true);
  expect(req.metadata.sourceFormat).toBe('json');
  expect(req.metadata.sampleEvents).toBe(2);
  const meta=req.metadata;
  const recipe={
   contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',
   compilerMode:'REVIEW_ONLY',projectId:meta.projectId,sourceFormat:'json',
   bodyFormat:'json',sample:{sha256:meta.sampleSha256,events:2},
   stages:[
    {op:'split_event',boundary:'single-line'},
    {op:'parse_json'},
    {op:'map_field',source:'action',target:'custom.action',
     data_type:'string',group:'top_fields'},
    {op:'classify',defaultIndex:'syslog',rules:[]},
    {op:'fallback_unparsed',mode:'retain_unparsed'},
   ],nativeVerified:false,targetVerified:false,
  };
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
   contract:'parser-studio.ai-reviewed-candidate.v0.1',recipe,
   externalTransfer:'METADATA_ONLY',
   usage:{outputTokens:74,reservedOutputTokens:512},
   userApprovalRequired:true,nativeParserVerified:false,
   targetImportVerified:false,rawLogsIncluded:false,
   providerId:aiCapability.providerId,modelId:aiCapability.modelId,
  })});
 });
 const block=await prepared(page);
 expect(probes).toBe(0);expect(posts).toBe(0);
 await block.getByRole('button',{name:/Check Configured AI Availability/}).click();
 const approves=block.getByRole('checkbox');
 await expect(approves).toHaveCount(2);
 const generate=block.getByRole('button',{name:'Request Metadata-Only Reviewed AI Candidate'});
 await expect(generate).toBeDisabled();
 expect(probes).toBe(1);expect(posts).toBe(0);
 await approves.nth(0).check();
 await expect(generate).toBeDisabled();
 await approves.nth(1).check();
 await expect(generate).toBeEnabled();
 await generate.click();
 const result=page.getByLabel('Reviewed integrated AI candidate');
 await expect(result).toContainText('REVIEW_ONLY');
 await expect(result).toContainText('Output tokens 74/512');
 for(const sensitive of ['192.0.2.11','PRIVATE_ALICE','SECRET_BOB'])
  expect(await result.innerText()).not.toContain(sensitive);
 expect(posts).toBe(1);
 await result.getByRole('button',{name:'Copy Candidate into Local Recipe Review'}).click();
 const rawRecipe=page.getByLabel('Pasted AI review-only recipe');
 await expect(rawRecipe).toHaveValue(/parser-studio\.recipe\.v0\.2/);
 await expect(page.getByLabel('Review Results stage')).toBeVisible();
 expect(posts).toBe(1);
});
test('P1 AP6 disabled endpoint cannot show approval controls or send metadata',async({page})=>{
 let count=0;
 await page.route(/\/api\/v1\/parser-pairs\/ai\/v0\.1\/(capabilities|review)$/,route=>{
  count++;
  return route.fulfill({status:403,contentType:'application/json',
   body:JSON.stringify({error:'AI_REVIEW_DISABLED'})});
 });
 const block=await prepared(page);
 await block.getByRole('button',{name:/Check Configured AI Availability/}).click();
 await expect(block).toContainText('Integrated AI is disabled or not authorized');
 await expect(block.getByRole('checkbox')).toHaveCount(0);
 await expect(block.getByRole('button',{name:'Request Metadata-Only Reviewed AI Candidate'}))
  .toHaveCount(0);
 expect(count).toBe(1);
});
