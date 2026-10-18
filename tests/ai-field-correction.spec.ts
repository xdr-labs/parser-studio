import {test,expect} from '@playwright/test';

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
type EditableRecipe={
  stages:Array<{op:string;source?:string;target?:string;data_type?:string;group?:string}>;
};
/** Use the actual product-generated baseline, never an obsolete guessed mapping. */
async function baselineRecipeFromReview(page:import('@playwright/test').Page):Promise<EditableRecipe>{
  await page.context().grantPermissions(['clipboard-read','clipboard-write']);
  await page.getByRole('button',{name:'Entire Log'}).click();
  await page.getByLabel('Reviewed and redacted AI excerpt').fill('{"src_ip":"192.0.2.10"}');
  await page.getByLabel('AI correction request').fill('Change only the src_ip mapping; preserve all unrelated parsing and mapping rules.');
  await page.getByLabel('Confirm reviewed AI excerpt').check();
  await page.getByRole('button',{name:'Copy AI Prompt'}).click();
  const prompt=await page.evaluate(()=>navigator.clipboard.readText());
  const begin='BEGIN CANONICAL PARSER RECIPE\n';
  const end='\nEND CANONICAL PARSER RECIPE';
  const left=prompt.indexOf(begin),right=prompt.indexOf(end,left+begin.length);
  expect(left,'canonical baseline present in manually copied review prompt').toBeGreaterThanOrEqual(0);
  expect(right,'canonical baseline terminated').toBeGreaterThan(left);
  return JSON.parse(prompt.slice(left+begin.length,right)) as EditableRecipe;
}
function oneMappingCorrection(canonical:EditableRecipe){
  const copy=structuredClone(canonical);
  const mapping=copy.stages.find(stage=>stage.op==='map_field'&&stage.source==='src_ip');
  expect(mapping,'src_ip mapping available for a single correction').toBeTruthy();
  const oldTarget=mapping!.target!;
  expect(oldTarget).not.toBe('custom.source_address');
  mapping!.target='custom.source_address';
  const cast=copy.stages.find(stage=>stage.op==='cast_type'&&stage.target===oldTarget);
  expect(cast,'single source mapping type cast exists').toBeTruthy();
  cast!.target='custom.source_address';
  return copy;
}
async function reachReview(page:import('@playwright/test').Page){
 await page.route('**/api/v1/parser-pairs/capabilities',route=>
  route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 if(await page.getByRole('button',{name:'Advanced'}).count())
  await page.getByRole('button',{name:'Advanced'}).click();
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
}
test('already parsed field correction can be rejected or explicitly applied without changing unrelated mappings',async({page})=>{
 await reachReview(page);
 await page.getByText('Paste ChatGPT Result').click();
 const canonical=await baselineRecipeFromReview(page);
 const recipe=JSON.stringify(oneMappingCorrection(canonical));
 const recipeBox=page.getByLabel('ChatGPT JSON result');
 const holdoutBox=page.getByLabel('Additional test logs');
 await recipeBox.fill(recipe);await holdoutBox.fill(holdout);
 await page.getByLabel('Confirm different test examples').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(page.getByText(/Fix passed: one corrected mapping/)).toBeVisible();
 await page.getByRole('button',{name:'Discard Fix'}).click();
 await expect(page.getByText(/Fix discarded/)).toBeVisible();
 await expect(page.getByLabel('Review Fields stage').getByText('Current output preview')).toBeVisible();
 await expect(page.getByLabel('Review Fields stage')).toContainText('srcip');
 await expect(page.getByLabel('Review Fields stage').getByText('Current output preview').locator('..').locator('pre')).not.toContainText('custom.source_address');

 await recipeBox.fill(recipe);await holdoutBox.fill(holdout);
 await page.getByLabel('Confirm different test examples').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await page.getByLabel('Approve tested fix').check();
 await page.getByRole('button',{name:'Apply Verified Fix'}).click();
 const normalized=page.getByText('Current output preview').locator('..').locator('pre');
 await expect(normalized).toContainText('\"source_address\"');
 await expect(normalized).toContainText('\"custom\"');
 await expect(normalized).not.toContainText('\"srcip\"');
 await expect(normalized).toContainText('\"dstport\"');
 await expect(normalized).toContainText('\"action\"');
});

test('unsupported split or merge AI operators fail closed and never create a candidate',async({page})=>{
 await reachReview(page);
 await page.getByText('Paste ChatGPT Result').click();
 const unsafe=await baselineRecipeFromReview(page);
 unsafe.stages.splice(2,0,{op:'split_field',source:'src_ip',delimiter:':',targets:['custom.ip','custom.port']} as never);
 await page.getByLabel('ChatGPT JSON result').fill(JSON.stringify(unsafe));
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(page.getByText(/ChatGPT result rejected: UNTRUSTED_RECIPE/)).toBeVisible();
 await expect(page.getByRole('button',{name:'Discard Fix'})).toHaveCount(0);
 await expect(page.getByLabel('Review Fields stage')).toContainText('srcip');
 await expect(page.getByLabel('Review Fields stage')).toContainText('dstport');
});
