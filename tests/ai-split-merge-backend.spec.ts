import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';

const source=[
 '{"action":"allow:http","src_ip":"198.51.100.10","dst_port":443}',
 '{"action":"deny:ssh","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
const holdout=[
 '{"action":"allow:https","src_ip":"192.0.2.10","dst_port":8443}',
 '{"action":"deny:rdp","src_ip":"192.0.2.11","dst_port":2222}',
].join('\n');

function recipe(includeSplit=true,includeMerge=false){
 const stages:any[]=[
  {op:'split_event',boundary:'single-line'},{op:'parse_json'},
  {op:'map_field',source:'src_ip',target:'custom.source_ip',data_type:'ip',group:'top_fields'},
  {op:'cast_type',target:'custom.source_ip',data_type:'ip'},
  {op:'map_field',source:'dst_port',target:'custom.destination_port',data_type:'port',group:'ns_fields'},
  {op:'cast_type',target:'custom.destination_port',data_type:'port'},
  {op:'map_field',source:'action',target:'custom.action',data_type:'string',group:'top_fields'},
 ];
 if(includeSplit)stages.push({op:'split_field',source:'custom.action',delimiter:':',
   targets:['custom.action_kind','custom.action_detail']});
 if(includeMerge)stages.push({op:'merge_fields',
   sources:['custom.action_kind','custom.action_detail'],delimiter:'/',target:'custom.action_joined'});
 stages.push({op:'classify',defaultIndex:'syslog',rules:[
  {field:'custom.action',operator:'equals',value:'deny',index:'threat'},
  {field:'custom.action',operator:'equals',value:'allow',index:'session'},
 ]},{op:'fallback_unparsed',mode:'retain_unparsed'});
 return {
  contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
  projectId:'draft-demo_firewall',sourceFormat:'json',bodyFormat:'json',
  sample:{sha256:createHash('sha256').update(source).digest('hex'),events:2},
  stages,nativeVerified:false,targetVerified:false,
 };
}
async function openAiRecipe(page:Page){
 const box=page.getByLabel('ChatGPT JSON result');
 if(!(await box.isVisible()))await page.getByText('Paste ChatGPT Result').click();
 await expect(box).toBeVisible();
 return box;
}
async function qualifyAndApply(page:Page,value:unknown,buttonName:string,expectedRefinement:string){
 const box=await openAiRecipe(page);
 await box.fill(JSON.stringify(value));
 await page.getByLabel('Additional test logs').fill(holdout);
 await page.getByLabel('Confirm different test examples').check();
 await page.getByRole('button',{name:'Test Proposed Fix'}).click();
 await expect(page.getByText(/Fix passed: one bounded split\/merge rule/)).toBeVisible();
 await page.getByLabel('Approve tested fix').check();
 await page.getByRole('button',{name:buttonName}).click();
 const refinements=page.getByLabel('Applied normalization refinements');
 await expect(refinements).toBeVisible();
 await expect(refinements).toContainText(expectedRefinement);
 await expect(page.getByLabel('Improve with AI')).toBeVisible();
}

test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1','Requires the exact pinned loopback backend integration job.');
test('selected-area AI approves one bounded split then merge and compiles exact v0.1/v0.2 DRAFT pair',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 if(await page.getByRole('button',{name:'Advanced'}).count())
  await page.getByRole('button',{name:'Advanced'}).click();
 await page.getByRole('button',{name:'Review Detected Results'}).click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();

 await qualifyAndApply(page,recipe(true,false),'Apply Verified Fix','Split #1');
 await qualifyAndApply(page,recipe(true,true),'Apply Verified Fix','Merge #2');

 await page.getByLabel('Review Fields stage').getByRole('button',{name:/Create Parser/}).click();
 await expect(page.getByLabel('Create Parser stage')).toBeVisible();
 const generatedResponse=page.waitForResponse(r=>r.url().endsWith('/api/v1/parser-pairs/generate')&&r.request().method()==='POST');
 await page.getByRole('button',{name:'Create Parser Files'}).click();
 expect((await generatedResponse).status()).toBe(200);
 const generated=page.getByLabel('Generated Auto Parser DRAFT pair');
 await expect(generated).toContainText('Two DRAFT files verified for SHA-256 integrity · Native NOT VERIFIED');

 await page.getByLabel('ParserRecipe v0.2 review').locator('summary').click();
 await page.getByRole('button',{name:'Review Staged Recipe'}).click();
 const reviewed=page.getByLabel('Review-only staged recipe');
 await expect(reviewed).toContainText('split_field');
 await expect(reviewed).toContainText('merge_fields');
 await expect(reviewed).not.toContainText('198.51.100.10');

 const recipeGenerated=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&
   r.request().method()==='POST');
 await page.getByRole('button',{name:'Validate and Compile Strict v0.2 DRAFT Pair'}).click();
 expect((await recipeGenerated).status()).toBe(200);
 const evidence=page.getByLabel('v0.2 exact compiler evidence');
 await expect(evidence).toContainText('v0.1 pair SHA MATCHED');
 await expect(evidence).toContainText('Native user parser NOT VERIFIED');
 await expect(evidence).toContainText('Stellar DP import NOT VERIFIED');
});
