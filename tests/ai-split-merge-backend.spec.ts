import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';

// Split/merge a valid official text field. A composite vendor action such as
// allow:http must not be silently classified as an official enforcement action.
const source=[
 '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"username":"CORP:alice"}',
 '{"action":"deny","src_ip":"203.0.113.5","dst_port":22,"username":"CORP:bob"}',
].join('\n');
const holdout=[
 '{"action":"allow","src_ip":"192.0.2.10","dst_port":8443,"username":"CORP:carol"}',
 '{"action":"deny","src_ip":"192.0.2.11","dst_port":2222,"username":"CORP:dave"}',
].join('\n');

function recipe(includeSplit=true,includeMerge=false){
 const stages:any[]=[
  {op:'split_event',boundary:'single-line'},{op:'parse_json'},
  {op:'map_field',source:'action',target:'action',data_type:'string',group:'top_fields'},
  {op:'map_field',source:'src_ip',target:'srcip',data_type:'ip',group:'top_fields'},
  {op:'cast_type',target:'srcip',data_type:'ip'},
  {op:'map_field',source:'dst_port',target:'dstport',data_type:'integer',group:'top_fields'},
  {op:'cast_type',target:'dstport',data_type:'integer'},
  {op:'map_field',source:'username',target:'username',data_type:'string',group:'top_fields'},
 ];
 if(includeSplit)stages.push({op:'split_field',source:'username',delimiter:':',
   targets:['custom.username_domain','custom.username_id']});
 if(includeMerge)stages.push({op:'merge_fields',
   sources:['custom.username_domain','custom.username_id'],delimiter:'/',target:'custom.username_joined'});
 stages.push({op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'});
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

test.skip(
  process.env.PARSER_STUDIO_LIVE_BACKEND!=='1' &&
  process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Requires the explicit exact-pinned or scoped loopback authoring backend.'
);
test('current Auto Parser reviews bounded AI split and merge with independent holdouts before generating DRAFT files',async({page})=>{
 await page.goto('/');
 await page.getByLabel('Auto Parser raw logs').fill(source);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const review=page.getByRole('button',{name:'Review Fields',exact:true});
 await expect(review).toBeEnabled({timeout:20000});
 await review.click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
 await page.getByLabel('Optional AI field correction').locator('summary').click();

 await qualifyAndApply(page,recipe(true,false),'Apply Verified Fix','Split #1');
 await qualifyAndApply(page,recipe(true,true),'Apply Verified Fix','Merge #2');
 await expect(page.getByLabel('Applied normalization refinements')).toContainText('Split #1');
 await expect(page.getByLabel('Applied normalization refinements')).toContainText('Merge #2');
 await expect(page.getByLabel('Applied normalization refinements')).not.toContainText('198.51.100.10');

 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
 const create=page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'});
 await expect(create).toBeEnabled({timeout:10_000});
 await create.click();
 await expect(page.getByLabel('Create Parser stage')).toBeVisible();
 const generatedResponse=page.waitForResponse(r=>r.url().endsWith('/api/v1/parser-pairs/generate')&&r.request().method()==='POST');
 const recipeGenerated=page.waitForResponse(r=>r.url().includes('/recipe/v0.2/generate')&&r.request().method()==='POST');
 await page.getByRole('button',{name:'Create Parser Files'}).click();
 expect((await generatedResponse).status()).toBe(200);
 expect((await recipeGenerated).status()).toBe(200);
 const generated=page.getByLabel('Generated parser files');
 await expect(generated).toContainText('Parser files created successfully');
 await generated.getByLabel('Parser file verification details').locator('summary').click();
 await expect(generated.getByLabel('Parser file verification details'))
   .toContainText('Native parser runtime and Stellar Cyber target not verified');
});
