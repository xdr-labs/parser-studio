import test from 'node:test';
import assert from 'node:assert/strict';
import type {AddressInfo} from 'node:net';
import {createBackendServer} from '../src/http.js';
import {AIReviewGateway,AIReviewGatewayError,type AIReviewConfig} from '../src/ai-review-gateway.js';
import {recipeFromLegacyProject} from '../src/parser-recipe-v02.js';
import {sampleProject} from './fixture.js';

const project=sampleProject();
project.projectId='draft-synthetic_ai';
project.classification.rules=project.classification.rules.filter(rule=>rule.operator==='equals');
const approved=recipeFromLegacyProject(project,'a'.repeat(64),2);
const metadata={
 contract:'parser-studio.ai-metadata.v0.1',projectId:approved.projectId,
 sampleSha256:approved.sample.sha256,sampleEvents:2,
 sourceFormat:'json',bodyFormat:'json',unsupported:0,
 families:[{envelope:'none',body:'json',count:2}],
};
const request={contract:'parser-studio.ai-request.v0.1',metadata,
 confirmedExternalTransfer:true,confirmedEstimatedTokenBudget:true};
const actor={tenant:'synthetic_tenant',actorId:'synthetic_owner'};
function fixture(overrides:Partial<AIReviewConfig>={}){
 const called:{prompt:string;maxOutputTokens:number}[]=[];
 const journal:string[]=[];
 let settled=0,reserved=0;
 const config:AIReviewConfig={
  providerId:'private-test-adapter',
  modelId:'review-model-fixed',
  maxOutputTokens:1024,
  authorize:async()=>actor,
  ledger:{
   reserve:async()=>{reserved++;return 'resv-01';},
   settle:async()=>{settled++;},
  },
  audit:async row=>{journal.push(row.phase);},
  provider:async input=>{
   called.push({prompt:input.prompt,maxOutputTokens:input.maxOutputTokens});
   return {recipe:structuredClone(approved),usage:{outputTokens:220}};
  },
  ...overrides,
 };
 return {config,called,journal,getReserved:()=>reserved,getSettled:()=>settled};
}
function expectNoSecrets(text:string){
 for(const secret of ['SECRET_CUSTOMER','192.0.2.15','PRIVATE_ALICE','apiKey','password='])
  assert.equal(text.includes(secret),false,'Unexpected raw secret reflected');
}
test('P1-AP6 opt-in integrated AI backend uses fixed metadata-only prompt, reserves tokens, audits then returns review-only candidate',async()=>{
 const f=fixture(),gateway=new AIReviewGateway(f.config);
 const value=await gateway.run(request,actor);
 assert.equal(f.called.length,1);
 assert.deepEqual(f.journal,['BEFORE','AFTER']);
 assert.equal(f.getReserved(),1);assert.equal(f.getSettled(),1);
 assert.equal(value.contract,'parser-studio.ai-reviewed-candidate.v0.1');
 assert.equal(value.userApprovalRequired,true);
 assert.equal(value.nativeParserVerified,false);
 assert.equal(value.targetImportVerified,false);
 assert.equal(value.externalTransfer,'METADATA_ONLY');
 assert.equal(value.recipe.sample.sha256,metadata.sampleSha256);
 assert.equal(value.usage.outputTokens,220);
 expectNoSecrets(JSON.stringify(f.called));
 expectNoSecrets(JSON.stringify(value));
});
test('P1-AP6 no consent, raw samples, unsafe metadata and unsupported draft cannot trigger provider',async()=>{
 const f=fixture(),gateway=new AIReviewGateway(f.config);
 const variants=[
  {...request,confirmedExternalTransfer:false},
  {...request,confirmedEstimatedTokenBudget:false},
  {...request,apiKey:'SECRET_CUSTOMER'},
  {...request,training:['PRIVATE_ALICE']},
  {...request,metadata:{...metadata,sourceFormat:'mixed'}},
  {...request,metadata:{...metadata,unsupported:2}},
  {...request,metadata:{...metadata,families:[{envelope:'none',body:'json',count:1}]}},
  {...request,metadata:{...metadata,projectId:null}},
  {...request,metadata:{...metadata,sampleSha256:'z'.repeat(64)}},
  {...request,metadata:{...metadata,sourceFormat:'auto'}},
 ];
 for(const item of variants)
  await assert.rejects(()=>gateway.run(item,actor),
   (e:unknown)=>e instanceof AIReviewGatewayError);
 assert.equal(f.called.length,0);
 assert.equal(f.getReserved(),0);
});
test('P1-AP6 unauthenticated, without trusted ledger/audit/provider, and provider injection are disabled',async()=>{
 const gateway=new AIReviewGateway(fixture().config);
 await assert.rejects(()=>gateway.run(request,{tenant:'../unsafe',actorId:'evil'}),
  (e:unknown)=>e instanceof AIReviewGatewayError);
 for(const override of [
  {authorize:async()=>null},
  {ledger:null},
  {audit:null},
  {provider:null},
 ]){
  const f=fixture(override as Partial<AIReviewConfig>);
  if(override.authorize){
    assert.equal(await f.config.authorize({} as never),null);
    continue;
  }
  assert.throws(()=>new AIReviewGateway(f.config),/AI_REVIEW_CONFIGURATION_DISABLED/);
 }
});
test('P1-AP6 provider errors, prompt injections and invalid v0.2 never return executable recipe',async()=>{
 const mismatched=structuredClone(approved);mismatched.sample.sha256='f'.repeat(64);
 const cases=[
  {recipe:{...approved,nativeVerified:true},usage:{outputTokens:10}},
  {recipe:{...approved,stages:[...approved.stages,{op:'execute_ruby',script:'SECRET_CUSTOMER'}]},usage:{outputTokens:10}},
  {recipe:mismatched,usage:{outputTokens:10}},
  {recipe:approved,usage:{outputTokens:9999}},
  {recipe:approved,usage:{outputTokens:NaN}},
  {recipe:'SECRET_CUSTOMER',usage:{outputTokens:10}},
 ];
 for(const result of cases){
  const f=fixture({provider:async()=>result as any});
  await assert.rejects(()=>new AIReviewGateway(f.config).run(request,actor),
    (e:unknown)=>e instanceof AIReviewGatewayError);
  assert.equal(f.getReserved(),1);
 }
});
async function served(
 options:Parameters<typeof createBackendServer>[0],
 cb:(base:string)=>Promise<void>,
){
 const server=createBackendServer(options);
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 try{await cb('http://127.0.0.1:'+(server.address() as AddressInfo).port);}
 finally{await new Promise<void>(r=>server.close(()=>r()));}
}
const route='/api/v1/parser-pairs/ai/v0.1';
async function post(base:string,body:unknown){
 return fetch(base+route+'/review',{
  method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify(body),
 });
}
test("P1-AP6 missing audit or budget reserve fails closed before external provider transfer",async()=>{
 const rows:string[]=[];
 for(const config of [
  {ledger:{reserve:async()=>{throw Error("PRIVATE_PROVIDER_KEY")},settle:async()=>{}}},
  {audit:async()=>{throw Error("PRIVATE_CUSTOMER_BODY")}},
 ]){
  const f=fixture({
   provider:async()=>{rows.push("TRANSFER_OCCURRED");return {recipe:approved,usage:{outputTokens:10}};},
   ...config,
  });
  await assert.rejects(()=>new AIReviewGateway(f.config).run(request,actor),
    (error:unknown)=>error instanceof AIReviewGatewayError &&
      !error.message.includes("PRIVATE"));
 }
 assert.deepEqual(rows,[]);
});
test("P1-AP6 post-provider usage-settlement failure does not return success",async()=>{
 const f=fixture({ledger:{
  reserve:async()=>"server-generated-reservation",
  settle:async()=>{throw Error("PRIVATE_COST_REPORT");},
 }});
 await assert.rejects(()=>new AIReviewGateway(f.config).run(request,actor),
  (e:unknown)=>e instanceof AIReviewGatewayError&&e.code==="AI_ACCOUNTING_UNAVAILABLE");
 assert.equal(f.called.length,1);
 assert.deepEqual(f.journal,["BEFORE","AFTER"]);
});
test("P1-AP6 server HTTP authorization denies metadata-only probes and review requests",async()=>{
 let providerCalls=0;
 const f=fixture({
  authorize:async req=>req.headers["x-synthetic-owner"]==="approved"?actor:null,
  provider:async()=>{
   providerCalls++;
   return {recipe:approved,usage:{outputTokens:10}};
  },
 });
 await served({aiReviewGateway:new AIReviewGateway(f.config)},async base=>{
  const cap=await fetch(base+route+"/capabilities");
  assert.equal(cap.status,403);
  assert.equal((await cap.json() as any).error,"AI_REVIEW_DENIED");
  assert.equal((await post(base,request)).status,403);
  assert.equal(providerCalls,0);
 });
});
test('P1-AP6 private HTTP auth/capability default-deny + explicit budget before metadata-only review',async()=>{
 await served(undefined,async base=>{
  const off=await fetch(base+route+'/capabilities');
  assert.equal(off.status,403);
  assert.equal((await off.json() as any).error,'AI_REVIEW_DISABLED');
  assert.equal((await post(base,request)).status,403);
 });
 const f=fixture();
 const gateway=new AIReviewGateway(f.config);
 await served({aiReviewGateway:gateway},async base=>{
  const cap=await fetch(base+route+'/capabilities');
  assert.equal(cap.status,200);
  const body=await cap.json() as any;
  assert.equal(body.externalTransfer,'METADATA_ONLY');
  assert.equal(body.noRawLogs,true);
  assert.equal(body.maxOutputTokens,1024);
  assert.equal(body.userApprovalRequired,true);
  assert.equal(body.nativeParserVerified,false);
  const generated=await post(base,request);
  assert.equal(generated.status,200);
  const reply=await generated.json() as any;
  assert.equal(reply.recipe.projectId,project.projectId);
  assert.equal(reply.userApprovalRequired,true);
  expectNoSecrets(JSON.stringify(reply));
  const wrong=await post(base,{...request,apiKey:'SECRET_CUSTOMER'});
  assert.equal(wrong.status,422);
  expectNoSecrets(await wrong.text());
 });
});
