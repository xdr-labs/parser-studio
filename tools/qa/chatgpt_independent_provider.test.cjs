'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {cases,sha,providerReceipt}=require('./chatgpt_independent_benchmark.cjs');
const {prepared,verifyLiveBundle,readKey,outputText,receiptFor,requestResponse}=require('./chatgpt_independent_provider.cjs');

test('ten security cases require complete source-bound, SHA-checked preparation',()=>{
 const out=fs.mkdtempSync(path.join(os.tmpdir(),'parserstudio-api-preflight-'));
 try{
  const fixtures=cases();
  const matrix=[];
  for(const c of fixtures){
   const folder=path.join(out,c.id);
   fs.mkdirSync(folder);
   const prompt='ParserRecipe v0.2\n'+c.rawSample+'\n'+c.originalSha256;
   fs.writeFileSync(path.join(folder,'prompt-1.txt'),prompt);
   fs.writeFileSync(path.join(folder,'prompt-1.sha256'),sha(prompt)+'\n');
   fs.writeFileSync(path.join(folder,'original-source.sha256'),c.originalSha256+'\n');
   matrix.push({id:c.id,promptReady:true,promptSha256:sha(prompt),externalRequestCount:0});
  }
  const audit={pass:10,fail:0,modelInvocations:0,origin:'https://app.parser.xdr.ooo',
   pinnedBundle:'index-BwZ2Ek3z.js',cases:matrix};
  fs.writeFileSync(path.join(out,'prepare-audit.json'),JSON.stringify(audit));
  const result=prepared(fixtures,out);
  assert.equal(result.cases,10);
  assert.equal(result.modelCallsPerformed,0);
  assert.ok(result.totalPromptBytes>1000);
  fs.writeFileSync(path.join(out,fixtures[0].id,'prompt-1.sha256'),'invalid');
  assert.throws(()=>prepared(fixtures,out),/PROMPT_HASH_FILE_MISMATCH/);
 }finally{fs.rmSync(out,{recursive:true,force:true});}
});

test('current public development bundle must match the evaluated bundle before spending',async()=>{
 const good=async()=>({ok:true,text:async()=>'<script src="/assets/index-BwZ2Ek3z.js"></script>'});
 const bad=async()=>({ok:true,text:async()=>'<script src="/assets/index-other.js"></script>'});
 assert.equal(await verifyLiveBundle(good),true);
 await assert.rejects(verifyLiveBundle(bad),/LIVE_DEVELOPMENT_BUNDLE_CHANGED_REVALIDATE/);
});
test('only completed, provider-identified responses yield imported text',()=>{
 const payload={id:'resp_valid-23',model:'chat-latest',status:'completed',
  output:[{type:'reasoning',content:[]},{type:'message',content:[
   {type:'output_text',text:'{"version":"0.2"}'}]}]};
 assert.equal(outputText(payload),'{"version":"0.2"}');
 assert.equal(outputText({...payload,output:[{type:'message',content:[{type:'refusal',refusal:'Cannot assist'}]}]}),'Cannot assist');
 assert.throws(()=>outputText({...payload,id:'invalid'}),/MISSING_PROVIDER_RESPONSE_ID/);
 assert.throws(()=>outputText({...payload,status:'in_progress'}),/PROVIDER_RESPONSE_NOT_FINAL/);
 assert.throws(()=>outputText({...payload,output:[]}),/PROVIDER_RETURNED_NO_TEXT/);
});

test('provider receipt binds original prompt, output and server-issued completion ID',()=>{
 const payload={id:'resp_abc123',model:'chat-latest',status:'completed',usage:{input_tokens:120}};
 const prompt='Source preserved 01';const response='{"contract":"ParserRecipe v0.2"}';
 const receipt=receiptFor(payload,prompt,response);
 assert.equal(receipt.origin,'OPENAI_API');
 assert.equal(receipt.completionId,payload.id);
 assert.equal(receipt.storeRequested,false);
 assert.equal(receipt.promptSha256,sha(prompt));
 assert.equal(receipt.responseSha256,sha(response));
 assert.ok(providerReceipt(receipt,response,prompt));
 assert.equal(providerReceipt(receipt,response+' ',prompt),false);
});

test('private credential files only: rejects group/world access or malformed key',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'parserstudio-provider-key-'));
 const p=path.join(dir,'key');
 try{
  fs.writeFileSync(p,'sk-this_is_a_demo_testing_key_12345\n',{mode:0o600});
  assert.match(readKey(p),/^sk-/);
  fs.chmodSync(p,0o644);
  assert.throws(()=>readKey(p),/PRIVATE_KEY_FILE_MODE_REQUIRED_0600/);
  fs.chmodSync(p,0o600);
  fs.writeFileSync(p,'wrong-key');
  assert.throws(()=>readKey(p),/INVALID_KEY_FILE_CONTENT/);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('mock provider is called only with whitelisted endpoint, raw prompt, no storage',async()=>{
 const prompt='Synthetic public one-source sample';const key='sk-unit_test_only';
 let calls=0;
 const networkFetch=async(url,init)=>{
  calls++;
  assert.equal(url,'https://api.openai.com/v1/responses');
  assert.equal(init.method,'POST');
  assert.equal(init.headers.Authorization,'Bearer '+key);
  const body=JSON.parse(init.body);
  assert.equal(body.model,'chat-latest');
  assert.equal(body.input,prompt);
  assert.equal(body.store,false);
  assert.equal(body.max_output_tokens,8192);
  return {ok:true,json:async()=>({id:'resp_test-456',model:'chat-latest',status:'completed',
   output:[{type:'message',content:[{type:'output_text',text:'{"v":"0.2"}'}]}]})};
 };
 const result=await requestResponse(key,prompt,'chat-latest',networkFetch);
 assert.equal(result.answer,'{"v":"0.2"}');
 assert.equal(result.receipt.completionId,'resp_test-456');
 assert.equal(calls,1);
});

test('mock external API failure does not produce synthetic provider evidence',async()=>{
 const networkFetch=async()=>({ok:false,status:401,json:async()=>({error:{code:'invalid_api_key'}})});
 await assert.rejects(requestResponse('sk-unit_test','public sample','chat-latest',networkFetch),
  /PROVIDER_HTTP_401 invalid_api_key/);
});
