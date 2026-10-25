#!/usr/bin/env node
'use strict';
// Opt-in, security-fixture-only independent Responses API runner.
// Does not run as part of Parser Studio or its default test suite.
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {spawnSync}=require('node:child_process');
const {cases,sha,providerReceipt}=require('./chatgpt_independent_benchmark.cjs');

const runner=path.resolve(__dirname,'chatgpt_independent_benchmark.cjs');
const defaultOut=path.join(os.homedir(),'.local/state/parserstudio-independent-chatgpt-qa-20261025');
const defaultKeyFile=path.join(os.homedir(),'.config/parserstudio-qa/openai-api-key');
const endpoint='https://api.openai.com/v1/responses';
const pinnedBundle='index-BwZ2Ek3z.js';
const models=new Set(['chat-latest','gpt-6-astra','gpt-6.1-sol','gpt-6-luna']);
const finalStates=new Set(['SUCCESS','PARTIAL_NATIVE_VALUES','FAIL_AFTER_3','REVIEW_REQUIRED']);
const fail=message=>{throw new Error(message);};
const assert=(ok,message)=>{if(!ok)fail(message);};
const readJson=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const file=p=>fs.readFileSync(p,'utf8');
const fileExists=p=>fs.existsSync(p);
const safeWrite=(p,data)=>{
 fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});
 fs.writeFileSync(p,data,{encoding:'utf8',flag:'wx',mode:0o600});
};
const args=Object.fromEntries(process.argv.slice(3).flatMap(x=>
 x.startsWith('--')&&x.includes('=')?[x.slice(2).split(/=(.*)/s).slice(0,2)]:[]
));
function prepared(all,out){
 const audit=readJson(path.join(out,'prepare-audit.json'));
 assert(audit.pass===10&&audit.fail===0&&audit.modelInvocations===0,'PREPARE_NOT_FULLY_PASSED');
 assert(audit.origin==='https://app.parser.xdr.ooo'&&audit.pinnedBundle===pinnedBundle,
  'DEVELOPMENT_BUNDLE_CHANGED_REVALIDATE');
 assert(audit.cases.length===all.length,'PREPARE_CASE_COUNT_MISMATCH');
 const matrix=Object.fromEntries(audit.cases.map(x=>[x.id,x]));
 let totalPromptBytes=0;
 for(const c of all){
  assert(['VENDOR_DOCUMENTED','VENDOR_DOCUMENTED_COMPACTED','PROJECT_SYNTHETIC'].includes(c.sampleClass),
   'UNAPPROVED_CASE_CLASS '+c.id);
  assert(c.sampleCount===1&&sha(c.rawSample)===c.originalSha256,'SOURCE_CHANGED '+c.id);
  const p=path.join(out,c.id,'prompt-1.txt');
  const prompt=file(p);
  const hash=sha(prompt);
  assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),'SOURCE_NOT_PRESERVED '+c.id);
  assert(file(path.join(out,c.id,'prompt-1.sha256')).trim()===hash,'PROMPT_HASH_FILE_MISMATCH '+c.id);
  assert(file(path.join(out,c.id,'original-source.sha256')).trim()===c.originalSha256,
   'ORIGINAL_HASH_FILE_MISMATCH '+c.id);
  assert(matrix[c.id]?.promptReady===true&&matrix[c.id]?.promptSha256===hash,
   'AUDIT_PROMPT_MISMATCH '+c.id);
  assert(matrix[c.id].externalRequestCount===0,'PREPARE_EXTERNAL_EGRESS '+c.id);
  totalPromptBytes+=Buffer.byteLength(prompt,'utf8');
 }
 return {cases:all.length,modelCallsPerformed:0,totalPromptBytes};
}
async function verifyLiveBundle(networkFetch=fetch){
 const response=await networkFetch('https://app.parser.xdr.ooo/',{
  method:'GET',signal:AbortSignal.timeout(15000)
 });
 assert(response.ok,'DEVELOPMENT_SITE_UNREACHABLE');
 const html=await response.text();
 assert(html.includes('/assets/'+pinnedBundle),'LIVE_DEVELOPMENT_BUNDLE_CHANGED_REVALIDATE');
 return true;
}
function readKey(p){
 const stat=fs.statSync(p);
 assert(stat.isFile()&&(stat.mode&0o077)===0,'PRIVATE_KEY_FILE_MODE_REQUIRED_0600');
 const key=file(p).trim();
 assert(/^sk-[A-Za-z0-9_-]{12,}$/.test(key),'INVALID_KEY_FILE_CONTENT');
 return key;
}
function outputText(payload){
 assert(payload&&typeof payload==='object','MALFORMED_PROVIDER_RESPONSE');
 assert(typeof payload.id==='string'&&/^resp_[\w-]+$/.test(payload.id),'MISSING_PROVIDER_RESPONSE_ID');
 assert(['completed','incomplete'].includes(payload.status),'PROVIDER_RESPONSE_NOT_FINAL');
 let parts=[];
 for(const item of payload.output||[]){
  if(item.type==='message')for(const part of item.content||[]){
   if(part.type==='output_text'&&typeof part.text==='string')parts.push(part.text);
   if(part.type==='refusal'&&typeof part.refusal==='string')parts.push(part.refusal);
  }
 }
 if(!parts.length&&typeof payload.output_text==='string')parts=[payload.output_text];
 const content=parts.join('\n');
 assert(content.trim().length>0,'PROVIDER_RETURNED_NO_TEXT');
 return content;
}
function receiptFor(payload,prompt,response){
 return {
  origin:'OPENAI_API',
  completionId:payload.id,
  model:payload.model,
  recordedAt:new Date().toISOString(),
  promptSha256:sha(prompt),
  responseSha256:sha(response),
  operatorAttestation:'Captured directly by authorized independent Responses API runner',
  endpoint,
  providerStatus:payload.status,
  providerUsage:payload.usage||null,
  sourceClass:'PUBLIC_DOCUMENTED_OR_SYNTHETIC_TEST_FIXTURE',
  storeRequested:false
 };
}
async function requestResponse(key,prompt,model,networkFetch=fetch){
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(),180000);
 try{
  const result=await networkFetch(endpoint,{
   method:'POST',
   headers:{Authorization:'Bearer '+key,'Content-Type':'application/json'},
   body:JSON.stringify({model,input:prompt,store:false,max_output_tokens:8192}),
   signal:controller.signal
  });
  if(!result.ok){
   let errorCode='unavailable';
   try{const payload=await result.json();errorCode=String(payload?.error?.code||payload?.error?.type||'api_error').slice(0,100);}
   catch{}
   fail('PROVIDER_HTTP_'+result.status+' '+errorCode);
  }
  const payload=await result.json();
  assert(typeof payload.model==='string'&&payload.model.length>0,'PROVIDER_MODEL_MISSING');
  const answer=outputText(payload);
  const receipt=receiptFor(payload,prompt,answer);
  assert(providerReceipt(receipt,answer,prompt),'SELF_PROVENANCE_CHECK_FAILED');
  return {answer,receipt};
 }finally{clearTimeout(timer);}
}
function replay(all,out){
 const execution=spawnSync(process.execPath,[runner,'replay','--out='+out],{
  cwd:path.resolve(__dirname,'../..'),encoding:'utf8',timeout:300000,
  maxBuffer:3*1024*1024,env:{...process.env,OPENAI_API_KEY:''}
 });
 if(execution.status!==0)fail('BROWSER_REPLAY_FAILED '+String(execution.stderr||execution.error).slice(-650));
 const results=Object.fromEntries(all.map(c=>{
  const p=path.join(out,c.id,'result.json');
  return [c.id,fileExists(p)?readJson(p):null];
 }));
 const errors=all.filter(c=>['REPLAY_ERROR','PROVENANCE_MISSING'].includes(results[c.id]?.state));
 if(errors.length)fail('REPLAY_GATED_CASES '+errors.map(c=>c.id+':'+results[c.id].state).join(','));
 return results;
}
function doScore(out){
 const execution=spawnSync(process.execPath,[runner,'score','--out='+out],{
  cwd:path.resolve(__dirname,'../..'),encoding:'utf8',timeout:30000,
  env:{...process.env,OPENAI_API_KEY:''}
 });
 if(execution.status!==0)fail('BENCHMARK_SCORE_FAILED');
 const s=readJson(path.join(out,'benchmark-summary.json'));
 console.log('SCORE',JSON.stringify({
  ready:s.provenanceLevel,completed:s.completeCases,first:s.firstResponseSuccessRate,
  second:s.secondCumulativeSuccessRate,third:s.thirdCumulativeSuccessRate,
  sourceValueRecall:s.sourceValueRecall,nativeDraftRate:s.nativeDraftCreationRate
 }));
 return s;
}
async function execute(all,out,key,model){
 const log=[];
 for(let round=1;round<=3;round++){
  const current=Object.fromEntries(all.map(c=>[c.id,
   fileExists(path.join(out,c.id,'result.json'))?readJson(path.join(out,c.id,'result.json')):null]));
  let count=0;
  for(const c of all){
   const state=current[c.id];
   if(finalStates.has(state?.state))continue;
   if(round>1&&state?.nextAttempt!==round)continue;
   const folder=path.join(out,c.id);
   const promptPath=path.join(folder,'prompt-'+round+'.txt');
   assert(fileExists(promptPath),'IMPROVED_PROMPT_MISSING '+c.id+' '+round);
   const prompt=file(promptPath);
   assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),
    'IMPROVED_PROMPT_LOST_SOURCE '+c.id+' '+round);
   const responseFile=path.join(folder,'response-'+round+'.txt');
   const receiptFile=path.join(folder,'receipt-'+round+'.json');
   if(fileExists(responseFile)||fileExists(receiptFile)){
    assert(fileExists(responseFile)&&fileExists(receiptFile)&&
     providerReceipt(readJson(receiptFile),file(responseFile),prompt),
     'PARTIAL_OR_INVALID_PRIOR_PROVIDER_EVIDENCE '+c.id+' '+round);
    console.log('PROVIDER_RESUMED',c.id,round);
    continue;
   }
   console.log('PROVIDER_REQUEST',c.id,round,'public_or_synthetic_fixture');
   const answer=await requestResponse(key,prompt,model);
   safeWrite(responseFile,answer.answer);
   safeWrite(receiptFile,JSON.stringify(answer.receipt,null,2)+'\n');
   log.push({id:c.id,attempt:round,completionId:answer.receipt.completionId,
    model:answer.receipt.model,promptSha256:answer.receipt.promptSha256,
    responseSha256:answer.receipt.responseSha256});
   count++;
   console.log('PROVIDER_CAPTURED',c.id,round,answer.receipt.completionId);
  }
  console.log('ROUND_COMPLETE',round,'new_completions',count);
  const results=replay(all,out);
  const terminal=all.filter(c=>finalStates.has(results[c.id]?.state)).length;
  const distribution=Object.fromEntries([...new Set(all.map(c=>results[c.id]?.state))].map(s=>
   [s,all.filter(c=>results[c.id]?.state===s).length]));
  console.log('NATIVE_REPLAY',round,terminal+'/'+all.length,JSON.stringify(distribution));
  if(terminal===all.length)break;
 }
 const score=doScore(out);
 const report={contract:'parserstudio.independent-chatgpt-api-execution.v1',
  recordedAt:new Date().toISOString(),requestedModel:model,requestsRecorded:log.length,
  completions:log,summarySha256:sha(file(path.join(out,'benchmark-summary.json'))),
  source:'PUBLIC_DOCUMENTED_OR_SYNTHETIC_ONLY',credentialsIncluded:false};
 const reportPath=path.join(out,'api-execution-'+Date.now()+'.json');
 safeWrite(reportPath,JSON.stringify(report,null,2)+'\n');
 console.log('EXECUTION_REPORT',reportPath);
 if(score.completeCases!==10)fail('INCOMPLETE_CASES_FIX_OR_RESUME_WITH_SAME_API_MODEL');
}
async function main(){
 const action=process.argv[2];
 assert(['preflight','run'].includes(action),
  'USAGE: node tools/qa/chatgpt_independent_provider.cjs preflight|run [--out=PATH] [--model=chat-latest] [--key-file=PATH] [--execute-external-inference=yes]');
 const out=path.resolve(args.out||defaultOut);
 const all=cases();
 const audit=prepared(all,out);
 await verifyLiveBundle();
 const model=args.model||'chat-latest';
 assert(models.has(model),'MODEL_NOT_ALLOWLISTED');
 console.log('PREPARED',JSON.stringify({...audit,model,bundle:pinnedBundle}));
 if(action==='preflight')return;
 assert(args['execute-external-inference']==='yes','EXPLICIT_EXTERNAL_INFERENCE_OPT_IN_REQUIRED');
 const keyFile=path.resolve(args['key-file']||defaultKeyFile);
 const key=readKey(keyFile);
 await execute(all,out,key,model);
}
if(require.main===module)main().catch(e=>{
 console.error('PROVIDER_RUNNER_ERROR',String(e.message||e));
 process.exitCode=1;
});
module.exports={prepared,verifyLiveBundle,readKey,outputText,receiptFor,requestResponse,finalStates};
