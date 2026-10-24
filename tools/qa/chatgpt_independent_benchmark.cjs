#!/usr/bin/env node
'use strict';
// Replays independent external ChatGPT responses through the already-deployed
// Parser Studio Chromium UI. Never calls an LLM or sends logs to third parties.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');
const {spawnSync} = require('node:child_process');

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const fatal = message => { throw new Error(message); };
const assert = (condition,message) => { if(!condition)fatal(message); };
const sourceFile = path.resolve(__dirname,'../../evals/chatgpt/security-cases.json');
const defaultOut = path.join(os.homedir(),'.local/state/parserstudio-independent-chatgpt-qa-20261025');
const origin = 'https://app.parser.xdr.ooo';
const pinnedBundle = 'index-BwZ2Ek3z.js';
const file = (p,value) => { fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700}); fs.writeFileSync(p,value,{mode:0o600}); };
const json = p => JSON.parse(fs.readFileSync(p,'utf8'));
const flags = Object.fromEntries(process.argv.slice(3).flatMap(s=>s.startsWith('--')&&s.includes('=')?[s.slice(2).split(/=(.*)/s).slice(0,2)]:[]));
const cases = () => {
 const set=json(sourceFile);
 assert(set.contract==='parserstudio.independent-chatgpt-evaluation.cases.v1','UNKNOWN_CASES_CONTRACT');
 assert(set.cases.length===10 && new Set(set.cases.map(x=>x.id)).size===10,'CASE_COUNT_OR_DUPLICATES');
 for(const c of set.cases){
  assert(c.sampleCount===1 && c.rawSample.trim(),'ONE_SOURCE_REQUIRED '+c.id);
  assert(sha(c.rawSample)===c.originalSha256,'SOURCE_SHA_MISMATCH '+c.id);
  assert(['VENDOR_DOCUMENTED','VENDOR_DOCUMENTED_COMPACTED','PROJECT_SYNTHETIC'].includes(c.sampleClass),'UNSUPPORTED_SOURCE_CLASS');
  assert(c.provenanceUrl.startsWith('https://'),'PROVENANCE_URL_MISSING');
  assert(c.goldenSourceValues.every(x=>c.rawSample.includes(x.sourceValue)),'GOLDEN_OUTSIDE_SOURCE '+c.id);
 }
 return set.cases;
};
const score = (all,results) => {
 const finished=all.filter(c=>['SUCCESS','PARTIAL_NATIVE_VALUES','FAIL_AFTER_3','REVIEW_REQUIRED'].includes(results[c.id]?.state));
 // A submitted response without a provider receipt or failed native gate is never
 // an independently measured success. This denominator excludes none of the planned cases.
 const ready=finished.length===all.length &&
  all.every(c=>results[c.id].independentProviderReceipts === results[c.id].attemptsConsumed &&
   results[c.id].attemptsConsumed>=1 &&
   (results[c.id].state!=='SUCCESS'||(results[c.id].nativeDraftCreated===true&&results[c.id].nativeRubyPassed===true)));
 const numberOrNull=n=>ready?n:null;
 const success=all.filter(c=>results[c.id]?.state==='SUCCESS');
 const allExpected=all.reduce((n,c)=>n+c.goldenSourceValues.length,0);
 const matched=all.reduce((n,c)=>n+(results[c.id]?.goldenSourceValueMatches||0),0);
 const semanticDone=all.every(c=>typeof results[c.id]?.humanValidatedSemanticCorrect==='number' &&
   typeof results[c.id]?.humanValidatedSemanticTotal==='number');
 const semanticTotal=all.reduce((n,c)=>n+(results[c.id]?.humanValidatedSemanticTotal||0),0);
 const semanticCorrect=all.reduce((n,c)=>n+(results[c.id]?.humanValidatedSemanticCorrect||0),0);
 const byFamily={};
 for(const c of all){const k=c.family;if(!byFamily[k])byFamily[k]={planned:0,completed:0,success:0};
  byFamily[k].planned++;if(finished.some(x=>x.id===c.id))byFamily[k].completed++;
  if(results[c.id]?.state==='SUCCESS')byFamily[k].success++;
 }
 return {
  contract:'parserstudio.independent-chatgpt-evaluation.summary.v1',
  provenanceLevel:ready?'PROVIDER_RESPONSES_RECORDED_AND_UI_REPLAYED':'NO_COMPLETE_INDEPENDENT_PROVIDER_EVIDENCE',
  plannedCases:all.length,documentedCases:all.filter(c=>c.sampleClass==='VENDOR_DOCUMENTED').length,
  explicitlySyntheticCases:all.filter(c=>c.sampleClass==='PROJECT_SYNTHETIC').length,
  completeCases:finished.length,providerVerified:false,
  // Web receipt metadata is operator-attested, never a cryptographic proof.
  providerEvidence:'User-supplied response text and signed-in conversation/API IDs; operator-attested',
  firstResponseSuccessRate:numberOrNull(success.filter(c=>results[c.id].successAttempt===1).length/all.length),
  secondCumulativeSuccessRate:numberOrNull(success.filter(c=>results[c.id].successAttempt<=2).length/all.length),
  thirdCumulativeSuccessRate:numberOrNull(success.filter(c=>results[c.id].successAttempt<=3).length/all.length),
  sourceValueRecall:numberOrNull(allExpected?matched/allExpected:0),
  semanticAccuracy:numberOrNull(semanticDone&&semanticTotal?semanticCorrect/semanticTotal:null),
  originalPreservedRate:numberOrNull(all.filter(c=>results[c.id]?.sourcePreserved===true).length/all.length),
  nativeDraftCreationRate:numberOrNull(all.filter(c=>results[c.id]?.nativeDraftCreated===true).length/all.length),
  regressionCount:ready&&all.every(c=>results[c.id].regressionVerified===true)
   ?all.reduce((n,c)=>n+(results[c.id]?.regressions||0),0):null,
  perFamily:byFamily,
  note:ready?'Source-only qualification; never interpret this as independent holdout or Stellar 7.0 target readiness':
  'UNMEASURED: no denominator-complete independent ChatGPT completion set. No zero-percent claim.'
 };
};
const providerReceipt = (receipt,response,prompt) => {
 if(!receipt||!response)return false;
 if(!['CHATGPT_WEB_SIGNED_IN','OPENAI_API'].includes(receipt.origin))return false;
 if(receipt.responseSha256!==sha(response)||receipt.promptSha256!==sha(prompt))return false;
 if(!receipt.model||!receipt.recordedAt||!receipt.operatorAttestation)return false;
 if(receipt.origin==='CHATGPT_WEB_SIGNED_IN'){
  if(!/^https:\/\/chatgpt\.com\/(c\/|share\/)/.test(receipt.conversationUrl||''))return false;
 }else if(!/^[\w-]+$/.test(receipt.completionId||''))return false;
 return true;
};
async function launch(){
 let chromium;
 if(process.env.PLAYWRIGHT_PACKAGE){({chromium}=require(process.env.PLAYWRIGHT_PACKAGE));}
 else{try{({chromium}=require('playwright'));}
  catch{({chromium}=require('/home/aella/parser-studio-adaptive-ai-repair-20261024/node_modules/playwright'));}}

 return chromium.launch({headless:true,args:['--no-sandbox']});
}
async function makePage(browser){
 const context=await browser.newContext({viewport:{width:1440,height:900},
  permissions:['clipboard-read','clipboard-write'],acceptDownloads:true});
 const page=await context.newPage();
 const unauthorized=[];
 page.on('request',q=>{
  try {const u=new URL(q.url()); if(['https:','http:'].includes(u.protocol)&&u.origin!==origin)unauthorized.push(u.origin);}catch{}
 });
 await page.goto(origin+'/?workspace=chatgpt',{waitUntil:'domcontentloaded',timeout:20000});
 const script=await page.locator('script[type=module][src]').first().getAttribute('src');
 assert(script.includes(pinnedBundle),'DEV_RELEASE_CHANGED_REVALIDATE_BUNDLE');
 await page.getByLabel('ChatGPT local sample logs').waitFor();
 return {page,context,unauthorized};
}
async function prepare(page,c){
 await page.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
 await page.getByLabel('ChatGPT solution vendor').fill(c.publisher);
 await page.getByLabel('ChatGPT solution product').fill(c.product);
 if(c.productVersion)await page.getByLabel('ChatGPT solution version or model').fill(c.productVersion);
 await page.getByLabel('ChatGPT log source or delivery').fill('Public documentation fixture; source transport not attested');
 await page.getByLabel('ChatGPT desired fields').fill(c.desiredFields.slice(0,512));
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const promptField=page.getByLabel('ChatGPT copyable prompt');
 await promptField.waitFor({timeout:20000});
 const prompt=await promptField.inputValue();
 assert(prompt.includes(c.rawSample),'RAW_SAMPLE_NOT_EXACT');
 assert(prompt.includes(c.originalSha256),'PROMPT_SOURCE_SHA_MISSING');
 assert(prompt.includes('ParserRecipe v0.2'),'CONTRACT_NOT_IN_PROMPT');
 const count=prompt.match(/"sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)/);
 assert(count&&count[1]===c.originalSha256&&count[2]==='1','NOT_EXACTLY_ONE_SOURCE_EVENT');
 return prompt;
}
function resultsFor(c,out){const p=path.join(out,c.id,'result.json');
 return fs.existsSync(p)?json(p):undefined;}
async function modePrepare(all,out){
 const browser=await launch();const matrix=[];
 try{
 for(const c of all){
  const item={id:c.id,sha256:c.originalSha256,sampleClass:c.sampleClass,promptReady:false};
  let session;
  try{
   session=await makePage(browser);
   const prompt=await prepare(session.page,c);
   const folder=path.join(out,c.id);
   file(path.join(folder,'prompt-1.txt'),prompt);
   file(path.join(folder,'prompt-1.sha256'),sha(prompt)+'\n');
   file(path.join(folder,'original-source.sha256'),c.originalSha256+'\n');
   item.promptReady=true;item.promptSha256=sha(prompt);
   item.externalRequestCount=session.unauthorized.length;
   item.promptLength=Buffer.byteLength(prompt,'utf8');
   assert(session.unauthorized.length===0,'UNEXPECTED_EXTERNAL_EGRESS');
  }catch(e){item.error=String(e).slice(0,450);}
  finally{if(session)await session.context.close();}
  matrix.push(item);console.log('PREPARE',c.id,item.promptReady?'PASS':'FAIL',item.error||'');
 }
 }finally{await browser.close();}
 file(path.join(out,'prepare-audit.json'),JSON.stringify({origin,pinnedBundle,cases:matrix,
  pass:matrix.filter(x=>x.promptReady).length,fail:matrix.filter(x=>!x.promptReady).length,
  modelInvocations:0},null,2)+'\n');
 assert(matrix.every(x=>x.promptReady),'ONE_OR_MORE_PROMPTS_FAILED');
}
function flatten(node,output=[]){
 if(node===null||node===undefined)return output;
 if(Array.isArray(node)){node.forEach(x=>flatten(x,output));return output;}
 if(typeof node==='object'){Object.values(node).forEach(x=>flatten(x,output));return output;}
 output.push(String(node));return output;
}
function verifyNativeRuby(artifact,source,expected){
 const pinnedRuby='/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby';
 const ruby=process.env.RUBY_BIN||(fs.existsSync(pinnedRuby)?pinnedRuby:'ruby');
 const program="require 'json'; k=Class.new; k.class_eval(File.read(ARGV[0]),ARGV[0]); parser=k.new; input=JSON.parse(STDIN.read); output=[]; input.each{|row| parser.parse(row){|time,event| output<<event }}; STDOUT.write(JSON.generate(output))";
 const result=spawnSync(ruby,['-e',program,artifact],{
  input:JSON.stringify([source]),encoding:'utf8',timeout:20000,maxBuffer:2*1024*1024,
  env:{PATH:'/usr/bin:/bin',HOME:os.tmpdir(),LANG:'C.UTF-8'},shell:false
 });
 const detail={exitCode:result.status,timeout:result.error?.code==='ETIMEDOUT',
  stderr:String(result.stderr||'').slice(-1000),callbackCount:0,lexicalMatched:0,
  expectedCount:expected.length,missedPaths:[],passed:false};
 if(result.status!==0||result.error)return detail;
 let rows;
 try{rows=JSON.parse(result.stdout);}catch{return detail;}
 if(!Array.isArray(rows)||rows.length!==1||rows[0]?.parser_err_msg)return detail;
 detail.callbackCount=rows.length;
 // Exact scalar equality, not substring containment of a full raw event.
 const values=flatten(rows[0]);
 detail.missedPaths=expected.filter(g=>!values.includes(g.sourceValue)).map(g=>g.sourcePath);
 detail.lexicalMatched=expected.length-detail.missedPaths.length;
 detail.passed=detail.missedPaths.length===0;
 return detail;
}
async function modeReplay(all,out){
 const browser=await launch();
 try{
 for(const c of all){
  const folder=path.join(out,c.id);
  const entry={id:c.id,state:'WAITING_PROVIDER',attemptsConsumed:0,independentProviderReceipts:0,
   successAttempt:null,sourcePreserved:false,nativeDraftCreated:false,
   goldenSourceValueMatches:0,regressions:null,regressionVerified:false,
   nativeRubyPassed:false,modelCallsPerformedByThisTool:0,
   evidenceLevel:'NOT_INDEPENDENT_HOLDOUT',provenance:'OPERATOR_ATTESTED'};
  let session;
  try{
   session=await makePage(browser);
   const {page}=session;
   let prompt=await prepare(page,c);
   for(let n=1;n<=3;n++){
    const cached=path.join(folder,'prompt-'+n+'.txt');
    if(fs.existsSync(cached))assert(fs.readFileSync(cached,'utf8')===prompt,'STALE_CAPTURED_PROMPT '+n);
    else file(cached,prompt);
    entry.sourcePreserved=prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256);
    const responsePath=path.join(folder,'response-'+n+'.txt');
    const receiptPath=path.join(folder,'receipt-'+n+'.json');
    if(!fs.existsSync(responsePath)){entry.state='WAITING_PROVIDER';entry.nextAttempt=n;break;}
    const response=fs.readFileSync(responsePath,'utf8');
    const receipt=fs.existsSync(receiptPath)?json(receiptPath):null;
    if(!providerReceipt(receipt,response,prompt)){entry.state='PROVENANCE_MISSING';entry.nextAttempt=n;break;}
    entry.attemptsConsumed++;entry.independentProviderReceipts++;
    await page.getByLabel('ChatGPT result JSON').fill(response);
    await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
    await Promise.race([
     page.getByLabel('ChatGPT result ready for testing').waitFor({timeout:20000}).catch(()=>{}),
     page.getByLabel('ChatGPT adaptive repair').waitFor({timeout:20000}).catch(()=>{}),
     page.getByText('Three attempts reached.',{exact:false}).waitFor({timeout:20000}).catch(()=>{})
    ]);
    const accepted=await page.getByLabel('ChatGPT result ready for testing').count()>0;
    if(accepted){
     const check=page.getByRole('button',{name:'Test Original Sample Only'});
     if(await check.count()===0){entry.state='SAMPLE_PATH_UNAVAILABLE';break;}
     await check.click();
     const report=page.getByLabel('ChatGPT fix test result');
     await report.waitFor({timeout:25000});
     const reportText=await report.innerText();
     file(path.join(folder,'attempt-'+n+'-web-report.txt'),reportText);
     entry.regressionVerified=reportText.includes('Original logs still pass: YES')||reportText.includes('Original logs still pass: NO');
     entry.regressions=reportText.includes('Original logs still pass: NO')?1:0;
     if(reportText.includes('SAMPLE PASS (NOT GENERALIZED)')){
      const details=report.getByText('Review actual extracted fields before approval');
      await details.click();
      const raw=await report.locator('pre').first().innerText();
      file(path.join(folder,'attempt-'+n+'-field-preview.json'),raw);
      const preview=JSON.parse(raw);
      // Only parsed/normalized values count. The original sourceLine is not extraction.
      const observed=flatten(preview.flatMap(x=>[x.extracted,x.normalized]));
      entry.goldenSourceValueMatches=c.goldenSourceValues.filter(x=>observed.includes(x.sourceValue)).length;
      await page.getByLabel('Approve sample-only draft').check();
      await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
      const created=page.getByLabel('ChatGPT created parser files');
      await created.waitFor({timeout:30000});
      const downloaded=[];
      for(const match of [/Download .*\.conf$/,/^Download customized_[A-Za-z0-9_]+$/]){
       const button=created.getByRole('button',{name:match}).first();
       assert(await button.count()===1,'MISSING_NATIVE_OUTPUT_BUTTON');
       const promise=page.waitForEvent('download',{timeout:15000});
       await button.click();
       const dl=await promise;
       const bytes=fs.readFileSync(await dl.path());
       assert(bytes.length>0,'EMPTY_NATIVE_ARTIFACT');
       const extension=dl.suggestedFilename().endsWith('.conf')?'conf':'rb';
       file(path.join(folder,'draft.'+extension),bytes);
       downloaded.push({name:dl.suggestedFilename(),sha256:sha(bytes),bytes:bytes.length});
      }
      entry.downloaded=downloaded;
      entry.nativeDraftCreated=downloaded.length===2;
      const native=verifyNativeRuby(path.join(folder,'draft.rb'),c.rawSample,c.goldenSourceValues);
      entry.native= native;
      entry.nativeRubyPassed=native.passed;
      entry.state=entry.nativeDraftCreated&&native.passed?'SUCCESS':'PARTIAL_NATIVE_VALUES';
      entry.successAttempt=entry.state==='SUCCESS'?n:null;
      break;
     }
    }
    if(n===3){entry.state='FAIL_AFTER_3';break;}
    const next=page.getByRole('button',{name:'Copy Improved Prompt · Attempt '+(n+1)+' of 3'});
    if(await next.count()!==1){entry.state='REVIEW_REQUIRED';break;}
    await next.click();
    prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
    assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),'RETRY_LOST_ORIGINAL');
    file(path.join(folder,'prompt-'+(n+1)+'.txt'),prompt);
    entry.nextAttempt=n+1;
   }
   assert(session.unauthorized.length===0,'UNEXPECTED_EXTERNAL_EGRESS');
  }catch(e){entry.error=String(e).slice(0,700);entry.state='REPLAY_ERROR';}
  finally{
   file(path.join(folder,'result.json'),JSON.stringify(entry,null,2)+'\n');
   console.log('REPLAY',entry.id,entry.state,'attempts',entry.attemptsConsumed);
   if(session)await session.context.close();
  }
 }
 }finally{await browser.close();}
}
function modeScore(all,out){
 const results=Object.fromEntries(all.map(c=>[c.id,resultsFor(c,out)]));
 const summary=score(all,results);
 file(path.join(out,'benchmark-summary.json'),JSON.stringify(summary,null,2)+'\n');
 console.log(JSON.stringify(summary,null,2));
}
async function main(){
 const action=process.argv[2];
 assert(['prepare','replay','score'].includes(action),'USAGE: node tools/qa/chatgpt_independent_benchmark.cjs prepare|replay|score [--out=/absolute/path]');
 const out=flags.out?path.resolve(flags.out):defaultOut;
 const all=cases();
 if(action==='score')modeScore(all,out);
 else if(action==='prepare')await modePrepare(all,out);
 else await modeReplay(all,out);
}
if(require.main===module)main().catch(e=>{console.error('BENCHMARK_ERROR',String(e));process.exitCode=1;});
module.exports={sha,cases,score,providerReceipt,flatten,verifyNativeRuby};
