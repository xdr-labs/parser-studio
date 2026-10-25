#!/usr/bin/env node
'use strict';
// New, provenance-labeled real-browser security corpus QA. Never invokes a model.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require('playwright');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const input=process.env.PARSER_STUDIO_EXPANDED_MANIFEST||
 '/home/aella/.local/state/parserstudio-expanded-security-20261025/additional-source-manifest.json';
const output=process.env.PARSER_STUDIO_EXPANDED_RESULTS||
 '/home/aella/.local/state/parserstudio-expanded-security-20261025/browser-78-real-public.json';
const set=JSON.parse(fs.readFileSync(input,'utf8'));
const origin='https://app.parser.xdr.ooo';
const max=Number(process.env.EXPANDED_MAX||set.cases.length);
const cases=set.cases.slice(0,max);
const begin=Date.now(),results=new Array(cases.length);
const file=(p,v)=>{fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});fs.writeFileSync(p,v,{mode:0o600});};
const assert=(cond,code)=>{if(!cond)throw Error(code)};
const flatten=(node,prefix='',out=[])=>{
 if(node===null||node===undefined)return out;
 if(Array.isArray(node)){node.forEach((x,i)=>flatten(x,prefix?prefix+'.'+i:String(i),out));return out}
 if(typeof node==='object'){Object.entries(node).forEach(([k,v])=>flatten(v,prefix?prefix+'.'+k:k,out));return out}
 out.push({path:prefix,value:String(node)});return out;
};
function exactOracle(c,previews){
 const all=previews.flatMap(p=>flatten(p.fields||{}));
 const byPath=c.oracle.map(x=>all.some(y=>y.path===x.path&&y.value===x.value));
 const byValue=c.oracle.map(x=>all.some(y=>y.value===x.value));
 return {expected:c.oracle.length,pathMatched:byPath.filter(Boolean).length,valueMatched:byValue.filter(Boolean).length,
  missed:c.oracle.filter((_,i)=>!byPath[i]).map(x=>x.path),
  actualCount:all.length,
  oracleScope:'SOURCE_LEXICAL_ONLY_NOT_SEMANTIC_VENDOR_GOLDEN'};
}
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 let pointer=0;
 async function worker(){
  const context=await browser.newContext({viewport:{width:1360,height:880},acceptDownloads:true});
  while(pointer<cases.length){
   const at=pointer++,c=cases[at],page=await context.newPage(),start=Date.now();
   const row={id:c.id,vendor:c.vendor,category:c.category,sampleClass:c.sampleClass,
    sourceSha256:c.originalSha256,sourceBytes:Buffer.byteLength(c.rawSample),status:'START',
    sourceExact:false,apiSourceHashesExact:false,noAutomaticThirdParty:true,
    browserErrors:[],backendErrors:[],promptReady:false,modelCalls:0};
   try{
    assert(sha(c.rawSample)===c.originalSha256,'MANIFEST_SHA_INVALID');
    page.on('pageerror',e=>row.browserErrors.push(String(e.message).slice(0,220)));
    page.on('request',req=>{
     try{const u=new URL(req.url());if(['http:','https:'].includes(u.protocol)&&u.origin!==origin)
      row.noAutomaticThirdParty=false;}catch{}
    });
    page.on('response',resp=>{if(resp.url().includes('/api/')&&resp.status()>=500)
      row.backendErrors.push(resp.status())});
    // Real Auto Parser user path: paste -> Analyze -> observe actual Multi-Pass API JSON.
    await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:18000});
    const textarea=page.getByLabel('Auto Parser raw logs');
    await textarea.fill(c.rawSample);
    row.sourceExact=(await textarea.inputValue())===c.rawSample;
    const req=page.waitForResponse(resp=>resp.request().method()==='POST'&&
      /^\/api\/v1\/multipass\/preview(?:-batch)?$/.test(new URL(resp.url()).pathname),
     {timeout:26000});
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const response=await req;
    row.httpStatus=response.status();
    const body=await response.json();
    const eventRows=Array.isArray(body.events)?body.events:[{preview:body}];
    const previews=eventRows.map(x=>x.preview||x);
    row.apiEvents=eventRows.length;
    row.syntax=previews.map(x=>x.syntax||'UNKNOWN');
    row.statuses=previews.map(x=>x.status||'UNKNOWN');
    row.eventHashes=previews.map(x=>x.sourceSha256||'');
    row.apiSourceHashesExact=previews.length===1&&previews[0].sourceSha256===c.originalSha256;
    row.grammarAccepted=previews.filter(x=>x.status==='SOURCE_PARSED').length;
    row.partial=previews.filter(x=>x.status==='PARTIAL').length;
    row.rawOnly=previews.filter(x=>x.status==='RAW_ONLY').length;
    row.structuredEmpty=previews.filter(x=>x.status==='STRUCTURED_EMPTY').length;
    row.missingStatuses=previews.filter(x=>!['SOURCE_PARSED','PARTIAL','RAW_ONLY','STRUCTURED_EMPTY'].includes(x.status)).length;
    row.residualCount=previews.reduce((s,x)=>s+(x.residuals?.length||0),0);
    row.issueCount=previews.reduce((s,x)=>s+(x.issues?.length||0),0);
    row.extracted=exactOracle(c,previews);
    row.beginnerSummary=(await page.getByLabel('Beginner analysis summary').innerText()).slice(0,850);
    row.reviewAvailable=await page.getByRole('button',{name:'Review Fields',exact:true}).isEnabled();
    row.sourceStillExact=(await textarea.inputValue())===c.rawSample;
    assert(row.httpStatus===200,'MULTIPASS_NON_200');
    assert(row.sourceExact&&row.sourceStillExact,'BROWSER_INPUT_CHANGED');
    assert(row.noAutomaticThirdParty,'EXTERNAL_EGRESS_DETECTED');
    assert(row.apiEvents>=1&&row.missingStatuses===0,'EVENT_ACCOUNTING_OR_UNKNOWN_STATUS');
    if(row.apiEvents===1)assert(row.apiSourceHashesExact,'PREVIEW_HASH_MISMATCH');
    // Second actual user path: manually prepare ChatGPT prompt (NO model invoked).
    await page.goto(origin+'/?workspace=chatgpt',{waitUntil:'domcontentloaded',timeout:18000});
    await page.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
    await page.getByLabel('ChatGPT solution vendor').fill(c.vendor);
    await page.getByLabel('ChatGPT solution product').fill(c.product);
    await page.getByLabel('ChatGPT desired fields').fill('Preserve source event fields with exact values; do not infer unsupported semantics');
    await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
    const promptEl=page.getByLabel('ChatGPT copyable prompt');
    await promptEl.waitFor({timeout:22000});
    const prompt=await promptEl.inputValue();
    const md=prompt.match(/"sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)/);
    row.promptReady=true;row.promptBytes=Buffer.byteLength(prompt);
    row.promptOriginalExact=prompt.includes(c.rawSample);
    row.promptHashExact=!!md&&md[1]===c.originalSha256;
    row.promptEventCount=md?Number(md[2]):null;
    row.promptMode=prompt.includes('BEGIN VALIDATED BASELINE RECIPE')?'BASELINE_EMBEDDED':
     prompt.includes('FULL_RECOVERY')?'FULL_RECOVERY':'UNCLASSIFIED';
    row.promptSha256=sha(prompt);
    assert(row.promptOriginalExact&&row.promptHashExact,'PROMPT_ORIGINAL_IDENTITY_LOST');
    assert(row.noAutomaticThirdParty,'PROMPT_EXTERNAL_EGRESS');
    if(process.env.EXPANDED_SAVE_PROMPTS==='1')
      file(path.join(path.dirname(output),'prompts',c.id+'.prompt.txt'),prompt);
    row.status='PASS';
   }catch(e){
    row.status='FAIL';row.error=String(e).slice(0,650);
   }finally{
    row.durationMs=Date.now()-start;results[at]=row;
    try{await page.close()}catch{}
    const done=results.filter(Boolean).length;
    console.log('EXPANDED_CASE '+JSON.stringify({done,total:cases.length,id:row.id,
      status:row.status,grammar:row.statuses?.join(','),body:row.syntax?.join(','),
      sourceFields:row.extracted?.actualCount,oraclePath:row.extracted?.pathMatched,
      oracleTotal:row.extracted?.expected,prompt:row.promptMode,error:row.error}));
    if(done%10===0||done===cases.length){
     const good=results.filter(x=>x?.status==='PASS').length;
     console.log('EXPANDED_PROGRESS '+JSON.stringify({done,total:cases.length,pass:good,
      fail:done-good,elapsedSec:Math.floor((Date.now()-begin)/1000)}));
     file(output+'.checkpoint',JSON.stringify({cases:results.filter(Boolean)},null,2));
    }
   }
  }
  await context.close();
 }
 try{await Promise.all(Array.from({length:3},worker))}finally{await browser.close()}
 const categories=Object.fromEntries([...new Set(results.map(x=>x.sampleClass))].map(k=>
  [k,{total:results.filter(x=>x.sampleClass===k).length,
   pass:results.filter(x=>x.sampleClass===k&&x.status==='PASS').length}]));
 const vendors=Object.fromEntries([...new Set(results.map(x=>x.vendor))].map(k=>
  [k,{total:results.filter(x=>x.vendor===k).length,
   sourceParsed:results.filter(x=>x.vendor===k&&x.statuses?.includes('SOURCE_PARSED')).length,
   partial:results.filter(x=>x.vendor===k&&x.statuses?.includes('PARTIAL')).length,
   rawOnly:results.filter(x=>x.vendor===k&&x.statuses?.includes('RAW_ONLY')).length}]));
 const count=(pred)=>results.filter(pred).length;
 const total=(map)=>results.reduce((s,x)=>s+(map(x)||0),0);
 const summary={contract:'parserstudio.expanded-security-live-browser.v1',
   testedAt:new Date().toISOString(),modelInferenceCalls:0,externalProviderSuccessRate:null,
   independentVendorFirmwareVerified:false,sourceProvenance:'vendor-documented or explicitly synthetic fixtures',
   actualBrowser:true,actualMultiPassAPI:true,actualChatGPTPromptPreparation:true,
   uniqueSecurityRecords:cases.length,uniqueSourceHashes:new Set(results.map(x=>x.sourceSha256)).size,
   totalPass:count(x=>x.status==='PASS'),totalFail:count(x=>x.status==='FAIL'),
   inputSourceExact:count(x=>x.sourceExact&&x.sourceStillExact),
   sourceHashExact:count(x=>x.apiSourceHashesExact),
   promptSourceHashExact:count(x=>x.promptReady&&x.promptOriginalExact&&x.promptHashExact),
   sourceParsed:count(x=>x.statuses?.includes('SOURCE_PARSED')),
   partial:count(x=>x.statuses?.includes('PARTIAL')),
   rawOnly:count(x=>x.statuses?.includes('RAW_ONLY')),
   structuredEmpty:count(x=>x.statuses?.includes('STRUCTURED_EMPTY')),
   observedUnknownStatus:total(x=>x.missingStatuses),
   browserPageErrors:total(x=>x.browserErrors?.length),
   backendHTTP5xx:total(x=>x.backendErrors?.length),
   unexpectedThirdPartyRequest:count(x=>!x.noAutomaticThirdParty),
   lexicalOracleExpected:total(x=>x.extracted?.expected),
   lexicalOraclePathMatched:total(x=>x.extracted?.pathMatched),
   lexicalOracleValueMatched:total(x=>x.extracted?.valueMatched),
   totalActualFieldOccurrences:total(x=>x.extracted?.actualCount),
   embeddedPrevalidatedRecipePrompts:count(x=>x.promptMode==='BASELINE_EMBEDDED'),
   newGrammarRequiredPrompts:count(x=>x.promptMode==='FULL_RECOVERY'),
   byProvenance:categories,byVendor:vendors,
   failures:results.filter(x=>x.status==='FAIL').map(x=>({id:x.id,error:x.error})),
   seconds:Math.floor((Date.now()-begin)/1000)};
 file(output,JSON.stringify({summary,cases:results},null,2));
 console.log('EXPANDED_FINAL '+JSON.stringify(summary));
 if(summary.totalFail)process.exitCode=1;
})().catch(e=>{console.error('EXPANDED_FATAL',String(e));process.exitCode=2});
