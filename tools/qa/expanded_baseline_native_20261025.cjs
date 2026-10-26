#!/usr/bin/env node
'use strict';
// Strict controlled same-conversation baseline reuse; NOT new model grammar inference.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {chromium}=require('playwright');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const src='/home/aella/.local/state/parserstudio-expanded-security-20261025';
const raw=JSON.parse(fs.readFileSync(path.join(src,'additional-source-manifest.json')));
const scan=JSON.parse(fs.readFileSync(path.join(src,'browser-78-real-public.json')));
const map=new Map(scan.cases.map(c=>[c.id,c]));
const origin='https://app.parser.xdr.ooo';
const out=path.join(src,'baseline-reuse-e2e');
fs.mkdirSync(out,{recursive:true,mode:0o700});
const cases=raw.cases.filter(c=>map.get(c.id)?.promptMode==='BASELINE_EMBEDDED')
 .slice(0,Number(process.env.BASELINE_REUSE_MAX||1000));
const results=new Array(cases.length);
const assert=(yes,code)=>{if(!yes)throw Error(code)};
const write=(p,v)=>{fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});fs.writeFileSync(p,v,{mode:0o600});};
const flatten=(v,out=[])=>{
 if(v===null||v===undefined)return out;
 if(typeof v==='object'){Object.values(v).forEach(x=>flatten(x,out));return out}
 out.push(String(v));return out;
};
function nativeReplay(file,source,oracle){
 const ruby='/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby';
 const program="require 'json'; k=Class.new; k.class_eval(File.read(ARGV[0]),ARGV[0]); p=k.new; a=JSON.parse(STDIN.read); o=[]; a.each{|r| p.parse(r){|t,e| o<<e}}; STDOUT.write(JSON.generate(o))";
 const call=spawnSync(ruby,['-e',program,file],{
   input:JSON.stringify([source]),encoding:'utf8',timeout:25000,maxBuffer:2*1024*1024,
   shell:false,env:{PATH:'/usr/bin:/bin',HOME:'/tmp',LANG:'C.UTF-8'}});
 if(call.error||call.status!==0)return {passed:false,reason:'RUBY_PROCESS_ERROR'};
 let events;try{events=JSON.parse(call.stdout)}catch{return {passed:false,reason:'INVALID_OUTPUT_JSON'}}
 if(!Array.isArray(events)||events.length!==1||events[0]?.parser_err_msg)
  return {passed:false,reason:'INVALID_NATIVE_CALLBACK'};
 const flat=flatten(events[0]);
 const matched=oracle.filter(x=>flat.includes(x.value));
 return {passed:true,callbackCount:1,oracleTotal:oracle.length,oracleValuesMatched:matched.length,
  missingPaths:oracle.filter(x=>!flat.includes(x.value)).map(x=>x.path),eventFieldCount:flat.length,
  strictScalarLexicalMatchingOnly:true};
}
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});let pointer=0;
 async function worker(){
  const context=await browser.newContext({viewport:{width:1440,height:900},acceptDownloads:true});
  while(pointer<cases.length){
   const at=pointer++,c=cases[at],page=await context.newPage(),folder=path.join(out,c.id);
   const row={id:c.id,sampleClass:c.sampleClass,vendor:c.vendor,mode:'EMBEDDED_BASELINE_REPRODUCED',
     originalSha256:c.originalSha256,modelExternalCalls:0,
     parserFilesCreated:false,nativePassed:false,status:'START',browserErrors:[],http5xx:[],thirdParty:false};
   try{
    assert(sha(c.rawSample)===c.originalSha256,'SOURCE_MISMATCH');
    page.on('pageerror',e=>row.browserErrors.push(String(e.message).slice(0,170)));
    page.on('response',r=>{if(r.status()>=500&&r.url().startsWith(origin+'/api/'))row.http5xx.push(r.status())});
    page.on('request',r=>{try{if(/^https?:/.test(r.url())&&new URL(r.url()).origin!==origin)row.thirdParty=true}catch{}});
    await page.goto(origin+'/?workspace=chatgpt',{waitUntil:'domcontentloaded',timeout:19000});
    await page.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
    await page.getByLabel('Parser manufacturer').fill(c.vendor);
    await page.getByLabel('Parser product',{exact:true}).fill(c.product);
    await page.getByLabel('ChatGPT desired fields')
     .fill('Preserve source event fields with exact values; do not infer unsupported semantics');
    await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
    const textarea=page.getByLabel('ChatGPT copyable prompt');
    await textarea.waitFor({timeout:22000});
    const prompt=await textarea.inputValue();
    assert(sha(prompt)===map.get(c.id).promptSha256,'PROMPT_SOURCE_DIFFERS_FROM_78_E2E');
    assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),'SOURCE_ABSENT');
    const anchor=prompt.match(/----- BEGIN VALIDATED BASELINE RECIPE -----\n([\s\S]*?)\n----- END VALIDATED BASELINE RECIPE -----/);
    assert(anchor,'NO_VALIDATED_BASELINE_RECIPE');
    const recipe=JSON.parse(anchor[1]);
    assert(recipe.contract==='parser-studio.recipe.v0.2'&&recipe.sample.sha256===c.originalSha256,
      'EMBEDDED_RECIPE_WRONG_SOURCE');
    row.baselineResponseSha256=sha(JSON.stringify(recipe));
    await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(recipe));
    await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
    const accepted=page.getByLabel('ChatGPT result ready for testing');
    await accepted.waitFor({timeout:24000});
    const details=await accepted.locator('details').first().textContent();
    assert(details.includes('0 suggested mappings')&&details.includes('0 changed stages'),
     'EMBEDDED_BASELINE_DIFFERS');
    assert((await page.getByRole('button',{name:'Test Original Sample Only'}).count())===0,
     'UNEXPECTED_SAMPLE_ONLY_PATH');
    const save=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
    assert(!(await save.isDisabled()),'COMPILE_DISABLED');
    await save.click();
    const generated=page.getByLabel('ChatGPT created parser files');
    await generated.waitFor({timeout:30000});
    const downloads=[];
    for(const match of [/Download .*\.conf$/,/^Download customized_[A-Za-z0-9_]+$/]){
      const button=generated.getByRole('button',{name:match}).first();
      assert(await button.count()===1,'DOWNLOAD_BUTTON_ABSENT');
      const done=page.waitForEvent('download',{timeout:17000});
      await button.click();const file=await done;
      const bytes=fs.readFileSync(await file.path());
      assert(bytes.length>0,'EMPTY_DOWNLOAD');
      const ext=file.suggestedFilename().endsWith('.conf')?'conf':'rb';
      write(path.join(folder,'draft.'+ext),bytes);
      downloads.push({ext,bytes:bytes.length,sha256:sha(bytes)});
    }
    row.downloads=downloads;row.parserFilesCreated=downloads.length===2;
    row.native=nativeReplay(path.join(folder,'draft.rb'),c.rawSample,c.oracle);
    row.nativePassed=row.native.passed;
    row.promptSha256=sha(prompt);
    assert(!row.thirdParty&&row.browserErrors.length===0&&row.http5xx.length===0,'BROWSER_OR_NETWORK_ERROR');
    row.status=row.parserFilesCreated&&row.nativePassed?'PASS':'FAIL';
   }catch(e){row.status='FAIL';row.error=String(e).slice(0,480)}
   finally{results[at]=row;await page.close().catch(()=>{});
    const done=results.filter(Boolean).length,pass=results.filter(x=>x?.status==='PASS').length;
    console.log('BASELINE_REPLAY '+JSON.stringify({done,total:cases.length,id:row.id,
     status:row.status,native:row.native?.passed,values:row.native?.oracleValuesMatched,
     expected:row.native?.oracleTotal,error:row.error}));
    if(done%12===0||done===cases.length)
      write(path.join(out,'checkpoint.json'),JSON.stringify({cases:results.filter(Boolean)},null,2));
   }
  }
  await context.close();
 }
 try{await Promise.all(Array.from({length:3},worker))}finally{await browser.close()}
 const count=fn=>results.filter(fn).length;
 const total=fn=>results.reduce((n,x)=>n+(fn(x)||0),0);
 const summary={contract:'parserstudio.expanded-embedded-baseline-native-e2e.v1',
  sourceMode:'EMBEDDED_PREVALIDATED_BASELINE_NOT_NEW_GPT_GENERATION',
  originalVendorSemanticAccuracy:null,externalIndependentProviderSuccessRate:null,
  alreadyValidatedRecipes:cases.length,sourceCaseDistinct:cases.length,
  processed:results.length,uiAcceptedAndDrafts:count(x=>x.parserFilesCreated),
  genuineNativeCallbacks:count(x=>x.nativePassed),
  strictScalarMatches:total(x=>x.native?.oracleValuesMatched),
  strictScalarExpected:total(x=>x.native?.oracleTotal),
  successes:count(x=>x.status==='PASS'),failed:count(x=>x.status==='FAIL'),
  unwantedExternalRequests:count(x=>x.thirdParty),
  failedCases:results.filter(x=>x.status==='FAIL').map(x=>({id:x.id,reason:x.error||x.native?.reason})),
  timestamp:new Date().toISOString()};
 write(path.join(out,'summary.json'),JSON.stringify({summary,cases:results},null,2));
 console.log('BASELINE_FINAL '+JSON.stringify(summary));
 if(summary.failed)process.exitCode=1;
})().catch(e=>{console.error('BASELINE_FATAL',String(e));process.exitCode=2});
