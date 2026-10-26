#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require('playwright'),{spawnSync}=require('node:child_process');
const root='/home/aella/.local/state/parserstudio-expanded-security-20261025';
const out=path.join(root,'new-grammar-recovery');
const source=JSON.parse(fs.readFileSync(path.join(root,'additional-source-manifest.json')));
const audit=JSON.parse(fs.readFileSync(path.join(root,'browser-78-real-public.json')));
const modes=new Map(audit.cases.map(x=>[x.id,x]));
const cases=source.cases.filter(c=>modes.get(c.id).promptMode==='FULL_RECOVERY');
const results=new Array(cases.length),origin='https://app.parser.xdr.ooo';
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const assert=(c,r)=>{if(!c)throw Error(r)};
const read=p=>fs.readFileSync(p,'utf8');
const write=(p,bytes)=>{fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});fs.writeFileSync(p,bytes,{mode:0o600})};
const flatten=(x,a=[])=>{
 if(x===null||x===undefined)return a;
 if(typeof x==='object'){Object.values(x).forEach(y=>flatten(y,a));return a}
 a.push(String(x));return a;
};
function runNative(rb,raw){
 const bin='/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby';
 const body="require 'json'; k=Class.new; k.class_eval(File.read(ARGV[0]),ARGV[0]); p=k.new; v=JSON.parse(STDIN.read); a=[];v.each{|r|p.parse(r){|t,e|a<<e}};STDOUT.write(JSON.generate(a))";
 const p=spawnSync(bin,['-e',body,rb],{input:JSON.stringify([raw]),encoding:'utf8',timeout:20000,
  maxBuffer:2*1024*1024,shell:false,env:{HOME:'/tmp',PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}});
 if(p.error||p.status!==0)return {valid:false,reason:'RUBY_EXECUTION_FAILURE'};
 let events;try{events=JSON.parse(p.stdout)}catch{return {valid:false,reason:'RUBY_OUTPUT_NOT_JSON'}};
 if(!Array.isArray(events)||events.length!==1||events[0]?.parser_err_msg)
  return {valid:false,reason:'RUBY_CALLBACK_MISSING_OR_PARSER_ERROR'};
 return {valid:true,eventCount:1,scalarCount:flatten(events[0]).length,
  // No source values or sensitive event content exported to shared Git logs.
  outputSha256:sha(p.stdout)};
}
async function handle(page,c,rootFolder,row){
 await page.goto(origin+'/?workspace=chatgpt',{waitUntil:'domcontentloaded',timeout:18000});
 await page.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
 await page.getByLabel('Parser manufacturer').fill(c.vendor);
 await page.getByLabel('Parser product',{exact:true}).fill(c.product);
 await page.getByLabel('ChatGPT desired fields').fill('Preserve source event fields with exact values; do not infer unsupported semantics');
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 let prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),'ORIGINAL_NOT_IN_PROMPT');
 assert(sha(prompt)===modes.get(c.id).promptSha256,'INITIAL_PROMPT_MISMATCH');
 for(let attempt=1;attempt<=3;attempt++){
   const saved=path.join(rootFolder,'prompt-'+attempt+'.txt');
   if(fs.existsSync(saved))assert(read(saved)===prompt,'RETRY_PROMPT_PROVENANCE_MISMATCH');
   else write(saved,prompt);
   const responsePath=path.join(rootFolder,'response-'+attempt+'.txt');
   if(!fs.existsSync(responsePath)){
    row.state='AWAITING_SAME_CHAT_REPLY';row.nextAttempt=attempt;break;
   }
   const reply=read(responsePath);
   const receipt=JSON.parse(read(path.join(rootFolder,'capture-'+attempt+'.json')));
   assert(receipt.origin==='SAME_CHAT_GPT6'&&receipt.promptSha256===sha(prompt)&&
     receipt.responseSha256===sha(reply),'SIMULATION_CAPTURE_INVALID');
   row.attempts=attempt;row.lastResponseSha256=sha(reply);
   await page.getByLabel('ChatGPT result JSON').fill(reply);
   await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
   if(reply.startsWith('REVIEW_REQUIRED:')){
    await page.waitForTimeout(280);
    assert((await page.getByLabel('ChatGPT created parser files').count())===0,
      'REFUSAL_CREATED_NATIVE_PARSER');
    row.state='REVIEW_REQUIRED';row.safeRefusal=true;row.reason='UNSUPPORTED_OR_INCOMPLETE_SOURCE';
    break;
   }
   await Promise.race([
    page.getByLabel('ChatGPT result ready for testing').waitFor({timeout:14000}).catch(()=>{}),
    page.getByLabel('ChatGPT adaptive repair').waitFor({timeout:14000}).catch(()=>{}),
    page.getByText('Three attempts reached.',{exact:false}).waitFor({timeout:14000}).catch(()=>{})
   ]);
   if(await page.getByLabel('ChatGPT result ready for testing').count()){
    const button=page.getByRole('button',{name:'Test Original Sample Only'});
    if(await button.count()===1){
     await button.click();
     const report=page.getByLabel('ChatGPT fix test result');
     await report.waitFor({timeout:22000});
     const text=await report.innerText();
     row.latestUIReport=text.slice(0,550);
     write(path.join(rootFolder,'attempt-'+attempt+'-web-report.txt'),text);
     if(text.includes('SAMPLE PASS (NOT GENERALIZED)')){
      await report.getByText('Review actual extracted fields before approval').click();
      const preview=await report.locator('pre').first().innerText();
      write(path.join(rootFolder,'attempt-'+attempt+'-fields.json'),preview);
      await page.getByLabel('Approve sample-only draft').check();
      await page.getByRole('button',{name:'Apply Fix & Create Parser Files'}).click();
      const files=page.getByLabel('ChatGPT created parser files');
      await files.waitFor({timeout:30000});
      const delivered=[];
      for(const expr of [/Download .*\.conf$/,/^Download customized_[A-Za-z0-9_]+$/]){
       const target=files.getByRole('button',{name:expr}).first();
       assert(await target.count()===1,'MISSING_DOWNLOAD');
       const download=page.waitForEvent('download',{timeout:18000});
       await target.click();
       const d=await download,bytes=fs.readFileSync(await d.path());
       const ext=d.suggestedFilename().endsWith('.conf')?'conf':'rb';
       assert(bytes.length>0,'EMPTY_DOWNLOAD');
       write(path.join(rootFolder,'draft.'+ext),bytes);
       delivered.push({ext,sha256:sha(bytes),size:bytes.length});
      }
      row.downloaded=delivered;
      row.native=runNative(path.join(rootFolder,'draft.rb'),c.rawSample);
      row.nativePair=delivered.length===2;
      row.state=row.native.valid?'NATIVE_PASS':'NATIVE_FAIL';
      row.evidence='SAMPLE_ONLY_NOT_GENERALIZED';
      break;
     }
    }
   }
   if(attempt===3){row.state='FAIL_AFTER_3';break}
   const retry=page.getByRole('button',{name:'Copy Improved Prompt · Attempt '+(attempt+1)+' of 3'});
   if(await retry.count()===0){row.state='REVIEW_REQUIRED_UI_NO_RETRY';break}
   await retry.click();
   prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
   assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),'RETRY_LOST_ORIGINAL_SOURCE');
   write(path.join(rootFolder,'prompt-'+(attempt+1)+'.txt'),prompt);
   row.nextAttempt=attempt+1;
   if(!fs.existsSync(path.join(rootFolder,'response-'+(attempt+1)+'.txt'))){
    row.state='AWAITING_SAME_CHAT_REPLY';break;
   }
 }
}
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});let pointer=0;
 async function worker(){
  const ctx=await browser.newContext({viewport:{width:1440,height:900},acceptDownloads:true});
  while(pointer<cases.length){
   const at=pointer++,c=cases[at],page=await ctx.newPage();
   const row={id:c.id,vendor:c.vendor,sampleClass:c.sampleClass,attempts:0,state:'START',
    nativePair:false,modelProviderCompletions:0,unexpectedOutside:false,browserErrors:[],http5xx:[]};
   page.on('pageerror',e=>row.browserErrors.push(String(e.message).slice(0,200)));
   page.on('response',res=>{if(res.url().startsWith(origin+'/api/')&&res.status()>=500)row.http5xx.push(res.status())});
   page.on('request',req=>{try{if(/^https?:/.test(req.url())&&new URL(req.url()).origin!==origin)row.unexpectedOutside=true}catch{}});
   try{
    await handle(page,c,path.join(out,c.id),row);
    assert(!row.unexpectedOutside&&row.http5xx.length===0&&row.browserErrors.length===0,'BROWSER_OR_NETWORK_SIDE_EFFECT');
   }catch(e){row.state='ERROR';row.error=String(e).slice(0,500)}
   finally{results[at]=row;console.log('RECOVERY_REPLAY '+JSON.stringify({id:row.id,
    state:row.state,attempts:row.attempts,native:row.native?.valid,error:row.error,
    nextAttempt:row.nextAttempt,report:row.latestUIReport?.slice(0,100)}));
    await page.close().catch(()=>{});
    const done=results.filter(Boolean).length;
    if(done%5===0||done===cases.length)
      write(path.join(out,'replay-checkpoint.json'),JSON.stringify({results:results.filter(Boolean)},null,2));
   }
  }await ctx.close();
 }
 try{await Promise.all([worker(),worker(),worker()])}finally{await browser.close()}
 const tally={};
 for(const c of results)tally[c.state]=(tally[c.state]||0)+1;
 const summary={contract:'parserstudio.expanded-new-grammar-samechat-replay.v1',
   provenance:'CONTROLLED_GPT6_CURRENT_CONVERSATION_NOT_PROVIDER_INFERENCE',
   vendorOriginalSemanticTruthVerified:false,
   total:results.length,modelProviderCompletions:0,
   successfulNative:results.filter(x=>x.state==='NATIVE_PASS').length,
   safeReviewRequired:results.filter(x=>x.state==='REVIEW_REQUIRED').length,
   firstAttemptSuccess:results.filter(x=>x.state==='NATIVE_PASS'&&x.attempts===1).length,
   secondCumulativeSuccess:results.filter(x=>x.state==='NATIVE_PASS'&&x.attempts<=2).length,
   thirdCumulativeSuccess:results.filter(x=>x.state==='NATIVE_PASS'&&x.attempts<=3).length,
   statusCounts:tally,errors:results.filter(x=>x.state==='ERROR').map(x=>({id:x.id,error:x.error})),
   recorded:new Date().toISOString()};
 write(path.join(out,'replay-summary.json'),JSON.stringify({summary,cases:results},null,2));
 console.log('RECOVERY_FINAL '+JSON.stringify(summary));
 if(summary.errors.length)process.exitCode=1;
})().catch(e=>{console.error('RECOVERY_FATAL',String(e));process.exitCode=2});
