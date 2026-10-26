#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require('playwright');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const root='/home/aella/.local/state/parserstudio-expanded-security-20261025';
const input=JSON.parse(fs.readFileSync(path.join(root,'additional-source-manifest.json')));
const browserAudit=JSON.parse(fs.readFileSync(path.join(root,'browser-78-real-public.json')));
const outcomeMap=new Map(browserAudit.cases.map(x=>[x.id,x]));
const recovery=input.cases.filter(c=>outcomeMap.get(c.id)?.promptMode==='FULL_RECOVERY');
const out=path.join(root,'new-grammar-recovery');
const origin='https://app.parser.xdr.ooo';
function file(p,v){fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});fs.writeFileSync(p,v,{mode:0o600})}
const assert=(ok,s)=>{if(!ok)throw Error(s)};
(async()=>{
 const b=await chromium.launch({headless:true,args:['--no-sandbox']});let index=0;
 const matrix=new Array(recovery.length);
 async function worker(){
  const ctx=await b.newContext({viewport:{width:1440,height:900}});
  while(index<recovery.length){
   const n=index++,c=recovery[n],p=await ctx.newPage(),item={id:c.id,vendor:c.vendor,ready:false};
   try{
    const outside=[];p.on('request',req=>{try{if(/^https?:/.test(req.url())&&new URL(req.url()).origin!==origin)outside.push(req.url())}catch{}});
    await p.goto(origin+'/?workspace=chatgpt',{waitUntil:'domcontentloaded',timeout:18000});
    await p.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
    await p.getByLabel('Parser manufacturer').fill(c.vendor);
    await p.getByLabel('Parser product',{exact:true}).fill(c.product);
    await p.getByLabel('ChatGPT desired fields').fill('Preserve source event fields with exact values; do not infer unsupported semantics');
    await p.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
    const field=p.getByLabel('ChatGPT copyable prompt');
    await field.waitFor({timeout:25000});
    const prompt=await field.inputValue();
    assert(prompt.includes(c.rawSample)&&prompt.includes(c.originalSha256),'SOURCE_NOT_PRESERVED');
    assert(sha(prompt)===outcomeMap.get(c.id).promptSha256,'PROMPT_DIFFERS_FROM_PRIOR_PROVENANCE');
    assert(outside.length===0,'UNEXPECTED_OUTSIDE_ORIGIN');
    file(path.join(out,c.id,'prompt-1.txt'),prompt);
    item.ready=true;item.promptSha256=sha(prompt);
   }catch(e){item.error=String(e).slice(0,450)}
   finally{matrix[n]=item;console.log('RECOVERY_PREP '+JSON.stringify(item));await p.close()}
  }await ctx.close();
 }
 try{await Promise.all([worker(),worker(),worker()])}finally{await b.close()}
 const summary={planned:recovery.length,pass:matrix.filter(x=>x.ready).length,
  failed:matrix.filter(x=>!x.ready).length,preexistingBaselineCount:0,
  modelCalls:0,outputProvider:'SAME_CONVERSATION_GPT6_ONLY'};
 file(path.join(out,'prepare-summary.json'),JSON.stringify({summary,cases:matrix},null,2));
 console.log('RECOVERY_PREP_FINAL '+JSON.stringify(summary));
 if(summary.failed)process.exitCode=1;
})().catch(e=>{console.error(String(e));process.exitCode=2});
