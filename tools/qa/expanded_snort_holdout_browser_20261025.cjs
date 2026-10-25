#!/usr/bin/env node
'use strict';
// Actual public Chromium review gate: a source-only Snort DRAFT must fail on
// another synthetic, source-disjoint, differently formatted Snort event.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require('playwright');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const root='/home/aella/.local/state/parserstudio-expanded-security-20261025';
const raw=JSON.parse(fs.readFileSync(path.join(root,'additional-source-manifest.json')));
const c=raw.cases.find(x=>x.id==='cisco-068');
const fixtures=fs.readFileSync('tests/novice-corpus-54-public-20261019.spec.ts','utf8');
const match=fixtures.match(/\{id:'19 Snort alert syslog',[^\n]+raw:'([^']+)'/);
if(!match)throw Error('SNORT_FIXTURE_NOT_FOUND');
const fixture46=fs.readFileSync('tests/novice-corpus-46-public-20261019.spec.ts','utf8');
const alternate=fixture46.match(/\['Snort fast alert','([^']+)'\]/);
if(!alternate)throw Error('SECOND_SNORT_FIXTURE_NOT_FOUND');
const holdout=match[1]+'\n'+alternate[1];
const resultsFile=path.join(root,'new-grammar-recovery/cisco-068/source-disjoint-ui-gate.json');
const folder=path.join(root,'new-grammar-recovery/cisco-068');
(async()=>{
const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
const page=await browser.newPage({viewport:{width:1440,height:900}});
const stats={contract:'parserstudio.snort-source-disjoint-ui-block.v1',case:'cisco-068',
 trainingSha256:c.originalSha256,holdoutSha256:sha(holdout),genuinelyDifferent:sha(c.rawSample)!==sha(holdout),
 holdoutOrigin:'AUTHORED_REPO_TEST_FIXTURE_NOT_MANUFACTURER_CAPTURE',
 publicBrowser:true,thirdPartyCalls:[],browserErrors:[]};
page.on('pageerror',e=>stats.browserErrors.push(e.message));
page.on('request',r=>{try{
 if(/^https?:/.test(r.url())&&new URL(r.url()).origin!=='https://app.parser.xdr.ooo')
  stats.thirdPartyCalls.push(r.url());
}catch{}});
try{
 await page.goto('https://app.parser.xdr.ooo/?workspace=chatgpt',{waitUntil:'domcontentloaded',timeout:22000});
 await page.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
 await page.getByLabel('ChatGPT solution vendor').fill(c.vendor);
 await page.getByLabel('ChatGPT solution product').fill(c.product);
 await page.getByLabel('ChatGPT desired fields').fill('Preserve source event fields with exact values; do not infer unsupported semantics');
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 for(let n=1;n<=3;n++){
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  const stored=fs.readFileSync(path.join(folder,'prompt-'+n+'.txt'),'utf8');
  if(prompt!==stored)throw Error('RETRY_PROMPT_IDENTITY_DRIFT_'+n);
  const response=fs.readFileSync(path.join(folder,'response-'+n+'.txt'),'utf8');
  await page.getByLabel('ChatGPT result JSON').fill(response);
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await Promise.race([
   page.getByLabel('ChatGPT result ready for testing').waitFor({timeout:20000}).catch(()=>{}),
   page.getByLabel('ChatGPT adaptive repair').waitFor({timeout:20000}).catch(()=>{})
  ]);
  stats['stage'+n+'Accepted']=(await page.getByLabel('ChatGPT result ready for testing').count())===1;
  if(n<3){
   if(stats['stage'+n+'Accepted']){
    const btn=page.getByRole('button',{name:'Test Original Sample Only'});
    if(await btn.count()===1){
      await btn.click();
      await page.getByLabel('ChatGPT fix test result').waitFor({timeout:18000});
    }
   }
   const retry=page.getByRole('button',{name:'Copy Improved Prompt · Attempt '+(n+1)+' of 3'});
   if(await retry.count()!==1)throw Error('EXPECTED_RETRY_NOT_PRESENT_'+n);
   await retry.click();
  }
 }
 if(!stats.stage3Accepted)throw Error('THIRD_RECIPE_NOT_ACCEPTED');
 await page.getByLabel('Additional ChatGPT test logs').fill(holdout);
 await page.getByLabel('Confirm test examples are different').check();
 const btn=page.getByRole('button',{name:'Test Proposed Fix'});
 if(await btn.isDisabled())throw Error('HOLDOUT_TEST_DISABLED');
 await btn.click();
 const report=page.getByLabel('ChatGPT fix test result');
 await report.waitFor({timeout:25000});
 const summary=await report.innerText();
 stats.overallFailed=summary.includes('Overall test: FAILED');
 stats.holdoutTested=summary.includes('Additional logs tested: YES');
 stats.originalStillPasses=summary.includes('Original logs still pass: YES');
 const draft=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
 stats.draftDisabled=await draft.isDisabled();
 stats.noParserGenerated=(await page.getByLabel('ChatGPT created parser files').count())===0;
 stats.report=summary.slice(0,1200);
 stats.passed=stats.genuinelyDifferent&&stats.holdoutTested&&stats.overallFailed&&
  stats.originalStillPasses&&stats.draftDisabled&&stats.noParserGenerated&&
  stats.browserErrors.length===0&&stats.thirdPartyCalls.length===0;
 if(!stats.passed)throw Error('SOURCE_DISJOINT_UI_ACCEPTANCE_FAILED '+JSON.stringify(stats));
}finally{
 fs.mkdirSync(path.dirname(resultsFile),{recursive:true,mode:0o700});
 fs.writeFileSync(resultsFile,JSON.stringify(stats,null,2)+'\n',{mode:0o600});
 await browser.close();
}
console.log('SNORT_SOURCE_DISJOINT_UI '+JSON.stringify(stats));
})().catch(err=>{console.error('SOURCE_DISJOINT_GATE_ERROR '+String(err));process.exitCode=1});
