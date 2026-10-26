#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require('playwright');
const root='/home/aella/.local/state/parserstudio-expanded-security-20261025';
const scan=JSON.parse(fs.readFileSync(path.join(root,'baseline-reuse-e2e/summary.json')));
const manifest=JSON.parse(fs.readFileSync(path.join(root,'additional-source-manifest.json')));
const byId=new Map(manifest.cases.map(x=>[x.id,x]));
const missed=scan.cases.filter(x=>x.native?.missingPaths?.length);
const results=[];
(async()=>{
const b=await chromium.launch({headless:true,args:['--no-sandbox']});
const ctx=await b.newContext({viewport:{width:1360,height:880}});
try{
for(const item of missed){
 const c=byId.get(item.id),page=await ctx.newPage();
 const row={id:c.id,missedPaths:item.native.missingPaths,
  missingMapped:[],missingUnmapped:[],missingTimestampTyped:[]};
 try{
 await page.goto('https://app.parser.xdr.ooo/?workspace=chatgpt',{waitUntil:'domcontentloaded'});
 await page.getByLabel('ChatGPT local sample logs').fill(c.rawSample);
 await page.getByLabel('Parser manufacturer').fill(c.vendor);
 await page.getByLabel('Parser product',{exact:true}).fill(c.product);
 await page.getByLabel('ChatGPT desired fields').fill('Preserve source event fields with exact values; do not infer unsupported semantics');
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
 const base=prompt.match(/----- BEGIN VALIDATED BASELINE RECIPE -----\n([\s\S]*?)\n----- END VALIDATED BASELINE RECIPE -----/);
 if(!base)throw Error('BASELINE_NOT_EMBEDDED');
 const parsed=JSON.parse(base[1]);
 const maps=parsed.stages.filter(x=>x.op==='map_field');
 for(const x of item.native.missingPaths){
   const targets=maps.filter(m=>m.source===x||m.source.replace(/\[(\d+)\]/g,'.$1')===x);
   if(targets.length){
    const t=targets.map(m=>({source:m.source,target:m.target,type:m.data_type}));
    if(targets.some(y=>y.data_type==='date'))row.missingTimestampTyped.push({path:x,maps:t});
    else row.missingMapped.push({path:x,maps:t});
   }else row.missingUnmapped.push(x);
 }
 row.extractedMappings=maps.length;
 }catch(e){row.error=String(e).slice(0,200)}
 finally{results.push(row);await page.close();console.log('MAPPING_GAP '+JSON.stringify(row))}
}
}finally{await ctx.close();await b.close()}
const all={contract:'parserstudio.expanded-native-mapping-gap-analysis.v1',
 basedOn:'same-source validated baseline prompt, not manufacturer semantic oracle',
 comparedRecords:results.length,missingLexicalValues:missed.reduce((n,x)=>n+x.native.missingPaths.length,0),
 mappedNonDateMissing:results.reduce((n,x)=>n+x.missingMapped.length,0),
 typedDateMismatches:results.reduce((n,x)=>n+x.missingTimestampTyped.length,0),
 unmappedSourceValues:results.reduce((n,x)=>n+x.missingUnmapped.length,0),
 details:results};
const o=path.join(root,'native-mapping-gap-analysis.json');
fs.writeFileSync(o,JSON.stringify(all,null,2),{mode:0o600});
console.log('MAPPING_GAP_FINAL '+JSON.stringify({comparedRecords:all.comparedRecords,
 missingLexicalValues:all.missingLexicalValues,mappedNonDateMissing:all.mappedNonDateMissing,
 typedDateMismatches:all.typedDateMismatches,unmappedSourceValues:all.unmappedSourceValues}));
})().catch(e=>{console.error(e);process.exitCode=1});
