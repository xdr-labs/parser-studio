const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {chromium}=require('playwright');
const root=process.env.PARSER_STUDIO_EVIDENCE_ROOT||'/home/aella/.local/state/parserstudio-real-evidence-20261024';
const ledger=JSON.parse(fs.readFileSync(path.join(root,'reports/vendor-source-ledger.json'),'utf8'));
const flatten=(value,p='',out=[])=>{
 if(value&&typeof value==='object'&&!Array.isArray(value)){
  for(const [k,v] of Object.entries(value))flatten(v,p?p+'.'+k:k,out);
 }else if(Array.isArray(value)){for(const [k,v] of value.entries())flatten(v,p+'.'+k,out)}
 else out.push({path:p,value:String(value)});
 return out;
};
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.PARSER_STUDIO_BROWSER_CHROME?{executablePath:process.env.PARSER_STUDIO_BROWSER_CHROME}:{})});
 const cases=[];
 try{
  for(const sample of ledger.sources){
   const context=await browser.newContext({viewport:{width:1440,height:900}});
   const page=await context.newPage();
   const raw=fs.readFileSync(path.join(root,'raw',sample.id+'.log'),'utf8');
   const r={id:sample.id,sha256:crypto.createHash('sha256').update(raw,'utf8').digest('hex'),product:sample.product,official_example:true,authenticated_device_original:false,ui:'real deployed public Chromium',analysis_status:'',parser_file_creation:false,raw_preserved:false};
   try{
    await page.goto('https://app.parser.xdr.ooo/');
    await page.getByLabel('Auto Parser raw logs').fill(raw);
    r.raw_preserved=await page.getByLabel('Auto Parser raw logs').inputValue()===raw;
    const promise=page.waitForResponse(resp=>resp.request().method()==='POST'&&(/\/api\/v1\/multipass\/preview(?:-batch)?$/.test(new URL(resp.url()).pathname)),{timeout:27000});
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const response=await promise;
    r.httpStatus=response.status();
    const body=await response.json();
    fs.writeFileSync(path.join(root,'reports',sample.id+'-live-api-preview.json'),JSON.stringify(body,null,2)+'\n');
    let evs=Array.isArray(body.events)?body.events:[{preview:body}];
    r.actual_frames=evs.length;
    r.source_grammar=evs.map(e=>e.preview?.syntax||'UNKNOWN');
    r.statuses=evs.map(e=>e.preview?.status||'UNKNOWN');
    r.raw_preview_sha256=evs.map(e=>e.preview?.sourceSha256);
    const fields=evs.flatMap(e=>flatten(e.preview?.fields||{}));
    r.extracted_occurrences=fields.length;
    const rawBytes=Buffer.from(raw,'utf8');
    r.field_checks=sample.golden.map(g=>{
     const matches=fields.filter(f=>f.path===g.path && f.value===g.sourceValue);
     const other=fields.filter(f=>f.value===g.sourceValue);
     const sourceSpan=rawBytes.subarray(g.startByte,g.endByte).toString('utf8')===g.sourceValue;
     return {path:g.path,value:g.sourceValue,sourceSpanVerified:sourceSpan,exactPathValueMatches:matches.length,sourceValueFoundAtOtherPaths:other.map(f=>f.path).slice(0,5)};
    });
    r.labeled_count=r.field_checks.length;
    r.exact_path_value_matches=r.field_checks.filter(x=>x.exactPathValueMatches>0).length;
    r.value_found_any_path=r.field_checks.filter(x=>x.sourceValueFoundAtOtherPaths.length>0).length;
    r.labeled_source_spans_valid=r.field_checks.filter(x=>x.sourceSpanVerified).length;
    r.unlabeled_fields_count=fields.filter(f=>!sample.golden.some(g=>g.path===f.path)).length;
    r.ui_summary=(await page.getByLabel('Beginner analysis summary').innerText()).slice(0,350);
    // Strictly not asserting the whole source schema was independently labeled.
    r.field_scoring_scope='Independently labeled subset only; no whole-record precision claim';
    await page.screenshot({path:path.join(root,'reports',sample.id+'-live-api.png'),fullPage:true});
   }catch(e){r.error=String(e).slice(0,500)}
   cases.push(r);fs.writeFileSync(path.join(root,'reports','official-live-field-scores.json'),JSON.stringify({cases},null,2)+'\n');
   console.log('LIVE_OFFICIAL_FIELD_SCORE '+JSON.stringify({id:r.id,http:r.httpStatus,frames:r.actual_frames,grammar:r.source_grammar,status:r.statuses,exact:r.exact_path_value_matches,labeled:r.labeled_count,anyValue:r.value_found_any_path,byte:r.labeled_source_spans_valid,extracted:r.extracted_occurrences,raw:r.raw_preserved,error:r.error}));
   await context.close();
  }
 }finally{await browser.close()}
})().catch(err=>{console.error(err);process.exitCode=1});
