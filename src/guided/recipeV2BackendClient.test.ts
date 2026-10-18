import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {webcrypto,createHash} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import type {GeneratedPair} from './backendClient';
import {buildReviewableRecipe,type RecipeReview} from './parserRecipeV2';
import {checkRecipeV02Compiler,compileReviewedRecipeV02} from './recipeV2BackendClient';

const inputSource=[
 '{"action":"deny","src_ip":"198.51.100.10","dst_port":443}',
 '{"action":"allow","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');
function canonical(value:unknown):string{
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object'){
  const obj=value as Record<string,unknown>;
  return '{'+Object.keys(obj).sort().map(key=>JSON.stringify(key)+':'+canonical(obj[key])).join(',')+'}';
 }
 return JSON.stringify(value);
}
const hash=(text:string)=>createHash('sha256').update(text).digest('hex');
const capability={
 contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',
 compilerMode:'V01_EQUIVALENT_SUBSET',currentOutputProfile:'host-customized-pair.v0.1',
 inputRequires:['recipe','legacyProject'],
 supportedBodyParsers:['json','kv','csv','cef','leef'],
 supportedEnvelopeParsers:['none','rfc3164_strict_no_year_or_zone','rfc5424_v1_strict'],
 strictMixedSingleLineFamilies:['json','kv','cef','leef'],
 jsonBlankLineTcpFraming:true,jsonBlankLineOtherTransports:false,
 jsonBlankLineDelimiter:'LF_LF',
 supportedOperators:['split_event','unwrap_syslog','dispatch_family','parse_json','parse_kv','parse_csv',
  'parse_cef','parse_leef','map_field','cast_type','classify_equals','fallback_unparsed'],
 nativeUserParserVerified:false,targetImportVerified:false,
 sourceHashVerifiedAgainstEvents:false,apiDoesNotDeploy:true,
};
function response(body:unknown,status=200){
 return new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
}
function pairFor(review:Extract<RecipeReview,{ok:true}>):GeneratedPair{
 const slug=review.legacyProject.slug,name='customized_'+slug;
 const files=[{name:name+'.conf',content:'<source> port 7501 </source>\n'},
  {name,content:'# STELLAR_INIT_BEGIN\n# STELLAR_PARSE_BEGIN\n'}]
  .map(x=>({...x,sha256:hash(x.content),bytes:Buffer.byteLength(x.content)}));
 return {contract:'host-customized-pair.v0.1',files,manifest:{
  contract:'host-customized-pair.v0.1',status:'DRAFT',schemaRevision:'0.1',
  projectId:review.legacyProject.projectId,projectRevision:review.legacyProject.revision,
  fileHashes:Object.fromEntries(files.map(x=>[x.name,x.sha256])),
  engineVerified:false,targetImportVerified:false,warnings:[],
 }};
}
async function setup(){
 const draft=createDraft();draft.format='json';
 const review=await buildReviewableRecipe(inputSource,draft,preview(inputSource,draft));
 if(!review.ok)throw new Error('Expected valid reviewed recipe');
 const pair=pairFor(review);
 const receipt={
  contract:'parser-studio.recipe-compiler.v0.2',compilerMode:'V01_EQUIVALENT_SUBSET',
  outputProfile:'host-customized-pair.v0.1',
  recipeSha256:hash(canonical(review.recipe)),
  legacyProjectSha256:hash(canonical(review.legacyProject)),
  sourceSha256:review.recipe.sample.sha256,
  sampleEventCount:review.recipe.sample.events,stageCount:review.recipe.stages.length,
  sourceHashVerifiedAgainstEvents:false,nativeUserParserVerified:false,targetImportVerified:false,
 };
 return {review,pair,receipt};
}
describe('P0-AP3 strict v0.2 backend client with pinned same-origin capability',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('validates and exactly compares v0.1 and staged v0.2 pair hashes without raw source egress',async()=>{
  const {review,pair,receipt}=await setup();
  const calls:string[]=[];
  const requester=vi.fn(async (url:RequestInfo|URL,init?:RequestInit)=>{
   const path=String(url),data=String(init?.body??'');
   calls.push(path);
   expect(path).toMatch(/^\/api\/v1\/parser-pairs\/recipe\/v0\.2\//);
   expect(init?.credentials).toBe('same-origin');
   if(path.endsWith('/capabilities'))return response(capability);
   expect(data).not.toContain('198.51.100.10');
   expect(data).not.toContain('203.0.113.5');
   expect(data).not.toContain('apiKey');
   if(path.endsWith('/validate'))return response({
    ok:true,issues:[],compilerMode:'V01_EQUIVALENT_SUBSET',
    nativeUserParserVerified:false,targetImportVerified:false,
   });
   return response({...pair,recipeReceipt:receipt});
  });
  const actual=await compileReviewedRecipeV02({
   recipe:review.recipe,legacyProject:review.legacyProject,
  },pair,requester as typeof fetch);
  expect(actual.pair.files).toEqual(pair.files);
  expect(actual.receipt.nativeUserParserVerified).toBe(false);
  expect(actual.receipt.targetImportVerified).toBe(false);
  expect(calls).toEqual([
   '/api/v1/parser-pairs/recipe/v0.2/capabilities',
   '/api/v1/parser-pairs/recipe/v0.2/validate',
   '/api/v1/parser-pairs/recipe/v0.2/generate',
  ]);
 });
 it('refuses unsupported and forged Native/DP capabilities without making a generation request',async()=>{
  const {review,pair}=await setup();
  const unsupported=vi.fn(async()=>response({error:'NOT_FOUND'},404));
  expect(await checkRecipeV02Compiler(unsupported as typeof fetch)).toBe(false);
  await expect(compileReviewedRecipeV02({
   recipe:review.recipe,legacyProject:review.legacyProject,
  },pair,unsupported as typeof fetch)).rejects.toThrow(/does not advertise/);
  const forged=vi.fn(async()=>response({...capability,nativeUserParserVerified:true}));
  await expect(checkRecipeV02Compiler(forged as typeof fetch))
   .rejects.toThrow(/not verified/);
 });
 it('requires explicit RFC3164 restricted capability before posting stages',async()=>{
  const bad=vi.fn(async()=>response({...capability,
    supportedEnvelopeParsers:['none','rfc5424_v1_strict']}));
  await expect(checkRecipeV02Compiler(bad as typeof fetch,
    'rfc3164_strict_no_year_or_zone')).rejects.toThrow(/not verified/);
  const safe=vi.fn(async()=>response(capability));
  expect(await checkRecipeV02Compiler(safe as typeof fetch,
    'rfc3164_strict_no_year_or_zone')).toBe(true);
 });
 it('refuses forged or missing mixed compiler dispatch capabilities without POST',async()=>{
   const backend=vi.fn(async()=>response({...capability,
     supportedBodyParsers:[...capability.supportedBodyParsers,'mixed']}));
   expect(await checkRecipeV02Compiler(backend as typeof fetch,undefined,true)).toBe(true);
   expect(backend).toHaveBeenCalledTimes(1);
   for(const bad of [
     {...capability,supportedOperators:capability.supportedOperators.filter(x=>x!=='dispatch_family'),
       supportedBodyParsers:[...capability.supportedBodyParsers,'mixed']},
     {...capability,strictMixedSingleLineFamilies:['json','kv','cef','other'],
       supportedBodyParsers:[...capability.supportedBodyParsers,'mixed']},
     capability,
   ]){
     const wrong=vi.fn(async()=>response(bad));
     await expect(checkRecipeV02Compiler(wrong as typeof fetch,undefined,true))
       .rejects.toThrow(/not verified/);
     expect(wrong).toHaveBeenCalledTimes(1);
   }
 });
 it('explicit RFC3164 TAG KV mixed route requires exact 7-family backend and yearless envelope',async()=>{
  const make=(families:string[])=>vi.fn(async()=>response({...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'mixed'],
    strictMixedSingleLineFamilies:families}));
  const old=make(['json','kv','cef','leef','rfc5424_cef','rfc5424_leef']);
  await expect(checkRecipeV02Compiler(old as typeof fetch,
    'rfc3164_strict_no_year_or_zone',true,false,
    ['json','kv','rfc3164_kv'])).rejects.toThrow(/not verified/);
  const supported=make(['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv']);
  expect(await checkRecipeV02Compiler(supported as typeof fetch,
    'rfc3164_strict_no_year_or_zone',true,false,
    ['json','kv','rfc3164_kv'])).toBe(true);
  const malicious=make(['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','unreviewed']);
  await expect(checkRecipeV02Compiler(malicious as typeof fetch,undefined,true))
    .rejects.toThrow(/not verified/);
 });
 it('needs exact 9-family native backend capability before accepting RFC5424 nested JSON and KV',async()=>{
  const make=(families:string[])=>vi.fn(async()=>response({...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'mixed'],
    strictMixedSingleLineFamilies:families}));
  const old=make(['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv']);
  await expect(checkRecipeV02Compiler(old as typeof fetch,undefined,true,false,
    ['json','kv','rfc5424_json','rfc5424_kv'])).rejects.toThrow(/not verified/);
  const families=['json','kv','cef','leef','rfc5424_cef','rfc5424_leef',
    'rfc3164_kv','rfc5424_json','rfc5424_kv'];
  const supported=make(families);
  expect(await checkRecipeV02Compiler(supported as typeof fetch,undefined,true,false,
    ['json','kv','rfc5424_json','rfc5424_kv'])).toBe(true);
  const missing=make([...families.slice(0,8),'unreviewed']);
  await expect(checkRecipeV02Compiler(missing as typeof fetch,undefined,true))
    .rejects.toThrow(/not verified/);
  const forged=make([...families,'experimental']);
  await expect(checkRecipeV02Compiler(forged as typeof fetch,undefined,true))
    .rejects.toThrow(/not verified/);
 });
 it('requires 11 reviewed mixed families for RFC3164 CEF/LEEF and denies old or forged IDs',async()=>{
  const make=(families:string[])=>vi.fn(async()=>response({...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'mixed'],
    strictMixedSingleLineFamilies:families}));
  const older=['json','kv','cef','leef','rfc5424_cef','rfc5424_leef',
    'rfc3164_kv','rfc5424_json','rfc5424_kv'];
  const denied=make(older);
  await expect(checkRecipeV02Compiler(denied as typeof fetch,
    'rfc3164_strict_no_year_or_zone',true,false,
    ['json','kv','rfc3164_cef','rfc3164_leef'])).rejects.toThrow(/not verified/);
  const valid=[...older,'rfc3164_cef','rfc3164_leef'];
  const good=make(valid);
  expect(await checkRecipeV02Compiler(good as typeof fetch,
    'rfc3164_strict_no_year_or_zone',true,false,
    ['json','kv','rfc3164_cef','rfc3164_leef'])).toBe(true);
  for(const invalid of [
    [...older,'rfc3164_cef','experimental'],
    [...valid,'experimental'],
  ]){
    await expect(checkRecipeV02Compiler(make(invalid) as typeof fetch,
      'rfc3164_strict_no_year_or_zone',true)).rejects.toThrow(/not verified/);
  }
 });
 it('qualifies 12 exact reviewed mixed families including CSV and rejects unreviewed substitutions',async()=>{
  const make=(families:string[])=>vi.fn(async()=>response({...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'mixed'],
    strictMixedSingleLineFamilies:families}));
  const base=['json','kv','cef','leef','rfc5424_cef','rfc5424_leef',
    'rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef'];
  const old=make(base);
  await expect(checkRecipeV02Compiler(old as typeof fetch,
    undefined,true,false,['csv','json','kv'])).rejects.toThrow(/not verified/);
  const current=make([...base,'csv']);
  expect(await checkRecipeV02Compiler(current as typeof fetch,
    undefined,true,false,['csv','json','kv'])).toBe(true);
  expect(await checkRecipeV02Compiler(current as typeof fetch,
    'rfc3164_strict_no_year_or_zone',true,false,
    ['json','kv','rfc3164_cef','rfc3164_leef'])).toBe(true);
  const incorrect=make([...base,'unreviewed']);
  await expect(checkRecipeV02Compiler(incorrect as typeof fetch,
    undefined,true,false,['csv','json','kv'])).rejects.toThrow(/not verified/);
  const oversized=make([...base,'csv','unreviewed']);
  await expect(checkRecipeV02Compiler(oversized as typeof fetch,
    undefined,true)).rejects.toThrow(/not verified/);
 });
 it('requires Java-specific TCP LF LF capability and parse stage; JSON framing alone is insufficient',async()=>{
  const source=['java.lang.IllegalStateException: Synthetic failure',
    '    at com.example.Service.run(Service.java:42)',
    '',
    'java.lang.RuntimeException: another',
    '    at com.example.App.main(App.java:5)'].join('\n');
  const draft=createDraft();
  draft.format='java_stacktrace';
  draft.guided={...draft.guided!,eventBoundary:'blank-line',
    receiver:{...draft.guided!.receiver,protocols:['tcp'],framing:'blank_line_java'},
    groups:{'java-class':'top_fields','java-frames':'top_fields'},
    classification:{defaultIndex:'Syslog',rules:[]}};
  draft.mappings=[
    {id:'java-class',source:'exception_class',target:'custom.exception_class',type:'string'},
    {id:'java-frames',source:'frame_count',target:'custom.frames',type:'integer'},
  ];
  const reviewed=await buildReviewableRecipe(source,draft,preview(source,draft));
  expect(reviewed.ok).toBe(true);
  if(!reviewed.ok)return;
  const good={...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'java_stacktrace'],
    supportedOperators:[...capability.supportedOperators,'parse_java_stacktrace'],
    javaBlankLineTcpFraming:true,javaBlankLineOtherTransports:false,
    javaBlankLineDelimiter:'LF_LF',javaStackTraceGrammar:'EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1'};
  const accepted=vi.fn(async()=>response(good));
  expect(await checkRecipeV02Compiler(accepted as typeof fetch,undefined,false,false,[],true)).toBe(true);
  for(const forged of [
    {...good,javaBlankLineTcpFraming:false},
    {...good,javaBlankLineOtherTransports:true},
    {...good,javaBlankLineDelimiter:'AUTO'},
    {...good,javaStackTraceGrammar:'BEST_EFFORT'},
    {...good,supportedBodyParsers:capability.supportedBodyParsers},
    {...good,supportedOperators:capability.supportedOperators},
  ]){
    await expect(checkRecipeV02Compiler(vi.fn(async()=>response(forged)) as typeof fetch,
      undefined,false,false,[],true)).rejects.toThrow(/not verified/);
  }
 });
 it('gates explicit TCP blank-line JSON by exact backend v0.2 transport claims',async()=>{
  const supported=vi.fn(async()=>response(capability));
  expect(await checkRecipeV02Compiler(supported as typeof fetch,undefined,false,true))
    .toBe(true);
  for(const body of [
    {...capability,jsonBlankLineTcpFraming:false},
    {...capability,jsonBlankLineOtherTransports:true},
    {...capability,jsonBlankLineDelimiter:'AUTO'},
  ])await expect(checkRecipeV02Compiler(vi.fn(async()=>response(body)) as typeof fetch,
      undefined,false,true)).rejects.toThrow('not verified');
 });
 it('explicit wrapped RFC5424 mixed families need all native-qualified capability names',async()=>{
  const old=vi.fn(async()=>response({...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'mixed'],
    strictMixedSingleLineFamilies:['json','kv','cef','leef']}));
  await expect(checkRecipeV02Compiler(old as typeof fetch,undefined,true,false,
    ['json','rfc5424_cef','rfc5424_leef'])).rejects.toThrow(/not verified/);
  expect(old).toHaveBeenCalledTimes(1);
  const modern=vi.fn(async()=>response({...capability,
    supportedBodyParsers:[...capability.supportedBodyParsers,'mixed'],
    strictMixedSingleLineFamilies:['json','kv','cef','leef','rfc5424_cef','rfc5424_leef']}));
  expect(await checkRecipeV02Compiler(modern as typeof fetch,undefined,true,false,
    ['json','rfc5424_cef','rfc5424_leef'])).toBe(true);
 });
 it('requires explicit split/merge compiler operators only when reviewed recipe uses them',async()=>{
  const source=[
   '{"action":"allow:http","src_ip":"198.51.100.10","dst_port":443}',
   '{"action":"deny:ssh","src_ip":"203.0.113.5","dst_port":22}',
  ].join('\n');
  const draft=createDraft();draft.format='json';
  const base=draft.guided!;
  draft.guided={...base,enrichment:[
   {id:'split',operator:'split_field',source:'custom.action',target:'',value:'',delimiter:':',
    targets:['custom.action_kind','custom.action_detail']},
   {id:'merge',operator:'merge_fields',source:'',target:'custom.action_joined',value:'',delimiter:'/',
    sources:['custom.action_kind','custom.action_detail']},
  ]};
  const review=await buildReviewableRecipe(source,draft,preview(source,draft));
  expect(review.ok).toBe(true);if(!review.ok)return;
  const missing=vi.fn(async()=>response(capability));
  await expect(compileReviewedRecipeV02({recipe:review.recipe,legacyProject:review.legacyProject},
    undefined,missing as typeof fetch)).rejects.toThrow(/contract was not verified/);
  expect(missing).toHaveBeenCalledTimes(1);
  const supported={...capability,supportedOperators:[...capability.supportedOperators,'split_field','merge_fields']};
  expect(await checkRecipeV02Compiler(vi.fn(async()=>response(supported)) as typeof fetch,
    undefined,false,false,[],false,['split_field','merge_fields'])).toBe(true);
 });
 it('refuses altered receipts, files and a mismatched baseline pair',async()=>{
  const {review,pair,receipt}=await setup();
  for(const altered of [
   {...receipt,sourceSha256:'a'.repeat(64)},
   {...receipt,nativeUserParserVerified:true},
   {...receipt,recipeSha256:'f'.repeat(64)},
   {...receipt,legacyProjectSha256:'e'.repeat(64)},
  ]){
   const req=vi.fn(async (url:RequestInfo|URL)=>{
    const path=String(url);
    if(path.endsWith('/capabilities'))return response(capability);
    if(path.endsWith('/validate'))return response({
     ok:true,issues:[],compilerMode:'V01_EQUIVALENT_SUBSET',
     nativeUserParserVerified:false,targetImportVerified:false,
    });
    return response({...pair,recipeReceipt:altered});
   });
   await expect(compileReviewedRecipeV02({
    recipe:review.recipe,legacyProject:review.legacyProject,
   },pair,req as typeof fetch)).rejects.toThrow(/not verified/);
  }
  const normal=vi.fn(async (url:RequestInfo|URL)=>{
   const path=String(url);
   if(path.endsWith('/capabilities'))return response(capability);
   if(path.endsWith('/validate'))return response({
    ok:true,issues:[],compilerMode:'V01_EQUIVALENT_SUBSET',
    nativeUserParserVerified:false,targetImportVerified:false,
   });
   return response({...pair,recipeReceipt:receipt});
  });
  const baseline={...pair,files:[{...pair.files[0]!,content:'different'},pair.files[1]!]};
  await expect(compileReviewedRecipeV02({
   recipe:review.recipe,legacyProject:review.legacyProject,
  },baseline,normal as typeof fetch)).rejects.toThrow(/differs/);
 });
});
