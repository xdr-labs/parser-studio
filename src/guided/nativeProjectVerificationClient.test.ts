import {describe,it,expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {ReviewedRecipeCompilation} from './recipeV2BackendClient';
import {
 buildNativeExpectedEvents,checkNativeProjectVerificationAvailability,
 NativeProjectVerificationUnavailable,verifyNativeProject,
} from './nativeProjectVerificationClient';

const source=[
 '{"action":"deny","src_ip":"192.0.2.10","dst_port":443}',
 '{"action":"allow","src_ip":"192.0.2.11","dst_port":53}',
].join('\n');
function canonical(value:unknown):string{
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object'){
  const record=value as Record<string,unknown>;
  return '{'+Object.keys(record).sort().map(key=>JSON.stringify(key)+':'+canonical(record[key])).join(',')+'}';
 }
 return JSON.stringify(value);
}
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
async function reviewed(){
 const draft=createDraft();draft.format='json';
 const suite=preview(source,draft);
 const review=await buildReviewableRecipe(source,draft,suite);
 if(!review.ok)throw new Error('expected reviewed recipe');
 return {draft,suite,review};
}
function compilation(review:Awaited<ReturnType<typeof reviewed>>['review']):ReviewedRecipeCompilation{
 const conf={name:'customized_demo_firewall.conf',content:'<source/>',sha256:'c'.repeat(64),bytes:9};
 const parser={name:'customized_demo_firewall',content:'# ruby',sha256:'d'.repeat(64),bytes:6};
 return {pair:{contract:'host-customized-pair.v0.1',files:[conf,parser],manifest:{
  status:'DRAFT',contract:'host-customized-pair.v0.1',schemaRevision:'0.1',
  projectId:review.legacyProject.projectId,projectRevision:1,
  fileHashes:{[conf.name]:conf.sha256,[parser.name]:parser.sha256},
  engineVerified:false,targetImportVerified:false,warnings:[],
 }},receipt:{
  contract:'parser-studio.recipe-compiler.v0.2',compilerMode:'V01_EQUIVALENT_SUBSET',
  recipeSha256:'a'.repeat(64),legacyProjectSha256:'b'.repeat(64),
  sourceSha256:review.recipe.sample.sha256,sampleEventCount:2,
  stageCount:review.recipe.stages.length,sourceHashVerifiedAgainstEvents:false,
  nativeUserParserVerified:false,targetImportVerified:false,
  outputProfile:'host-customized-pair.v0.1',
 }};
}
const capability=(configured=true)=>({
 contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',
 sourceHashVerifiedAgainstEvents:false,nativeUserParserVerified:false,
 nativeProjectVerificationConfigured:configured,
 nativeProjectVerificationRequiresAuth:true,targetImportVerified:false,apiDoesNotDeploy:true,
});
function response(value:unknown,status=200){
 return new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}});
}

describe('explicit source-bound Native project verification client',()=>{
 it('derives independent final Ruby record hashes including classification and msg_origin',async()=>{
  const {suite,review}=await reviewed();
  const actual=await buildNativeExpectedEvents(suite,review.recipe,review.legacyProject);
  const first={
   custom:{action:'deny',destination_port:443,source_ip:'192.0.2.10'},
   stellar_log_index:'threat',
   msg_origin:{source:'demo_firewall',category:'network',class:'demo_firewall'},
  };
  const second={
   custom:{action:'allow',destination_port:53,source_ip:'192.0.2.11'},
   stellar_log_index:'session',
   msg_origin:{source:'demo_firewall',category:'network',class:'demo_firewall'},
  };
  expect(actual).toEqual([
   {eventId:'event-1',recordSha256:sha(canonical(first)),eventTimeMs:null},
   {eventId:'event-2',recordSha256:sha(canonical(second)),eventTimeMs:null},
  ]);
 });
 it('preserves the backend vendor namespace and fails closed on noncanonical IPv6 expectations',async()=>{
  const draft=createDraft();draft.format='json';
  draft.guided={...draft.guided!,groups:{...draft.guided!.groups,'source-ip':'vendor_fields'}};
  const one='{"action":"deny","src_ip":"192.0.2.10","dst_port":443}';
  const suite=preview(one,draft),review=await buildReviewableRecipe(one,draft,suite);
  if(!review.ok)throw new Error('expected reviewed recipe');
  const actual=await buildNativeExpectedEvents(suite,review.recipe,review.legacyProject);
  const record={
   custom:{action:'deny',destination_port:443},
   'Demo Local Draft':{custom:{source_ip:'192.0.2.10'}},
   stellar_log_index:'threat',
   msg_origin:{source:'demo_firewall',category:'network',class:'demo_firewall'},
  };
  expect(actual[0]?.recordSha256).toBe(sha(canonical(record)));

  const ipv6=createDraft();ipv6.format='json';
  const raw='{"action":"deny","src_ip":"2001:db8::1","dst_port":443}';
  const ipv6Suite=preview(raw,ipv6),ipv6Review=await buildReviewableRecipe(raw,ipv6,ipv6Suite);
  if(!ipv6Review.ok)throw new Error('expected IPv6 review');
  await expect(buildNativeExpectedEvents(ipv6Suite,ipv6Review.recipe,ipv6Review.legacyProject))
   .rejects.toThrow(/canonical IPv4/);
 });
 it('checks availability without raw source and posts source only on explicit verification',async()=>{
  const {suite,review}=await reviewed(),compiled=compilation(review);
  const expected=await buildNativeExpectedEvents(suite,review.recipe,review.legacyProject);
  const calls:Array<{url:string;body:string}>= [];
  const requester=vi.fn(async(url:RequestInfo|URL,init?:RequestInit)=>{
   const path=String(url),body=String(init?.body??'');calls.push({url:path,body});
   if(path.endsWith('/capabilities')){
    expect(body).toBe('');
    return response(capability(true));
   }
   expect(path).toBe('/api/v1/parser-pairs/recipe/v0.2/native-verify');
   const request=JSON.parse(body);
   expect(request.source).toBe(source);
   expect(request.confirmed).toBe(true);
   expect(request.expected).toEqual(expected);
   expect(init?.credentials).toBe('same-origin');
   return response({
    contract:'parser-studio.native-project-verification.v0.1',
    sourceSha256:review.recipe.sample.sha256,recipeSha256:compiled.receipt.recipeSha256,
    parserSha256:'d'.repeat(64),confSha256:'c'.repeat(64),
    eventCount:2,eventsPassed:2,recordHashMatches:2,eventTimeMatches:2,
    ruby:'3.2',fluentd:'1.17.1',confAstVerified:true,parserCallbackVerified:true,
    sourceHashVerifiedAgainstEvents:true,nativeUserParserVerified:true,
    targetImportVerified:false,sensorTrafficSent:false,rawValuesReturned:false,
   });
  });
  const report=await verifyNativeProject({
   source,suite,recipe:review.recipe,legacyProject:review.legacyProject,compiled,
  },requester as typeof fetch);
  expect(report.nativeUserParserVerified).toBe(true);
  expect(report.targetImportVerified).toBe(false);
  expect(calls.map(call=>call.url)).toEqual([
   '/api/v1/parser-pairs/recipe/v0.2/capabilities',
   '/api/v1/parser-pairs/recipe/v0.2/native-verify',
  ]);
 });
 it('does not post source when private verification is disabled and rejects forged reports',async()=>{
  const {suite,review}=await reviewed(),compiled=compilation(review);
  const disabled=vi.fn(async()=>response(capability(false)));
  expect(await checkNativeProjectVerificationAvailability(disabled as typeof fetch)).toBe(false);
  await expect(verifyNativeProject({
   source,suite,recipe:review.recipe,legacyProject:review.legacyProject,compiled,
  },disabled as typeof fetch)).rejects.toBeInstanceOf(NativeProjectVerificationUnavailable);
  expect(disabled).toHaveBeenCalledTimes(2);
  for(const forged of [
   {nativeUserParserVerified:false},
   {targetImportVerified:true},
   {parserSha256:'e'.repeat(64)},
   {rawValuesReturned:true},
  ]){
   const backend=vi.fn(async(url:RequestInfo|URL)=>{
    if(String(url).endsWith('/capabilities'))return response(capability(true));
    return response({
     contract:'parser-studio.native-project-verification.v0.1',
     sourceSha256:review.recipe.sample.sha256,recipeSha256:compiled.receipt.recipeSha256,
     parserSha256:'d'.repeat(64),confSha256:'c'.repeat(64),
     eventCount:2,eventsPassed:2,recordHashMatches:2,eventTimeMatches:2,
     ruby:'3.2',fluentd:'1.17.1',confAstVerified:true,parserCallbackVerified:true,
     sourceHashVerifiedAgainstEvents:true,nativeUserParserVerified:true,
     targetImportVerified:false,sensorTrafficSent:false,rawValuesReturned:false,
     ...forged,
    });
   });
   await expect(verifyNativeProject({
    source,suite,recipe:review.recipe,legacyProject:review.legacyProject,compiled,
   },backend as typeof fetch)).rejects.toThrow(/untrusted/);
  }
 });
});
