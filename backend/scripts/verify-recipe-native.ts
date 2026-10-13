/** Fixed offline v0.2 compiler equivalence fixtures for pinned Fluentd smoke.
 * Never accepts user input or a configurable destination; no network or DP IO.
 */
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {constants,closeSync,lstatSync,mkdirSync,openSync,
 realpathSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import type {ParserProject,FieldMap} from '../src/types.js';
import {sampleProject} from '../test/fixture.js';
import {recipeFromLegacyProject,compileRecipePair} from '../src/parser-recipe-v02.js';
import {compilePair} from '../src/compiler.js';
import {canonicalJson} from '../src/validate.js';

const ROOT=resolve('.tmp/recipe-v02-fixtures');
const PARENT=resolve('.tmp');
const MANIFEST=resolve('.tmp/recipe-v02-native-manifest.json');
const FIXTURE=resolve('test_native/fixtures/recipe-v0.2-golden.json');
const PROFILE_NAMES=['v02_json','v02_kv','v02_csv','v02_cef','v02_leef',
 'v02_syslog_cef','v02_syslog_leef',
 'v02_syslog3164_kv','v02_syslog3164_cef','v02_syslog3164_leef','v02_mixed','v02_json_blanks','v02_mixed_rfc5424','v02_mixed_rfc3164'];
const sha=(value:string|Buffer)=>createHash('sha256').update(value).digest('hex');
function directory(path:string){
 const st=lstatSync(path,{throwIfNoEntry:false});
 if(st&&(!st.isDirectory()||st.isSymbolicLink()))
  throw new Error('Unsafe fixed recipe fixture directory');
 if(!st)mkdirSync(path,{mode:0o700});
 if(realpathSync(path)!==path)throw new Error('Redirected recipe fixture directory');
}
function writeTrusted(path:string,value:string){
 const st=lstatSync(path,{throwIfNoEntry:false});
 if(st&&(!st.isFile()||st.isSymbolicLink()||st.nlink!==1))
  throw new Error('Untrusted native fixture destination');
 const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|
  constants.O_TRUNC|constants.O_NOFOLLOW,0o600);
 try{writeFileSync(fd,value,{encoding:'utf8'});}finally{closeSync(fd);}
}
type Profile={slug:string;format:ParserProject['extraction']['format'];
 transport?:'blank_line_json';
 bodyFormat?:'kv'|'cef'|'leef';raw:string;expectedTime:string|null;
 expectedRecord:Record<string,unknown>};
const samples=JSON.parse(readFileSync(FIXTURE,'utf8')) as
 {kind:string;origin:string;profiles:Profile[];
  negative:Array<{id:string;slug:string;raw:string}>;
  mixedCases:Array<{id:string;slug:string;raw:string}>;
  mixedNegative:Array<{id:string;slug:string;raw:string}>;
  mixedSyslogCases:Array<{id:string;slug:string;raw:string}>;
  mixedSyslogNegative:Array<{id:string;slug:string;raw:string}>;
  mixedRfc3164Cases:Array<{id:string;slug:string;raw:string}>;
  mixedRfc3164Negative:Array<{id:string;slug:string;raw:string}>;
  blankLineCases:Array<{id:string;slug:string;raw:string;
     expectedTime:string|null;expectedRecord:Record<string,unknown>}>};
if(samples.kind!=='parser-studio.recipe-v0.2-native-golden.v0.1'||
 samples.origin!=='independently-authored-public-synthetic'||
 !Array.isArray(samples.profiles)||samples.profiles.length!==14||
 !Array.isArray(samples.mixedRfc3164Cases)||samples.mixedRfc3164Cases.length!==3||
 samples.mixedRfc3164Cases.some(e=>e.slug!=='v02_mixed_rfc3164'||
   typeof e.raw!=='string'||e.raw.length>16384||!/^[a-z0-9-]+$/.test(e.id))||
 !Array.isArray(samples.mixedRfc3164Negative)||samples.mixedRfc3164Negative.length!==9||
 samples.mixedRfc3164Negative.some(e=>e.slug!=='v02_mixed_rfc3164'||
   typeof e.raw!=='string'||e.raw.length>16384||!/^[a-z0-9-]+$/.test(e.id))||
 !Array.isArray(samples.mixedSyslogCases)||samples.mixedSyslogCases.length!==3||
 samples.mixedSyslogCases.some(e=>e.slug!=='v02_mixed_rfc5424'||
   typeof e.raw!=='string'||e.raw.length>16384||!/^[a-z0-9-]+$/.test(e.id))||
 !Array.isArray(samples.mixedSyslogNegative)||samples.mixedSyslogNegative.length!==8||
 samples.mixedSyslogNegative.some(e=>e.slug!=='v02_mixed_rfc5424'||
   typeof e.raw!=='string'||e.raw.length>16384||!/^[a-z0-9-]+$/.test(e.id))||
 !Array.isArray(samples.blankLineCases)||samples.blankLineCases.length!==1||
 samples.blankLineCases.some(x=>x.id!=='second_pretty_json'||
  x.slug!=='v02_json_blanks'||typeof x.raw!=='string'||
  Buffer.byteLength(x.raw)>16384)||
 !Array.isArray(samples.negative)||samples.negative.length!==9||
 !Array.isArray(samples.mixedCases)||samples.mixedCases.length!==3||
 samples.mixedCases.some(e=>e.slug!=='v02_mixed'||typeof e.raw!=='string'||
   e.raw.length>16384||!/^[a-z-]+$/.test(e.id))||
 !Array.isArray(samples.mixedNegative)||samples.mixedNegative.length!==5||
 samples.mixedNegative.some(e=>e.slug!=='v02_mixed'||typeof e.raw!=='string'||
   e.raw.length>16384||!/^[a-z-]+$/.test(e.id))||
 samples.negative.some(e=>typeof e.raw!=="string"||
   e.raw.length>16384||!PROFILE_NAMES.includes(e.slug)||
   !/^[a-z_]+$/.test(e.id))||
 samples.profiles.map(x=>x.slug).join(',')!==PROFILE_NAMES.join(','))
 throw new Error('Untrusted or reordered recipe native fixture');
directory(PARENT);directory(ROOT);
const shaList:Record<string,string>={};
const receipts:Array<{slug:string;recipeSha256:string;sampleSha256:string;
 pairSha256:string}>=[];

const field=(src:string,dst:string,type:'string'|'ip'|'port'|'date')=>
 [src,{normalized_name:dst,data_type:type,
  ...(type==='date'?{time_format:'iso8601' as const,timezone:'UTC' as const}:{})}] as const;
function buildProject(entry:Profile):ParserProject{
 const p=sampleProject();
 p.projectId='draft-'+entry.slug;p.slug=entry.slug;
 p.receiver.port=7501;
 if(entry.transport==='blank_line_json'){
   if(entry.slug!=='v02_json_blanks'||entry.format!=='json')
     throw new Error('Native blank-line framing fixture mismatch');
   p.receiver.protocols=['tcp'];
   p.receiver.bindAddress='127.0.0.1';
   p.receiver.tcpFraming='blank_line_json';
 }
 p.classification.rules=[{field:'action',operator:'equals',value:'deny',index:'threat'}];
 p.extraction={format:entry.format,
  ...(entry.format==='csv'?{csvColumns:['src_ip','dst_port','action'],csvDelimiter:',' as const}:{}),
  ...(entry.format==='mixed'?{mixedFormats:entry.slug==='v02_mixed_rfc5424'?
    ['json','kv','rfc5424_cef','rfc5424_leef'] as const:
    entry.slug==='v02_mixed_rfc3164'?
      ['json','kv','rfc3164_kv'] as const:
      ['json','kv','cef','leef'] as const}:{}),
  ...(['syslog_rfc5424','syslog_rfc3164'].includes(entry.format)?
    {syslogBodyFormat:entry.bodyFormat}:{})};
 if(entry.slug==='v02_mixed_rfc3164'){
  p.receiver.port=6802;
  p.normalization.topFields=Object.fromEntries([
   field('src_ip','srcip','ip'),field('action','action','string'),
   field('body.src_ip','wrapped_srcip','ip'),field('body.action','wrapped_action','string'),
   field('syslog_timestamp','yearless_header','string'),
   field('syslog_time_policy','time_policy','string'),
  ]) as FieldMap;
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[
   {field:'action',operator:'equals',value:'deny',index:'threat'},
   {field:'action',operator:'equals',value:'allow',index:'session'},
   {field:'wrapped_action',operator:'equals',value:'deny',index:'threat'},
   {field:'wrapped_action',operator:'equals',value:'allow',index:'session'},
  ];
 }else if(entry.slug==='v02_mixed_rfc5424'){
  p.receiver.port=6801;
  p.normalization.topFields=Object.fromEntries([
   field('src_ip','srcip','ip'),field('dst_port','dstport','port'),
   field('action','action','string'),field('body.src','wrapped_src','ip'),
   field('body.dpt','wrapped_cef_port','port'),field('body.dstPort','wrapped_leef_port','port'),
   field('body.act','wrapped_action','string'),field('syslog_timestamp','timestamp','date'),
  ]) as FieldMap;
  p.normalization.nsFields={};p.normalization.vendorFields={};
  p.classification.rules=[
   {field:'action',operator:'equals',value:'deny',index:'threat'},
   {field:'action',operator:'equals',value:'allow',index:'session'},
   {field:'wrapped_action',operator:'equals',value:'deny',index:'threat'},
   {field:'wrapped_action',operator:'equals',value:'allow',index:'session'},
  ];
 }else if(entry.format==='mixed'){
  p.normalization.topFields=Object.fromEntries([
   field('src_ip','srcip','ip'),field('dst_port','dstport','port'),
   field('action','action','string'),field('src','cef_src','ip'),
   field('dpt','cef_port','port'),field('act','cef_action','string'),
   field('dstPort','leef_port','port'),
  ]) as FieldMap;
  p.normalization.nsFields={};
  p.normalization.vendorFields={};
  p.classification.rules=[
   {field:'action',operator:'equals',value:'deny',index:'threat'},
   {field:'action',operator:'equals',value:'allow',index:'session'},
   {field:'cef_action',operator:'equals',value:'deny',index:'threat'},
   {field:'cef_action',operator:'equals',value:'allow',index:'session'},
  ];
 }else if(entry.format!=='json'){
  let source='src_ip',port='dst_port',action='action';
  if(entry.format==='cef'||entry.format==='leef'){
   source='src';port=entry.format==='cef'?'dpt':'dstPort';action='act';
  }
  if(entry.format==='syslog_rfc5424'||entry.format==='syslog_rfc3164'){
   source=entry.bodyFormat==='kv'?'body.src_ip':'body.src';
   port=entry.bodyFormat==='kv'?'body.dst_port':
     entry.bodyFormat==='cef'?'body.dpt':'body.dstPort';
   action=entry.bodyFormat==='kv'?'body.action':'body.act';
  }
  p.normalization.topFields=Object.fromEntries([
   field(source,'srcip','ip'),field(port,'dstport','port'),
   field(action,'action','string'),
   ...(entry.format==='syslog_rfc5424'?
     [field('syslog_timestamp','timestamp','date')]:[]),
   ...(entry.format==='syslog_rfc3164'?
     [field('syslog_timestamp','syslog_header_time','string'),
      field('syslog_time_policy','syslog_time_policy','string')]:[])
  ]) as FieldMap;
  p.normalization.nsFields={};
  p.normalization.vendorFields={};
 }
 return p;
}
for(const entry of samples.profiles){
 if(typeof entry.raw!=='string'||Buffer.byteLength(entry.raw)>16384)
  throw new Error('Source fixture exceeds bound');
 const p=buildProject(entry);
 const sampleRows=[entry.raw,...(entry.slug==='v02_mixed'?
   samples.mixedCases.map(x=>x.raw):[]),
   ...(entry.slug==='v02_mixed_rfc5424'?
    samples.mixedSyslogCases.map(x=>x.raw):[]),
   ...(entry.slug==='v02_mixed_rfc3164'?
    samples.mixedRfc3164Cases.map(x=>x.raw):[]),
   ...(entry.transport==='blank_line_json'?
    samples.blankLineCases.map(x=>x.raw):[])];
 const digest=sha(sampleRows.join(entry.transport==='blank_line_json'?
   '\n\n':'\n'));
 const recipe=recipeFromLegacyProject(p,digest,sampleRows.length);
 const compiled=compileRecipePair({recipe,legacyProject:p});
 const baseline=compilePair(p);
 if(canonicalJson(compiled.files)!==canonicalJson(baseline.files)||
   canonicalJson(compiled.manifest)!==canonicalJson(baseline.manifest)||
   compiled.recipeReceipt.sourceHashVerifiedAgainstEvents!==false||
   compiled.recipeReceipt.nativeUserParserVerified!==false||
   compiled.recipeReceipt.targetImportVerified!==false)
  throw new Error('Recipe staged contract differs from exact v0.1 codegen');
 for(const output of compiled.files){
  const expected='customized_'+entry.slug;
  if(![expected,expected+'.conf'].includes(output.name)||
    sha(output.content)!==output.sha256)
   throw new Error('Unsafe generated fixture filename or checksum');
  writeTrusted(resolve(ROOT,output.name),output.content);
  shaList[output.name]=output.sha256;
 }
 receipts.push({slug:entry.slug,recipeSha256:compiled.recipeReceipt.recipeSha256,
  sampleSha256:digest,pairSha256:sha(canonicalJson(compiled.manifest.fileHashes))});
}
const head=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const manifest={
 kind:'parser-studio.recipe-v0.2-native-fixture-evidence.v0.1',
 origin:'independently-authored-public-synthetic',
 backendHead:head,
 fixtureSha256:sha(readFileSync(FIXTURE)),
 files:shaList,receipts,nativeUserParserVerified:false,
 targetImportVerified:false,sensorTrafficSent:false,
 caveat:'Native verification occurs only in the independently pinned Ruby smoke step.'
};
writeTrusted(MANIFEST,JSON.stringify(manifest,null,2)+'\n');
console.log('ParserRecipe v0.2: '+receipts.length+
 ' exact deterministic paired profiles generated for isolated Fluentd smoke.');
