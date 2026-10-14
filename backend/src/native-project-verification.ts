/**
 * Per-project Native verification contract.
 *
 * This layer only accepts the strict reviewed ParserRecipe v0.2 + matching
 * ParserProject and binds them to the exact source bytes and caller-supplied
 * expected output digests. Only compiler-generated Ruby/CONF may reach a
 * separately injected Native runner. Raw/normalized values are never part of
 * the public verification report and target/import status always stays false.
 */
import {createHash} from 'node:crypto';
import {compileRecipePair,type ParserRecipeV02} from './parser-recipe-v02.js';
import type {ParserProject} from './types.js';
import {canonicalJson} from './validate.js';
import {hasOnlyPairedSurrogates} from './unicode.js';

export const MAX_NATIVE_PROJECT_SOURCE_BYTES=64*1024;
export const MAX_NATIVE_PROJECT_EVENTS=500;
const SHA=/^[a-f0-9]{64}$/;
const EVENT_ID=/^event-[1-9][0-9]{0,2}$/;

export class NativeProjectVerificationError extends Error{
  readonly code:string;
  constructor(code:string){super(code);this.name='NativeProjectVerificationError';this.code=code;}
}

export interface NativeProjectExpectedEvent{
  eventId:string;
  recordSha256:string;
  eventTimeMs:number|null;
}
export interface NativeProjectVerificationRequest{
  contract:'parser-studio.native-project-request.v0.1';
  confirmed:true;
  recipe:ParserRecipeV02;
  legacyProject:ParserProject;
  source:string;
  expected:NativeProjectExpectedEvent[];
}
export interface NativeProjectPreparedEvent extends NativeProjectExpectedEvent{
  raw:string;
}
export interface NativeProjectPrepared{
  contract:'parser-studio.native-project-prepared.v0.1';
  sourceSha256:string;
  sourceHashVerifiedAgainstEvents:true;
  eventCount:number;
  recipeSha256:string;
  parserName:string;
  confName:string;
  parserSha256:string;
  confSha256:string;
  receiver:{port:number;protocols:string[]};
  files:Array<{name:string;content:string;sha256:string}>;
  events:NativeProjectPreparedEvent[];
  nativeUserParserVerified:false;
  targetImportVerified:false;
}
export interface NativeProjectVerificationReport{
  contract:'parser-studio.native-project-verification.v0.1';
  sourceSha256:string;
  recipeSha256:string;
  parserSha256:string;
  confSha256:string;
  eventCount:number;
  eventsPassed:number;
  recordHashMatches:number;
  eventTimeMatches:number;
  ruby:'3.2';
  fluentd:'1.17.1';
  confAstVerified:true;
  parserCallbackVerified:true;
  sourceHashVerifiedAgainstEvents:true;
  nativeUserParserVerified:true;
  targetImportVerified:false;
  sensorTrafficSent:false;
  rawValuesReturned:false;
}

const sha=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
const exact=(value:unknown,keys:readonly string[]):value is Record<string,unknown>=>{
  if(!value||typeof value!=='object'||Array.isArray(value))return false;
  const actual=Object.keys(value).sort(),expected=[...keys].sort();
  return actual.length===expected.length&&actual.every((key,i)=>key===expected[i]);
};
function fail(code:string):never{throw new NativeProjectVerificationError(code);}

function splitSource(source:string,boundary:'single-line'|'blank-line'):string[]{
  const lines=source.replace(/\r\n?/g,'\n').split('\n');
  if(boundary==='single-line')
    return lines.filter(raw=>raw.trim().length>0).slice(0,MAX_NATIVE_PROJECT_EVENTS+1);
  const records:string[]=[];let parts:string[]=[];
  const flush=()=>{if(parts.length)records.push(parts.join('\n'));parts=[];};
  for(const line of lines){
    if(records.length>MAX_NATIVE_PROJECT_EVENTS)break;
    if(!line.trim())flush();else parts.push(line);
  }
  if(parts.length&&records.length<=MAX_NATIVE_PROJECT_EVENTS)flush();
  return records;
}

export function prepareNativeProjectVerification(input:unknown):NativeProjectPrepared{
  if(!exact(input,['contract','confirmed','recipe','legacyProject','source','expected']))
    fail('NATIVE_PROJECT_INPUT_SHAPE');
  if(input.contract!=='parser-studio.native-project-request.v0.1'||input.confirmed!==true)
    fail('NATIVE_PROJECT_EXPLICIT_CONFIRMATION_REQUIRED');
  const req=input as unknown as NativeProjectVerificationRequest;
  if(typeof req.source!=='string'||!req.source.length||
     Buffer.byteLength(req.source,'utf8')>MAX_NATIVE_PROJECT_SOURCE_BYTES||
     !hasOnlyPairedSurrogates(req.source)||req.source.includes('\u0000'))
    fail('NATIVE_PROJECT_SOURCE_UNSUPPORTED');
  if(!Array.isArray(req.expected)||req.expected.length<1||
     req.expected.length>MAX_NATIVE_PROJECT_EVENTS)
    fail('NATIVE_PROJECT_EXPECTED_COUNT');

  const expected:NativeProjectExpectedEvent[]=req.expected.map((entry,index)=>{
    if(!exact(entry,['eventId','recordSha256','eventTimeMs'])||
       typeof entry.eventId!=='string'||!EVENT_ID.test(entry.eventId)||
       entry.eventId!==`event-${index+1}`||
       typeof entry.recordSha256!=='string'||!SHA.test(entry.recordSha256)||
       (entry.eventTimeMs!==null&&
        (typeof entry.eventTimeMs!=='number'||!Number.isSafeInteger(entry.eventTimeMs)||
         Math.abs(entry.eventTimeMs)>8640000000000000)))
      fail('NATIVE_PROJECT_EXPECTED_INVALID');
    return {eventId:entry.eventId,recordSha256:entry.recordSha256,
      eventTimeMs:entry.eventTimeMs as number|null};
  });

  let compiled;
  try{compiled=compileRecipePair({recipe:req.recipe,legacyProject:req.legacyProject});}
  catch{fail('NATIVE_PROJECT_RECIPE_UNSUPPORTED');}
  const digest=sha(req.source);
  if(digest!==compiled.recipeReceipt.sourceSha256||
     digest!==req.recipe.sample.sha256)
    fail('NATIVE_PROJECT_SOURCE_HASH_MISMATCH');
  const first=req.recipe.stages[0];
  if(!first||first.op!=='split_event')fail('NATIVE_PROJECT_BOUNDARY_UNSUPPORTED');
  const records=splitSource(req.source,first.boundary);
  if(records.length<1||records.length>MAX_NATIVE_PROJECT_EVENTS||
     records.length!==req.recipe.sample.events||
     records.length!==compiled.recipeReceipt.sampleEventCount||
     records.length!==expected.length)
    fail('NATIVE_PROJECT_EVENT_COUNT_MISMATCH');

  if(compiled.files.length!==2)fail('NATIVE_PROJECT_PAIR_SHAPE');
  const fragment=compiled.files.find(x=>!x.name.endsWith('.conf'));
  const conf=compiled.files.find(x=>x.name.endsWith('.conf'));
  if(!fragment||!conf||conf.name!==fragment.name+'.conf'||
     !SHA.test(fragment.sha256)||!SHA.test(conf.sha256)||
     sha(fragment.content)!==fragment.sha256||sha(conf.content)!==conf.sha256)
    fail('NATIVE_PROJECT_PAIR_HASH_MISMATCH');
  if(fragment.name!=='customized_'+req.legacyProject.slug)
    fail('NATIVE_PROJECT_PAIR_IDENTITY');

  return {
    contract:'parser-studio.native-project-prepared.v0.1',
    sourceSha256:digest,sourceHashVerifiedAgainstEvents:true,
    eventCount:records.length,recipeSha256:compiled.recipeReceipt.recipeSha256,
    parserName:fragment.name,confName:conf.name,
    parserSha256:fragment.sha256,confSha256:conf.sha256,
    receiver:{port:req.legacyProject.receiver.port,
      protocols:[...req.legacyProject.receiver.protocols]},
    files:compiled.files.map(f=>({name:f.name,content:f.content,sha256:f.sha256})),
    events:records.map((raw,index)=>({...expected[index]!,raw})),
    nativeUserParserVerified:false,targetImportVerified:false,
  };
}

const REPORT_KEYS=[
  'contract','sourceSha256','recipeSha256','parserSha256','confSha256',
  'eventCount','eventsPassed','recordHashMatches','eventTimeMatches',
  'ruby','fluentd','confAstVerified','parserCallbackVerified',
  'sourceHashVerifiedAgainstEvents','nativeUserParserVerified',
  'targetImportVerified','sensorTrafficSent','rawValuesReturned',
] as const;

export function verifyNativeProjectReport(
 input:unknown,prepared:NativeProjectPrepared
):NativeProjectVerificationReport{
  if(!exact(input,REPORT_KEYS))fail('NATIVE_PROJECT_REPORT_SHAPE');
  const r=input as unknown as NativeProjectVerificationReport;
  if(r.contract!=='parser-studio.native-project-verification.v0.1'||
     r.sourceSha256!==prepared.sourceSha256||
     r.recipeSha256!==prepared.recipeSha256||
     r.parserSha256!==prepared.parserSha256||
     r.confSha256!==prepared.confSha256||
     r.eventCount!==prepared.eventCount||
     r.eventsPassed!==prepared.eventCount||
     r.recordHashMatches!==prepared.eventCount||
     r.eventTimeMatches!==prepared.eventCount||
     r.ruby!=='3.2'||r.fluentd!=='1.17.1'||
     r.confAstVerified!==true||r.parserCallbackVerified!==true||
     r.sourceHashVerifiedAgainstEvents!==true||
     r.nativeUserParserVerified!==true||
     r.targetImportVerified!==false||r.sensorTrafficSent!==false||
     r.rawValuesReturned!==false)
    fail('NATIVE_PROJECT_REPORT_UNTRUSTED');
  return {...r};
}

/** Utility shared by deterministic tests/clients when producing expected hashes. */
export function nativeRecordSha256(record:unknown):string{
  return sha(canonicalJson(record));
}
