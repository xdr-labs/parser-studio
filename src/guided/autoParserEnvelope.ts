/** P0-AP1: bounded local envelope/body census, never a native parser runner.
 * Return ONLY fixed identifiers, counts and source line numbers. Untrusted
 * source strings, diagnostic messages and field values never enter this report.
 */
import {MAX_DATASET_BYTES,MAX_EVENTS,MAX_LINE_CHARS,splitEvents} from '../parser';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {extractStructuredFamily} from '../structuredFamilies';
import type {BackendCapabilities} from './backendCapabilities';
import type {EventBoundary} from './contract';

export type Envelope='none'|'rfc3164'|'rfc5424';
export type Body='json'|'kv'|'cef'|'leef'|'csv'|'unknown';
export type EntryStatus='RECOGNIZED'|'HEADER_MALFORMED'|'BODY_MALFORMED'|
  'BOUNDARY_AMBIGUOUS'|'TOO_LONG'|'UNKNOWN';
export interface EnvelopeEntry{
  sequence:number;line:number;envelope:Envelope;body:Body;
  status:EntryStatus;
  timePolicy:'EXPLICIT_TIME'|'YEAR_AND_ZONE_UNKNOWN'|'NO_TIMESTAMP';
}
export interface EnvelopeLedger{
  contract:'auto-parser.envelopes.v0.1';
  status:'READY'|'NO_SAMPLES'|'SOURCE_LIMIT';
  sourceCount:number;accounted:number;unsupported:number;
  complete:boolean;boundary:EventBoundary;
  events:EnvelopeEntry[];
  families:Array<{envelope:Envelope;body:Body;count:number}>;
  nativeVerified:false;targetVerified:false;
}
export type CompilerAssessment={
  status:'DRAFT_COMPILABLE'|'COMPILER_UNSUPPORTED'|'MIXED_OR_UNKNOWN'|
    'COLUMNS_REQUIRED'|'BOUNDARY_REVIEW'|'BACKEND_UNAVAILABLE'|
    'BACKEND_UNTRUSTED'|'SOURCE_LIMIT';
  format:'json'|'kv'|'csv'|'cef'|'leef'|'syslog_rfc3164'|'syslog_rfc5424'|null;
  bodyFormat:'raw'|'json'|'kv'|'cef'|'leef'|null;
  nativeVerified:false;targetVerified:false;
};
const EMPTY=(status:EnvelopeLedger['status'],boundary:EventBoundary,sourceCount=0):EnvelopeLedger=>({
  contract:'auto-parser.envelopes.v0.1',status,sourceCount,
  accounted:0,unsupported:sourceCount,complete:status==='NO_SAMPLES',
  boundary,events:[],families:[],nativeVerified:false,targetVerified:false,
});
const MONTH_DAYS:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
const KV_TOKEN=/^([A-Za-z_][A-Za-z0-9_.-]{0,95})=(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"'\\]+)(?=\s|$)/;
function kvValid(input:string):boolean{
  let index=0,count=0;
  while(index<input.length){
    while(index<input.length&&/\s/.test(input[index]!))index++;
    if(index===input.length)break;
    const match=KV_TOKEN.exec(input.slice(index));
    if(!match)return false;
    count++;if(count>100)return false;
    index+=match[0].length;
  }
  return count>0;
}
function jsonValid(input:string):boolean{
  try{
    const value=JSON.parse(input) as unknown;
    if(!value||typeof value!=='object'||Array.isArray(value))return false;
    const descend=(node:unknown,depth:number):boolean=>{
      if(depth>8)return false;
      if(!node||typeof node!=='object')return true;
      if(Array.isArray(node))return node.length<=128&&node.every(item=>descend(item,depth+1));
      const entries=Object.entries(node);
      return entries.length<=128&&entries.every(([name,item])=>
        name!=='__proto__'&&name!=='constructor'&&name!=='prototype'&&
        descend(item,depth+1));
    };
    return descend(value,0);
  }catch{return false;}
}
function csvValid(input:string):boolean{
  // Lexical candidate only; columns must be explicitly named and reviewed.
  let quote=false,commas=0;
  for(let i=0;i<input.length;i++){
    const c=input[i]!;
    if(c==='"'){
      if(quote&&input[i+1]==='"'){i++;continue;}
      quote=!quote;
    }else if(c===','&&!quote)commas++;
  }
  return !quote&&commas>=2;
}
function classifyBody(text:string):{body:Body;status:EntryStatus}{
  const value=text.trim();
  if(!value)return {body:'unknown',status:'UNKNOWN'};
  if(value[0]==='{'){
    return {body:'json',status:jsonValid(value)?'RECOGNIZED':'BODY_MALFORMED'};
  }
  if(value.startsWith('CEF:')){
    return {body:'cef',status:extractStructuredFamily(value,'cef').errors.length===0?
      'RECOGNIZED':'BODY_MALFORMED'};
  }
  if(value.startsWith('LEEF:')){
    return {body:'leef',status:extractStructuredFamily(value,'leef').errors.length===0?
      'RECOGNIZED':'BODY_MALFORMED'};
  }
  if(value.includes('=')){
    return {body:'kv',status:kvValid(value)?'RECOGNIZED':'BODY_MALFORMED'};
  }
  if(value.includes(',')){
    return {body:'csv',status:csvValid(value)?'RECOGNIZED':'BODY_MALFORMED'};
  }
  return {body:'unknown',status:'UNKNOWN'};
}
function analyzeRecord(text:string,sequence:number,line:number):EnvelopeEntry{
  const raw=text.trim();
  const base={sequence,line,timePolicy:'NO_TIMESTAMP' as EnvelopeEntry['timePolicy']};
  if(text.length>MAX_LINE_CHARS)
    return {...base,envelope:'none',body:'unknown',status:'TOO_LONG'};
  if(text.includes('\n')||text.includes('\r'))
    return {...base,envelope:'none',body:'unknown',status:'BOUNDARY_AMBIGUOUS'};
  if(raw.startsWith('<')){
    if(/^<\d{1,3}>1\s/.test(raw)){
      const scanned=parseRfc5424Subset(raw);
      if(!scanned.ok)return {...base,envelope:'rfc5424',body:'unknown',status:'HEADER_MALFORMED'};
      const classified=classifyBody(scanned.message??'');
      return {...base,envelope:'rfc5424',...classified,
        timePolicy:scanned.fields.syslog_timestamp==='-'?'NO_TIMESTAMP':'EXPLICIT_TIME'};
    }
    // RFC3164 has no year or zone. A browser hypothesis MUST NOT fabricate
    // time, a native export adapter, or a vendor-approved parsing status.
    const match=/^<(\d{1,3})>([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+([^\s]{1,255})\s+(.+)$/.exec(raw);
    if(!match||Number(match[1])>191||!MONTH_DAYS[match[2]!]||
      Number(match[3])<1||Number(match[3])>MONTH_DAYS[match[2]!]||
      Number(match[4])>23||Number(match[5])>59||Number(match[6])>59)
      return {...base,envelope:'rfc3164',body:'unknown',status:'HEADER_MALFORMED'};
    const tag=/^([A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\[(\d{1,8})\])?: +(.+)$/.exec(match[8]!);
    if(!tag)return {...base,envelope:'rfc3164',body:'unknown',status:'HEADER_MALFORMED'};
    return {...base,envelope:'rfc3164',...classifyBody(tag[3]!),
      timePolicy:'YEAR_AND_ZONE_UNKNOWN'};
  }
  return {...base,envelope:'none',...classifyBody(raw)};
}
export function analyzeLogEnvelopes(source:string,boundary:EventBoundary):EnvelopeLedger{
  if(typeof source!=='string'||!['single-line','blank-line'].includes(boundary))
    return EMPTY('SOURCE_LIMIT','single-line');
  if(new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES)
    return EMPTY('SOURCE_LIMIT',boundary);
  if(!source.trim())return EMPTY('NO_SAMPLES',boundary);
  const records=splitEvents(source,boundary,MAX_EVENTS+1);
  if(records.length>MAX_EVENTS)return EMPTY('SOURCE_LIMIT',boundary,records.length);
  const events=records.map((item,index)=>analyzeRecord(item.raw,index+1,item.line));
  const groups=new Map<string,{envelope:Envelope;body:Body;count:number}>();
  for(const event of events){
    const id=event.envelope+'/'+event.body;
    const entry=groups.get(id);
    if(entry)entry.count++;
    else groups.set(id,{envelope:event.envelope,body:event.body,count:1});
  }
  return {contract:'auto-parser.envelopes.v0.1',status:'READY',boundary,
    sourceCount:records.length,accounted:events.length,
    unsupported:events.filter(e=>e.status!=='RECOGNIZED').length,
    complete:events.length===records.length,events,
    families:[...groups.values()].sort((a,b)=>b.count-a.count||
      (a.envelope+'/'+a.body).localeCompare(b.envelope+'/'+b.body)),
    nativeVerified:false,targetVerified:false};
}
export function assessEnvelopeCompilation(
  report:EnvelopeLedger,cap:BackendCapabilities|null,
):CompilerAssessment{
  const no=(status:CompilerAssessment['status']):CompilerAssessment=>
    ({status,format:null,bodyFormat:null,nativeVerified:false,targetVerified:false});
  if(!report.complete||report.status!=='READY'||report.sourceCount===0)
    return no('SOURCE_LIMIT');
  if(report.boundary!=='single-line'||
    report.events.some(e=>e.status==='BOUNDARY_AMBIGUOUS'))
    return no('BOUNDARY_REVIEW');
  if(report.unsupported>0||report.accounted!==report.sourceCount||
    report.families.length!==1)return no('MIXED_OR_UNKNOWN');
  if(!cap)return no('BACKEND_UNAVAILABLE');
  if(cap.verification?.engineVerified!==false||
    cap.verification?.targetImportVerified!==false||
    !Array.isArray(cap.authoring?.extractionFormats))return no('BACKEND_UNTRUSTED');
  const family=report.families[0]!;
  if(family.envelope==='rfc3164'&&
      cap.authoring.rfc3164TimePolicy!==undefined&&
      cap.authoring.rfc3164TimePolicy!=='YEAR_AND_ZONE_UNKNOWN')
    return no('BACKEND_UNTRUSTED');
  if(family.envelope==='rfc3164'&&(
      cap.authoring.rfc3164StrictTaggedMessageSubset!==true||
      cap.authoring.rfc3164TimePolicy!=='YEAR_AND_ZONE_UNKNOWN'||
      cap.authoring.rfc3164NativeTimeReconstruction!==false||
      !cap.authoring.rfc3164BodyFormats?.includes(family.body as 'kv')
   ))return no('COMPILER_UNSUPPORTED');
  if(family.body==='csv')return no(family.envelope==='none'?'COLUMNS_REQUIRED':'COMPILER_UNSUPPORTED');
  const format=family.envelope==='rfc5424'?'syslog_rfc5424':
    family.envelope==='rfc3164'?'syslog_rfc3164':family.body;
  if(!['json','kv','cef','leef','syslog_rfc3164','syslog_rfc5424'].includes(format)||
     !cap.authoring.extractionFormats.includes(format as 'json')||
     (family.envelope==='rfc5424'&&
       !cap.authoring.rfc5424BodyFormats?.includes(family.body as 'json')))
    return no('COMPILER_UNSUPPORTED');
  return {status:'DRAFT_COMPILABLE',format:format as CompilerAssessment['format'],
    bodyFormat:family.envelope==='rfc5424'||family.envelope==='rfc3164'?
      family.body as CompilerAssessment['bodyFormat']:null,
    nativeVerified:false,targetVerified:false};
}
