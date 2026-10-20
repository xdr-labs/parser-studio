/** P0-AP1: bounded local envelope/body census, never a native parser runner.
 * Return ONLY fixed identifiers, counts and source line numbers. Untrusted
 * source strings, diagnostic messages and field values never enter this report.
 */
import {MAX_DATASET_BYTES,MAX_EVENTS,MAX_LINE_CHARS,splitEvents,tokenizeCSV} from '../parser';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {extractStructuredFamily} from '../structuredFamilies';
import {parseJavaStacktrace} from '../javaStacktrace';
import type {BackendCapabilities} from './backendCapabilities';
import type {EventBoundary} from './contract';
import {inspectDeclaredForwarders,type ForwarderConfig} from './declaredForwarder';

export type Envelope='none'|'rfc3164'|'rfc5424';
export type Body='json'|'kv'|'cef'|'leef'|'csv'|'java_stacktrace'|'unknown';
export type EntryStatus='RECOGNIZED'|'HEADER_MALFORMED'|'BODY_MALFORMED'|
  'BOUNDARY_AMBIGUOUS'|'TOO_LONG'|'UNKNOWN';
export interface EnvelopeEntry{
  sequence:number;line:number;envelope:Envelope;body:Body;
  status:EntryStatus;
  timePolicy:'EXPLICIT_TIME'|'YEAR_AND_ZONE_UNKNOWN'|'NO_TIMESTAMP';
  rfc3164Profile?:'strict_tagged'|'tagless_structured_security';
  relayHops?:number;
}
export interface EnvelopeLedger{
  contract:'auto-parser.envelopes.v0.1';
  status:'READY'|'NO_SAMPLES'|'SOURCE_LIMIT';
  sourceCount:number;accounted:number;unsupported:number;
  complete:boolean;boundary:EventBoundary;
  events:EnvelopeEntry[];
  families:Array<{envelope:Envelope;body:Body;count:number}>;
  nativeVerified:false;targetVerified:false;
  forwarderConfigured?:boolean;relayEvents?:number;
}
export type CompilerAssessment={
  status:'DRAFT_COMPILABLE'|'COMPILER_UNSUPPORTED'|'MIXED_OR_UNKNOWN'|
    'COLUMNS_REQUIRED'|'BOUNDARY_REVIEW'|'BACKEND_UNAVAILABLE'|
    'BACKEND_UNTRUSTED'|'SOURCE_LIMIT';
  format:'json'|'kv'|'csv'|'cef'|'leef'|'syslog_rfc3164'|'syslog_rfc5424'|'mixed'|'java_stacktrace'|null;
  mixedFormats?:Array<'json'|'kv'|'cef'|'leef'|'rfc5424_cef'|'rfc5424_leef'|'rfc3164_kv'|'rfc5424_json'|'rfc5424_kv'|'rfc3164_cef'|'rfc3164_leef'|'csv'>;
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
    let leaves=0;
    const descend=(node:unknown,depth:number):boolean=>{
      if(depth>8)return false;
      if(!node||typeof node!=='object'){
        leaves++;
        return leaves<=4096;
      }
      if(Array.isArray(node))return node.every(item=>descend(item,depth+1));
      return Object.entries(node).every(([name,item])=>
        name!=='__proto__'&&name!=='constructor'&&name!=='prototype'&&
        descend(item,depth+1));
    };
    return descend(value,0);
  }catch{return false;}
}
function csvValid(input:string):boolean{
  // Candidate syntax must agree with the already qualified strict CSV lexer.
  // Counting delimiters with quote toggles alone accepts trailing bytes after
  // closing quotes and quotes embedded in an unquoted field. Those are not
  // valid RFC4180-style records for the downloadable CSV parser.
  // A successful lexer check proves grammar only; names still need review.
  return [',',';','\t'].some(delimiter=>{
    const fields=tokenizeCSV(input,delimiter);
    if(fields===null)return false;
    if(fields.length>=3)return true;
    // With only two values, an unquoted comma can be ordinary prose.
    // Accept just an explicitly fully quoted field pair after the shared
    // strict lexer has validated escapes and post-quote boundaries.
    // This establishes CSV syntax, never guessed CSV field names.
    return fields.length===2&&input.startsWith('"')&&input.endsWith('"')&&
      input.includes('"'+delimiter+'"');
  });
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
  // A full key=value record wins over incidental comma/semicolon/TAB data.
  // But a positional CSV record may contain '=' in any field (for example,
  // a URL query), not only when its first field happens to be quoted.
  const hasEquals=value.includes('=');
  if(hasEquals&&kvValid(value))return {body:'kv',status:'RECOGNIZED'};
  if(value.includes(',')||value.includes(';')||value.includes('\t')){
    // Do not turn a malformed leading key=value record into CSV success just
    // because its later free-form bytes contain two separators. A candidate
    // CSV still needs the shared strict lexer and reviewed field names.
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,95}\s*=/.test(value)){
      return {body:'csv',status:csvValid(value)?'RECOGNIZED':'BODY_MALFORMED'};
    }
  }
  if(hasEquals)return {body:'kv',status:'BODY_MALFORMED'};
  return {body:'unknown',status:'UNKNOWN'};
}
function analyzeRecord(text:string,sequence:number,line:number,boundary:EventBoundary,
  forwarder?:ForwarderConfig):EnvelopeEntry{
  if(forwarder){
    const inspection=inspectDeclaredForwarders(text,forwarder);
    if(inspection.status==='ABSTAIN_UNSAFE')
      return {sequence,line,envelope:'none',body:'unknown',
        timePolicy:'NO_TIMESTAMP',status:'HEADER_MALFORMED'};
    if(inspection.status==='UNWRAPPED'){
      const inner=analyzeRecord(inspection.payload,sequence,line,boundary);
      return {...inner,relayHops:inspection.hops.length};
    }
  }
  const raw=text.trim();
  const base={sequence,line,timePolicy:'NO_TIMESTAMP' as EnvelopeEntry['timePolicy']};
  if(text.length>MAX_LINE_CHARS)
    return {...base,envelope:'none',body:'unknown',status:'TOO_LONG'};
  if(text.includes('\n')||text.includes('\r')){
    if(boundary==='blank-line'&&parseJavaStacktrace(text).errors.length===0)
      return {...base,envelope:'none',body:'java_stacktrace',status:'RECOGNIZED'};
    return {...base,envelope:'none',body:'unknown',status:'BOUNDARY_AMBIGUOUS'};
  }
  // Bounded tagless BSD security envelope, including an optional PRI.
  // It is accepted only when the body begins with an explicit structured
  // signature; arbitrary prose remains unknown and cannot become DRAFT-ready.
  const tagless=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+([!-~]{1,255})\s+((?:\{|CEF:|LEEF:|[A-Za-z_][A-Za-z0-9_.-]{0,95}=).+)$/.exec(raw);
  if(tagless){
    const pri=tagless[1]===undefined?undefined:Number(tagless[1]);
    const classified=classifyBody(tagless[8]!);
    if((pri===undefined||pri<=191)&&MONTH_DAYS[tagless[2]!]&&
      Number(tagless[3])>=1&&Number(tagless[3])<=MONTH_DAYS[tagless[2]!]&&
      Number(tagless[4])<=23&&Number(tagless[5])<=59&&Number(tagless[6])<=59)
      return {...base,envelope:'rfc3164',...classified,
        timePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164Profile:'tagless_structured_security'};
  }
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
      timePolicy:'YEAR_AND_ZONE_UNKNOWN',rfc3164Profile:'strict_tagged'};
  }
  return {...base,envelope:'none',...classifyBody(raw)};
}
export function analyzeLogEnvelopes(source:string,boundary:EventBoundary,forwarder?:ForwarderConfig):EnvelopeLedger{
  if(typeof source!=='string'||!['single-line','blank-line'].includes(boundary))
    return EMPTY('SOURCE_LIMIT','single-line');
  if(new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES)
    return EMPTY('SOURCE_LIMIT',boundary);
  // Native Java strict LF LF grammar rejects CR. Do not normalize raw CRLF
  // into a false browser/native DRAFT equivalence.
  if(boundary==='blank-line'&&source.includes('\r'))
    return EMPTY('SOURCE_LIMIT',boundary);
  if(!source.trim())return EMPTY('NO_SAMPLES',boundary);
  const records=splitEvents(source,boundary,MAX_EVENTS+1);
  if(records.length>MAX_EVENTS)return EMPTY('SOURCE_LIMIT',boundary,records.length);
  const events=records.map((item,index)=>analyzeRecord(item.raw,index+1,item.line,boundary,forwarder));
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
    ...(forwarder?{forwarderConfigured:true,
      relayEvents:events.filter(event=>(event.relayHops??0)>0).length}:{}),
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
  if(report.forwarderConfigured){
    if(!cap)return no('BACKEND_UNAVAILABLE');
    if(cap.authoring?.declaredForwarderEnvelopeUnwrap!==true||
      cap.authoring.declaredForwarderMaximumHops!==3)
      return no('COMPILER_UNSUPPORTED');
  }
  if(report.boundary==='blank-line'){
    if(report.families.length!==1||
       report.families[0]?.envelope!=='none'||
       report.families[0]?.body!=='java_stacktrace'||
       report.unsupported!==0||report.accounted!==report.sourceCount||
       report.events.some(e=>e.status!=='RECOGNIZED'))
      return no('BOUNDARY_REVIEW');
    if(!cap)return no('BACKEND_UNAVAILABLE');
    if(cap.verification?.engineVerified!==false||
       cap.verification?.targetImportVerified!==false)
      return no('BACKEND_UNTRUSTED');
    if(!cap.authoring?.extractionFormats?.includes('java_stacktrace')||
       cap.authoring.javaBlankLineTcpFraming!==true||
       cap.authoring.javaBlankLineOtherTransports!==false||
       cap.authoring.javaBlankLineDelimiter!=='LF_LF'||
       cap.authoring.javaStackTraceGrammar!=='EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1')
      return no('COMPILER_UNSUPPORTED');
    return {status:'DRAFT_COMPILABLE',format:'java_stacktrace',bodyFormat:null,
      nativeVerified:false,targetVerified:false};
  }
  if(report.boundary!=='single-line'||
    report.events.some(e=>e.status==='BOUNDARY_AMBIGUOUS'))
    return no('BOUNDARY_REVIEW');
  const hasTaglessRfc3164=report.events.some(
    e=>e.rfc3164Profile==='tagless_structured_security');
  if(report.unsupported>0||report.accounted!==report.sourceCount||
    report.families.length>4)return no('MIXED_OR_UNKNOWN');
  if(report.families.length>1){
    // Exactly 2–4 explicitly reviewed fixed families. RFC3164 accepts
    // strict TAG: KV only, with year/zone ALWAYS UNKNOWN; RFC5424 accepts
    // reviewed CEF/LEEF/JSON/KV wrappers only. Unknown/malformed never fallback; CSV requires user-reviewed columns.
    const formats=report.families.map(f=>
      f.envelope==='none'?f.body:
      f.envelope==='rfc5424'&&['cef','leef','json','kv'].includes(f.body)?
        'rfc5424_'+f.body:
      f.envelope==='rfc3164'&&['kv','cef','leef'].includes(f.body)?
        'rfc3164_'+f.body:null);
    const basic=['json','kv','cef','leef'];
    const wrapped=['rfc5424_cef','rfc5424_leef'];
    const rfc3164=['rfc3164_kv','rfc3164_cef','rfc3164_leef'];
    const nested=['rfc5424_json','rfc5424_kv'];
    const known=[...basic,...wrapped,...rfc3164,...nested,'csv'];
    if(formats.some(f=>f===null||!known.includes(f))||
      new Set(formats).size!==formats.length)return no('MIXED_OR_UNKNOWN');
    if(!cap)return no('BACKEND_UNAVAILABLE');
    if(cap.verification?.engineVerified!==false||
      cap.verification?.targetImportVerified!==false)return no('BACKEND_UNTRUSTED');
    const mixedClaim:unknown=cap.authoring?.strictMixedRequiresExplicitAllowlist;
    if(mixedClaim===false)return no('BACKEND_UNTRUSTED');
    const advertised=cap.authoring?.strictMixedSingleLineFamilies;
    if(formats.some(name=>name?.startsWith('rfc3164_'))&&(
      cap.authoring.rfc3164StrictTaggedMessageSubset!==true||
      (hasTaglessRfc3164&&cap.authoring.rfc3164TaglessStructuredSecuritySubset!==true)||
      cap.authoring.rfc3164TimePolicy!=='YEAR_AND_ZONE_UNKNOWN'||
      cap.authoring.rfc3164NativeTimeReconstruction!==false||
      !formats.filter(name=>name?.startsWith('rfc3164_')).every(name=>
        cap.authoring.rfc3164BodyFormats?.includes(name!.slice(8) as 'kv'|'cef'|'leef'))))
      return no('COMPILER_UNSUPPORTED');
    if(!cap.authoring?.extractionFormats?.includes('mixed')||
      cap.authoring.strictMixedRequiresExplicitAllowlist!==true||
      !Array.isArray(advertised)||![4,6,7,9,11,12].includes(advertised.length)||
      new Set(advertised).size!==advertised.length||
      !basic.every(name=>advertised.includes(name as 'json'))||
      (advertised.length>=6&&!wrapped.every(name=>advertised.includes(name as 'rfc5424_cef')))||
      (advertised.length>=7&&!advertised.includes('rfc3164_kv'))||
      (advertised.length>=11&&!rfc3164.every(name=>advertised.includes(name as 'rfc3164_kv')))||
      (advertised.length===12&&!advertised.includes('csv'))||
      (advertised.length>=9&&!nested.every(name=>advertised.includes(name as 'rfc5424_json')))||
      !formats.every(name=>advertised.includes(name as 'json')))
      return no('COMPILER_UNSUPPORTED');
    return {status:'DRAFT_COMPILABLE',format:'mixed',
      bodyFormat:null,mixedFormats:formats.slice().sort() as Array<'json'|'kv'|'cef'|'leef'|'rfc5424_cef'|'rfc5424_leef'|'rfc3164_kv'|'rfc5424_json'|'rfc5424_kv'|'rfc3164_cef'|'rfc3164_leef'|'csv'>,
      nativeVerified:false,targetVerified:false};
  }
  if(report.families.length!==1)return no('MIXED_OR_UNKNOWN');
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
      (hasTaglessRfc3164&&cap.authoring.rfc3164TaglessStructuredSecuritySubset!==true)||
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
