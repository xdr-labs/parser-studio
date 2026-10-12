/** Beginner-facing format guidance from the current bounded local Web Worker.
 * Never exports sample values, worker reasons, diagnostic text or source bytes.
 * A recommendation is not a native parser compile, multi-family router or
 * permission to download, install or run a Stellar parser.
 */
import type {ConcreteFormat,SuiteResult} from '../model';
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import type {EventBoundary} from './contract';

const ALL=new Set<string>([
  'json','kv','csv','syslog_rfc5424','cef','leef','syslog','regex','unknown',
]);
const SAFE=new Set<string>(['json','kv','syslog_rfc5424','cef','leef']);
export type LocalFormatStatus=
  'NO_SAMPLES'|'NO_PREVIEW'|'LIMIT_EXCEEDED'|'MULTILINE_UNVERIFIED'|
  'UNTRUSTED_PREVIEW'|'SOURCE_MISMATCH'|'MIXED_FORMATS'|'UNKNOWN_EVENTS'|
  'MANUAL_REVIEW'|'PREVIEW_FAILED'|'CANDIDATE_UNTESTED'|'RECOMMENDED';
export interface LocalFormatAdvice{
  status:LocalFormatStatus;
  format:ConcreteFormat|null;
  totalEvents:number;
  reviewedEvents:number;
  families:Array<{format:ConcreteFormat|'unknown';count:number}>;
  confidencePercent:number;
  nativeVerified:false;
}
const empty=(status:LocalFormatStatus):LocalFormatAdvice=>({
  status,format:null,totalEvents:0,reviewedEvents:0,
  families:[],confidencePercent:0,nativeVerified:false,
});
const integer=(value:unknown,min:number,max:number)=>
  typeof value==='number'&&Number.isSafeInteger(value)&&value>=min&&value<=max;

export function recommendLocalFormat(
  raw:string,suite:SuiteResult|undefined,boundary:EventBoundary,
):LocalFormatAdvice {
  if(typeof raw!=='string'||!['single-line','blank-line'].includes(boundary))
    return empty('UNTRUSTED_PREVIEW');
  const bytes=new TextEncoder().encode(raw).byteLength;
  if(bytes>MAX_DATASET_BYTES)return empty('LIMIT_EXCEEDED');
  if(!raw.trim())return empty('NO_SAMPLES');
  if(boundary!=='single-line')return empty('MULTILINE_UNVERIFIED');
  const source=splitEvents(raw,boundary,MAX_EVENTS+1);
  if(source.length>MAX_EVENTS)return empty('LIMIT_EXCEEDED');
  if(!source.length)return empty('NO_SAMPLES');
  if(!suite)return empty('NO_PREVIEW');
  if(suite.engine!=='browser-preview'||suite.nativeFluentdVerified!==false||
    suite.stellarExportVerified!==false||!Array.isArray(suite.events)||
    !suite.counts||!integer(suite.counts.total,0,MAX_EVENTS)||
    suite.counts.total!==source.length||
    !integer(suite.counts.matched,0,MAX_EVENTS)||
    !integer(suite.counts.extracted,0,MAX_EVENTS)||
    !integer(suite.counts.normalized,0,MAX_EVENTS)||
    suite.events.length!==source.length)return empty('UNTRUSTED_PREVIEW');

  const tally=new Map<ConcreteFormat|'unknown',number>();
  let reviewed=0,minConfidence=1;
  for(let i=0;i<source.length;i++){
    const event=suite.events[i]!;
    const record=source[i]!;
    if(!event||event.raw!==record.raw||event.line!==record.line||
      event.id!=='event-'+(i+1))return empty('SOURCE_MISMATCH');
    if(!event.detected||typeof event.detected.format!=='string'||
      !ALL.has(event.detected.format)||
      typeof event.detected.confidence!=='number'||
      !Number.isFinite(event.detected.confidence)||
      event.detected.confidence<0||event.detected.confidence>1||
      typeof event.matched!=='boolean'||typeof event.extracted!=='boolean'||
      !['pass','warning','fail'].includes(event.status))return empty('UNTRUSTED_PREVIEW');
    const family=event.detected.format as ConcreteFormat|'unknown';
    tally.set(family,(tally.get(family)??0)+1);
    if(event.matched&&event.extracted)reviewed++;
    minConfidence=Math.min(minConfidence,event.detected.confidence);
  }
  const families=[...tally].map(([format,count])=>({format,count}))
    .sort((a,b)=>b.count-a.count||a.format.localeCompare(b.format));
  const summary:LocalFormatAdvice={
    status:'UNTRUSTED_PREVIEW',format:null,totalEvents:source.length,
    reviewedEvents:reviewed,families,
    confidencePercent:Math.round(minConfidence*100),nativeVerified:false,
  };
  if(tally.has('unknown'))return {...summary,status:'UNKNOWN_EVENTS'};
  if(families.length>1)return {...summary,status:'MIXED_FORMATS'};
  const one=families[0]?.format;
  if(!one||!SAFE.has(one)||minConfidence<0.85)
    return {...summary,status:'MANUAL_REVIEW'};
  // A forced extractor may produce fields even when it differs from the
  // detected family. Do not count that as extraction verified for the
  // proposed parser format; offer a signature-only recheck instead.
  if(!suite.events.every(event=>event.effectiveFormat===one)){
    if(!suite.events.every(event=>
      typeof event.effectiveFormat==='string'&&
      ALL.has(event.effectiveFormat)&&event.effectiveFormat!=='unknown'))
      return {...summary,status:'UNTRUSTED_PREVIEW',format:null};
    return {...summary,status:'CANDIDATE_UNTESTED',
      format:one as ConcreteFormat};
  }
  if(reviewed!==source.length)
    return {...summary,status:'PREVIEW_FAILED'};
  return {...summary,status:'RECOMMENDED',format:one as ConcreteFormat};
}
