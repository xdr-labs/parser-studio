import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {listSafeLeafPaths} from '../fieldPaths';

export interface NamedLogType {
  id:string;
  name:string;
  sample:string;
}
export interface NamedLogSpan {
  id:string;
  name:string;
  startByte:number;
  endByte:number;
}
export interface NamedLogAssembly {
  source:string;
  spans:NamedLogSpan[];
}
export interface NamedLogValidation {
  ok:boolean;
  issues:string[];
  bytes:number;
}
export interface NamedLogAnalysis {
  id:string;
  name:string;
  events:number;
  parsed:number;
  partial:number;
  rawOnly:number;
  fields:string[];
  boundaryWarning:boolean;
}
export const MAX_NAMED_LOG_TYPES=10;
export const MAX_NAMED_LOG_BYTES=65536;
const encoder=new TextEncoder();
const byteSize=(value:string)=>encoder.encode(value).length;
const SAFE_NAME=/^[^\u0000-\u001f\u007f]{1,64}$/;

export function newNamedLogType(id:string,name:string,sample=''):NamedLogType{
  return {id,name,sample};
}

/** A joined source is a working dataset, not a fabricated on-wire event.
 * Every individual group remains byte-identical; only separators are added.
 */
export function assembleNamedLogs(groups:readonly NamedLogType[]):NamedLogAssembly{
  let source='';
  let size=0;
  const spans:NamedLogSpan[]=[];
  for(const group of groups){
    if(!group.sample.trim())continue;
    if(source.length){source+='\n';size++;}
    const startByte=size;
    source+=group.sample;
    size+=byteSize(group.sample);
    spans.push({id:group.id,name:group.name,startByte,endByte:size});
  }
  return {source,spans};
}

export function validateNamedLogs(groups:readonly NamedLogType[]):NamedLogValidation{
  const issues:string[]=[];
  if(groups.length<1||groups.length>MAX_NAMED_LOG_TYPES)
    issues.push('Use 1–10 named log types for one review.');
  const ids=new Set<string>();
  const reserved=new Set(['__proto__','prototype','constructor']);
  const names=new Set<string>();
  groups.forEach((group,index)=>{
    const label='Log type '+(index+1);
    if(!/^[A-Za-z0-9_-]{1,80}$/.test(group.id)||ids.has(group.id)||reserved.has(group.id))
      issues.push(label+': the internal group identity is invalid.');
    ids.add(group.id);
    const name=group.name.trim();
    const folded=name.toLocaleLowerCase('en-US');
    if(!SAFE_NAME.test(name))issues.push(label+': enter a name (up to 64 characters).');
    else if(names.has(folded))issues.push(label+': choose a unique log type name.');
    names.add(folded);
    if(!group.sample.trim())issues.push(label+': paste or upload at least one sample, or remove this type.');
    if(byteSize(group.sample)>MAX_NAMED_LOG_BYTES)
      issues.push(label+': reduce the sample to 64 KiB or less.');
  });
  const bytes=byteSize(assembleNamedLogs(groups).source);
  if(bytes>MAX_NAMED_LOG_BYTES)
    issues.push('The combined sample exceeds 64 KiB. Reduce the log samples.');
  return {ok:issues.length===0,issues,bytes};
}

/** Map verified source UTF-8 byte intervals to user-named groups. A record
 * spanning a synthetic group boundary is never silently assigned to a type.
 * Group names cannot act as event-type routing or parser predicates.
 */
export function analyzeNamedLogs(
  groups:readonly NamedLogType[],
  events:readonly {startByte:number;endByte:number;preview:MultiPassSourcePreview}[],
):{groups:NamedLogAnalysis[];unassigned:number}{
  const spans=assembleNamedLogs(groups).spans;
  const result=groups.map(group=>({
    id:group.id,name:group.name,events:0,parsed:0,partial:0,rawOnly:0,
    fields:[] as string[],boundaryWarning:false,
  }));
  const unique=result.map(()=>new Set<string>());
  let unassigned=0;
  for(const event of events){
    const found=spans.findIndex(span=>event.startByte>=span.startByte&&
      event.endByte<=span.endByte&&event.endByte>event.startByte);
    if(found<0){
      unassigned++;
      for(const [index,span] of spans.entries()){
        if(event.endByte>span.startByte&&event.startByte<span.endByte)
          result[index]!.boundaryWarning=true;
      }
      continue;
    }
    const summary=result.find(entry=>entry.id===spans[found]!.id);
    if(!summary){unassigned++;continue;}
    summary.events++;
    if(event.preview.status==='SOURCE_PARSED')summary.parsed++;
    else if(event.preview.status==='PARTIAL')summary.partial++;
    else summary.rawOnly++;
    if(event.preview.status!=='SOURCE_PARSED')continue;
    for(const path of listSafeLeafPaths(event.preview.fields,101))
      if(path.length<=128&&unique[found]!.size<100)unique[found]!.add(path);
  }
  result.forEach((group,index)=>{group.fields=[...unique[index]!].sort();});
  return {groups:result,unassigned};
}
