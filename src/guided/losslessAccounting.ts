import type {EventParseStatus,EventResult,ParserDraft} from '../model';
import {sha256Utf8Hex} from '../sha256';
import {countUnaddressableSourceValues,lookupFieldValue,safeLocalFieldPath} from '../fieldPaths';

export type ResidualEvidence={startByte:number;endByte:number};
export type AccountingEventInput={event:EventResult;residuals?:ResidualEvidence[]};
export type AccountingEvent={id:string;sourceBytes:number;sourceSha256:string;structuralStatus:EventParseStatus;
 structuralLeafPaths:string[];structuralLeafCount:number;residuals:ResidualEvidence[]|null;normalizedPaths:string[];normalizedPathCount:number;
 notMappablePaths:string[];notMappablePathCount:number;pathListTruncated:boolean;unaddressableValueCount:number;
 outputEvidence:'PRESENT_BROWSER_PREVIEW'|'UNKNOWN'};
export type LosslessAccounting={sourceBytes:number;sourceSha256:string;eventCount:number;events:AccountingEvent[];
 structuralCounts:Record<EventParseStatus,number>;normalizedPathCount:number;unaccountedEventIds:string[];proof:'COMPLETE'|'UNKNOWN'};

const SOURCE_ONLY=new Set(['source_raw','message_raw','raw','generic.source_raw','generic.message_raw']);
function leaves(value:unknown,path:string,out:string[],depth=0){
 if(depth>8)return;
 if(value&&typeof value==='object'&&!Array.isArray(value)){
  for(const [key,child] of Object.entries(value as Record<string,unknown>))leaves(child,path?path+'.'+key:key,out,depth+1);
 }else if(path&&!SOURCE_ONLY.has(path)&&!path.endsWith('.source_raw')&&!path.endsWith('.message_raw'))out.push(path);
}
function status(event:EventResult):EventParseStatus{
 return event.parseStatus==='FULL'||event.parseStatus==='PARTIAL'||event.parseStatus==='UNKNOWN'||event.parseStatus==='ERROR'?event.parseStatus:'UNKNOWN';
}
function normalizedPaths(event:EventResult,draft:ParserDraft):string[]{
 const out:string[]=[];leaves(event.normalized,'',out);
 return out.filter(path=>path!==`${draft.vendor}.parserstudio_source.source_raw`&&
  !path.endsWith('.parserstudio_source.source_raw')&&!path.endsWith('.source_raw'));
}
function nonMappable(fields:Record<string,unknown>):{paths:string[];count:number;truncated:boolean}{
 const result:string[]=[];let count=0,visits=0,truncated=false;const add=(path:string)=>{
  count++;if(result.length<1024)result.push(path);else truncated=true;
 };
 const visit=(value:unknown,path:string,depth:number)=>{
  if(++visits>50000){truncated=true;return;}
  if(Array.isArray(value)){add(path+' [array]');return;}
  if(value&&typeof value==='object'){
   if(depth>=8){add(path+' [depth limit]');return;}
   for(const [key,child] of Object.entries(value as Record<string,unknown>)){
    const next=path?path+'.'+key:key;
    if(!safeLocalFieldPath(next)){add(next+' [unsafe path]');continue;}
    visit(child,next,depth+1);
   }return;
  }
  if(value===null)add(path+' [null]');
  else if(!lookupFieldValue(fields,path).found)add(path+' [ambiguous or unaddressable]');
 };
 visit(fields,'',0);return {paths:result,count,truncated};
}
/** Independent bounded accounting; missing multipass spans/output evidence stay UNKNOWN. */
export async function accountLosslessSource(raw:string,inputs:AccountingEventInput[],draft:ParserDraft):Promise<LosslessAccounting>{
 const events:AccountingEvent[]=await Promise.all(inputs.slice(0,400).map(async({event,residuals})=>{
  const structuralLeafPaths:string[]=[];leaves(event.fields,'',structuralLeafPaths);
  const output=normalizedPaths(event,draft);
  const byteLength=new TextEncoder().encode(event.raw).byteLength;
  const validResiduals=residuals!==undefined&&residuals.every(span=>Number.isInteger(span.startByte)&&Number.isInteger(span.endByte)&&span.startByte>=0&&span.endByte>span.startByte&&span.endByte<=byteLength);
  const evidence=residuals===undefined?null:residuals.map(span=>({...span}));
  const sourceBytes=new TextEncoder().encode(event.raw).byteLength;
  const unsupported=nonMappable(event.fields);
  return {id:event.id,sourceBytes,sourceSha256:await sha256Utf8Hex(event.raw),structuralStatus:status(event),
   structuralLeafPaths:structuralLeafPaths.slice(0,2048),structuralLeafCount:structuralLeafPaths.length,
   residuals:evidence,normalizedPaths:output.slice(0,2048),normalizedPathCount:output.length,
   notMappablePaths:unsupported.paths,notMappablePathCount:unsupported.count,pathListTruncated:unsupported.truncated||
    structuralLeafPaths.length>2048||output.length>2048||!validResiduals,
   unaddressableValueCount:countUnaddressableSourceValues(event.fields),
   outputEvidence:event.normalized?'PRESENT_BROWSER_PREVIEW':'UNKNOWN'};
 }));
 const structuralCounts:Record<EventParseStatus,number>={FULL:0,PARTIAL:0,UNKNOWN:0,ERROR:0};
 for(const item of inputs)structuralCounts[status(item.event)]++;
 const normalizedPathCount=events.reduce((sum,item)=>sum+item.normalizedPathCount,0);
 const inconsistentFull=inputs.some(item=>status(item.event)==='FULL'&&
  (leavesCount(item.event.fields)===0||item.residuals===undefined||item.residuals.length>0));
 let cursor=0;
 const sourceLines=raw.split(/\r?\n/).filter(line=>line.length>0);
 const sourceMismatch=inputs.length>400||sourceLines.length!==inputs.length||inputs.some(({event},index)=>{
  const at=event.raw?raw.indexOf(event.raw,cursor):-1;
  if(at<cursor)return true;
  cursor=at+event.raw.length;return sourceLines[index]!==event.raw;
 })||inputs.reduce((sum,{event})=>sum+new TextEncoder().encode(event.raw).length,0)>new TextEncoder().encode(raw).length;
 const incomplete=sourceMismatch||inputs.length>events.length||inconsistentFull||events.some(event=>event.pathListTruncated)||inputs.some(item=>item.residuals===undefined||item.event.parseStatus===undefined||!item.event.normalized);
 const unaccountedEventIds=inputs.filter((item,index)=>sourceMismatch||index>=events.length||item.residuals===undefined||
  item.event.parseStatus===undefined||!item.event.normalized||
  (status(item.event)==='FULL'&&(leavesCount(item.event.fields)===0||item.residuals.length>0))).map(item=>item.event.id);
 return {sourceBytes:new TextEncoder().encode(raw).byteLength,sourceSha256:await sha256Utf8Hex(raw),eventCount:inputs.length,
  events,structuralCounts,normalizedPathCount,unaccountedEventIds,
  proof:incomplete?'UNKNOWN':'COMPLETE'};
}
function leavesCount(fields:Record<string,unknown>):number{
 const found:string[]=[];leaves(fields,'',found);return found.length;
}
