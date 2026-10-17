/** Conservative, explicit-profile RFC3164 BSD source observer without PRI.
 * Source-only PoC; neither manufacturer semantics nor native parser approved.
 */
import type {SyslogOriginalField,SyslogSourceInspection} from './generalSyslogEnvelopeSpans';
export interface UnprioritizedSyslogContext{sourceFraming:'PUBLISHER_ASSERTED_BSD_WITHOUT_PRI'}
const utf8=new TextEncoder(),decoder=new TextDecoder('utf8',{fatal:true});
const months:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,
 Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
function unicodeOkay(raw:string):boolean{
 for(let i=0;i<raw.length;i++){
  const code=raw.charCodeAt(i);
  if(code>=0xd800&&code<=0xdbff){
   i++;if(i>=raw.length||raw.charCodeAt(i)<0xdc00||raw.charCodeAt(i)>0xdfff)return false;
  }else if(code>=0xdc00&&code<=0xdfff)return false;
 }
 return true;
}
function fallback(raw:string,reason:string,
 disposition:SyslogSourceInspection['disposition']='RAW_ONLY'):SyslogSourceInspection{
 return {disposition,format:'none',fields:[],reason,sourceBytes:utf8.encode(raw).length,
  originalRaw:raw,branchAttempts:0,maxDepth:1,autoPromoted:false,
  manufacturerSemantics:'NOT_CERTIFIED',nativeParser:'NOT_VERIFIED'};
}
function field(raw:string,bytes:Uint8Array,name:string,start:number,end:number):
 SyslogOriginalField|null {
 if(start<0||end<=start||end>raw.length)return null;
 const value=raw.slice(start,end),s=utf8.encode(raw.slice(0,start)).length,
  e=utf8.encode(raw.slice(0,end)).length;
 if(s<0||e>bytes.length)return null;
 try{if(decoder.decode(bytes.subarray(s,e))!==value)return null;}
 catch{return null;}
 return {name,value,type:'string',startByte:s,endByte:e};
}
export function inspectRfc3164WithoutPri(raw:string,
 context?:UnprioritizedSyslogContext):SyslogSourceInspection{
 const initial=fallback(raw,'NO_PUBLISHER_QUALIFIED_PRI_LESS_SYSLOG_FRAMING');
 if(!context||context.sourceFraming!=='PUBLISHER_ASSERTED_BSD_WITHOUT_PRI')return initial;
 const bytes=utf8.encode(raw);
 if(!raw||bytes.length>8192||/[\r\n\0]/.test(raw)||!unicodeOkay(raw))
  return fallback(raw,'UNPRIORITIZED_SYSLOG_OUTSIDE_BOUNDS','ABSTAIN_UNSAFE');
 if(raw.startsWith('<'))return initial;
 const rx=/^([A-Z][a-z]{2})( {1,2})([0-9]{1,2})( +)([0-9]{2}):([0-9]{2}):([0-9]{2})( +)([A-Za-z0-9][A-Za-z0-9_.-]{0,254})( +)([A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\[([0-9]{1,8})\])?:( +)(.+)$/;
 const m=rx.exec(raw);
 if(!m)return fallback(raw,'NOT_FULLY_CONFORMING_BSD_TAGGED_SYSLOG','ABSTAIN_UNSAFE');
 const month=months[m[1]!],day=Number(m[3]!),hh=Number(m[5]!),
  mm=Number(m[6]!),ss=Number(m[7]!);
 if(!month||day<1||day>month||hh>23||mm>59||ss>59)
  return fallback(raw,'INVALID_BSD_HEADER_CLOCK','ABSTAIN_UNSAFE');
 const timestampEnd=m[1]!.length+m[2]!.length+m[3]!.length+m[4]!.length+
  m[5]!.length+1+m[6]!.length+1+m[7]!.length;
 const hostStart=timestampEnd+m[8]!.length;
 const appStart=hostStart+m[9]!.length+m[10]!.length;
 const pidStart=m[12]===undefined?null:appStart+m[11]!.length+1;
 const msgStart=appStart+m[11]!.length+(m[12]?m[12]!.length+2:0)+1+m[13]!.length;
 const positions:Array<[string,number,number]>=[
  ['timestamp',0,timestampEnd],
  ['hostname',hostStart,hostStart+m[9]!.length],
  ['appname',appStart,appStart+m[11]!.length],
  ...(pidStart===null?[]:[['procid',pidStart,pidStart+m[12]!.length] as [string,number,number]]),
  ['message',msgStart,raw.length],
 ];
 const result=positions.map(([name,start,end])=>field(raw,bytes,name,start,end));
 if(result.some(f=>f===null))return fallback(raw,'BOUNDARY_BYTE_REPLAY_FAILED','ABSTAIN_UNSAFE');
 if(result.at(-1)!.value!==m[14])return fallback(raw,'MESSAGE_VALUE_REPLAY_FAILED','ABSTAIN_UNSAFE');
 return {...initial,disposition:'REVIEW_ONLY',format:'rfc3164',
  fields:result as SyslogOriginalField[],branchAttempts:1,
  reason:'PUBLISHER_QUALIFIED_PRI_LESS_BSD_SOURCE_ONLY'};
}
