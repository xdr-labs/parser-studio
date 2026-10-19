import {parseRfc5424Subset} from '../rfc5424Subset';
export type ForwarderConfig={maxHops:1|2|3;relayHosts:string[]};
export interface ForwarderHop {
 relayHost:string;relayTimestamp:string;format:'rfc3164'|'rfc5424';
 prefixStartByte:number;payloadStartByte:number;
}
export type ForwarderInspection={
 status:'DIRECT'|'UNWRAPPED'|'ABSTAIN_UNSAFE';
 payload:string;payloadStartByte:number;hops:ForwarderHop[];
 reason:string;
};
const enc=new TextEncoder();
const monthDays:Record<string,number>={
 Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
export function validForwarderConfig(config?:ForwarderConfig):boolean{
 return !config||(Number.isInteger(config.maxHops)&&config.maxHops>=1&&config.maxHops<=3&&
   config.relayHosts.length>=1&&config.relayHosts.length<=8&&
   new Set(config.relayHosts).size===config.relayHosts.length&&
   config.relayHosts.every(host=>/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$/.test(host)));
}
function singleEnvelope(raw:string):
 {host:string;timestamp:string;format:'rfc3164'|'rfc5424';payload:string}|null{
 if(/^<\d{1,3}>1 /.test(raw)){
   const parsed=parseRfc5424Subset(raw);
   if(!parsed.ok||typeof parsed.message!=='string'||!parsed.message.length)return null;
   return {host:parsed.fields.syslog_hostname,timestamp:parsed.fields.syslog_timestamp,
     format:'rfc5424',payload:parsed.message};
 }
 const match=/^<(\d{1,3})>([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+([!-~]{1,255})\s+([A-Za-z_][A-Za-z0-9_.-]{0,95})(?:\[\d{1,8}\])?:\s+(.+)$/.exec(raw);
 if(!match||Number(match[1])>191||!monthDays[match[2]!]||
    Number(match[3])<1||Number(match[3])>monthDays[match[2]!]||
    Number(match[4])>23||Number(match[5])>59||Number(match[6])>59)return null;
 return {host:match[7]!,timestamp:match[2]+' '+match[3]+' '+match[4]+':'+match[5]+':'+match[6],
   format:'rfc3164',payload:match[9]!};
}
export function inspectDeclaredForwarders(raw:string,config?:ForwarderConfig):ForwarderInspection{
 const direct={status:'DIRECT' as const,payload:raw,payloadStartByte:0,hops:[],reason:'NO_DECLARED_RELAY'};
 if(!config)return direct;
 const unsafe=(reason:string):ForwarderInspection=>({
   status:'ABSTAIN_UNSAFE',payload:raw,payloadStartByte:0,hops:[],reason});
 if(!validForwarderConfig(config)||enc.encode(raw).length>65536||raw.includes('\0')||
   raw.includes('\n')||raw.includes('\r'))return unsafe('UNSAFE_RELAY_SOURCE_OR_PROFILE');
 let text=raw,startByte=0;
 const hops:ForwarderHop[]=[];
 for(let i=0;i<=config.maxHops;i++){
   if(!text.startsWith('<'))break;
   const envelope=singleEnvelope(text);
   if(!envelope)break;
   if(!config.relayHosts.includes(envelope.host))break;
   if(i===config.maxHops)return unsafe('DECLARED_RELAY_HOP_LIMIT_EXCEEDED');
   if(!envelope.payload||!text.endsWith(envelope.payload)||
     enc.encode(envelope.payload).length>=enc.encode(text).length)
     return unsafe('UNREPLAYABLE_RELAY_BODY');
   const offset=enc.encode(text).length-enc.encode(envelope.payload).length;
   hops.push({relayHost:envelope.host,relayTimestamp:envelope.timestamp,
     format:envelope.format,prefixStartByte:startByte,payloadStartByte:startByte+offset});
   startByte+=offset;
   text=envelope.payload;
 }
 return hops.length?
   {status:'UNWRAPPED',payload:text,payloadStartByte:startByte,hops,reason:'DECLARED_SYSLOG_RELAY'}:
   direct;
}
