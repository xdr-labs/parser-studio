import {strictKeyValues} from './structuredFamilies';

const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'] as const;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function ipv4(value:string):boolean{
  const parts=value.split('.');
  return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255);
}

function ipv6(value:string):boolean{
  if(!value.includes(':')||!/^[0-9A-Fa-f:]+$/.test(value)||value.indexOf('::')!==value.lastIndexOf('::'))return false;
  const sides=value.split('::');
  if(sides.length>2)return false;
  const groups=sides.flatMap(side=>side?side.split(':'):[]);
  if(groups.some(group=>!/^[0-9A-Fa-f]{1,4}$/.test(group)))return false;
  return sides.length===2?groups.length<8:groups.length===8;
}

function ip(value:string):boolean{return ipv4(value)||ipv6(value);}
function port(value:string):boolean{return /^\d{1,5}$/.test(value)&&Number(value)<=65535;}

function leap(year:number):boolean{return year%4===0&&(year%100!==0||year%400===0);}

function calendar(year:number,month:number,day:number):boolean{
  if(year<1||year>9999||month<1||month>12||day<1)return false;
  const days=[31,leap(year)?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1]!;
}

function clock(value:string):boolean{
  const match=/^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?$/.exec(value);
  return !!match&&Number(match[1])<=23&&Number(match[2])<=59&&Number(match[3])<=59;
}

function bsdDate(month:string,dayText:string,time:string):boolean{
  const monthIndex=MONTHS.indexOf(month as typeof MONTHS[number])+1;
  const day=Number(dayText);
  if(monthIndex<1||!Number.isInteger(day)||day<1||!clock(time))return false;
  const max=[31,29,31,30,31,30,31,31,30,31,30,31][monthIndex-1]!;
  return day<=max;
}

function priority(value:string):boolean{
  return /^\d{1,3}$/.test(value)&&Number(value)<=191;
}

function timezone(value:string):boolean{
  if(/^[A-Z]{2,8}$/.test(value))return true;
  const match=/^([+-])(\d{2})(\d{2})$/.exec(value);
  return !!match&&Number(match[2])<=23&&Number(match[3])<=59;
}

function decodeQuoted(value:string):string|null{
  let output='';
  for(let index=0;index<value.length;index++){
    const ch=value[index]!;
    if(ch!=='\\'){output+=ch;continue;}
    const next=value[index+1];
    if(next===undefined)return null;
    if(next==='"'||next==='\\'){output+=next;index++;continue;}
    output+='\\'+next;index++;
  }
  return bytes(output)<=8192?output:null;
}

export function parseCiscoIosMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  const match=/^%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+): +(.*)$/.exec(text);
  if(!match)return null;
  const severity=Number(match[2]);
  if(severity<0||severity>7||!match[4]||bytes(match[4])>4096)return null;
  return {facility:match[1],severity:match[2],mnemonic:match[3],message:match[4]};
}

export function parseCiscoIosSequenceSyslog(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>8192)return null;
  const match=/^<(\d{1,3})>(\d{1,10}): +([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +([A-Z]{2,8}|[+-]\d{4}): +(.+)$/.exec(raw);
  if(!match||!priority(match[1]!)||!bsdDate(match[3]!,match[4]!,match[5]!)||!timezone(match[6]!))return null;
  const body=parseCiscoIosMessage(match[7]!);
  if(!body)return null;
  return {
    syslog:{pri:match[1],sequence:match[2],month:match[3],day:match[4],time:match[5],timezone:match[6]},
    cisco_ios:{...body,source_raw:raw},
  };
}

function parseHttpTimestamp(value:string):{raw:string;timezone:string}|null{
  const match=/^(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}:\d{2}:\d{2}) +([+-]\d{4})$/.exec(value);
  if(!match)return null;
  const month=MONTHS.indexOf(match[2] as typeof MONTHS[number])+1;
  const zone=/^([+-])(\d{2})(\d{2})$/.exec(match[5]!);
  if(month<1||!calendar(Number(match[3]),month,Number(match[1]))||!clock(match[4]!)||
     !zone||Number(zone[2])>23||Number(zone[3])>59)return null;
  return {raw:value,timezone:match[5]!};
}

export function parseHttpAccessLog(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>16384)return null;
  const match=/^(\S+) +(\S+) +(\S+) +\[([^\]]+)\] +"((?:\\.|[^"\\])*)" +(\d{3}) +(\d+|-)(?: +"((?:\\.|[^"\\])*)" +"((?:\\.|[^"\\])*)")?$/.exec(raw);
  if(!match||!ip(match[1]!))return null;
  const timestamp=parseHttpTimestamp(match[4]!);
  if(!timestamp)return null;
  const request=decodeQuoted(match[5]!);
  const referer=match[8]===undefined?undefined:decodeQuoted(match[8]);
  const userAgent=match[9]===undefined?undefined:decodeQuoted(match[9]);
  if(request===null||referer===null||userAgent===null)return null;
  const requestMatch=/^([A-Z][A-Z0-9_-]{1,15}) +(\S{1,8192}) +HTTP\/(\d(?:\.\d)?)$/.exec(request);
  if(!requestMatch)return null;
  const status=Number(match[6]);
  if(status<100||status>599)return null;
  return {
    http_access:{
      client_ip:match[1],ident:match[2],user:match[3],timestamp:timestamp.raw,timezone:timestamp.timezone,
      method:requestMatch[1],request_target:requestMatch[2],http_version:requestMatch[3],
      status:match[6],bytes:match[7],
      ...(referer!==undefined?{referer}:{}),...(userAgent!==undefined?{user_agent:userAgent}:{}),
      source_raw:raw,
    },
    generic:{mode:match[8]===undefined?'http_common_access':'http_combined_access',source_raw:raw},
  };
}

export function parseSquidAccessLog(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n\t]/.test(raw)||bytes(raw)>16384)return null;
  const parts=raw.trim().split(/ +/);
  if(parts.length!==10)return null;
  if(!/^\d{9,12}(?:\.\d{1,6})?$/.test(parts[0]!)||!/^[0-9]{1,10}$/.test(parts[1]!)||!ip(parts[2]!))return null;
  const result=/^([A-Z][A-Z0-9_-]{2,63})\/(\d{3})$/.exec(parts[3]!);
  if(!result||Number(result[2])>599||Number(result[2])<100||!/^\d+$/.test(parts[4]!))return null;
  if(!/^[A-Z][A-Z0-9_-]{1,15}$/.test(parts[5]!)||parts[6]!.length>8192)return null;
  if(parts[7]!.length>256)return null;
  const hierarchy=/^([A-Z][A-Z0-9_-]{2,63})\/(.+)$/.exec(parts[8]!);
  if(!hierarchy||hierarchy[2]!.length>255)return null;
  if(hierarchy[2]!== '-'&&!ip(hierarchy[2]!)&&!/^[A-Za-z0-9_.:-]{1,255}$/.test(hierarchy[2]!))return null;
  if(parts[9]!.length>255)return null;
  return {
    squid_access:{
      timestamp:parts[0],elapsed_ms:parts[1],client_ip:parts[2],result_code:result[1],status:result[2],
      bytes:parts[4],method:parts[5],url:parts[6],user:parts[7],
      hierarchy_code:hierarchy[1],hierarchy_peer:hierarchy[2],content_type:parts[9],source_raw:raw,
    },
    generic:{mode:'squid_native_access',source_raw:raw},
  };
}

export function parseBindQueryMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  const match=/^client(?: +@0x([0-9A-Fa-f]+))? +(\S+)#(\d{1,5}) +\(([^)\r\n]{1,255})\): +query: +(\S{1,255}) +(IN|CH|HS) +([A-Z0-9-]{1,32}) +(\S{1,64}) +\(([^)\r\n]{1,255})\)$/.exec(text);
  if(!match||!ip(match[2]!)||!port(match[3]!)||!ip(match[9]!))return null;
  if(match[4]!==match[5]&&match[4]!=='.')return null;
  return {
    ...(match[1]?{client_handle:match[1]}:{}),client_ip:match[2],client_port:match[3],
    query_name:match[5],query_class:match[6],query_type:match[7],flags:match[8],server_ip:match[9],
  };
}

export function parseLegacyOriginatorMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  const match=/^\[([A-Za-z][A-Za-z0-9_.-]*@\d{1,10}) +([^\]]+)\] +(.+)$/.exec(text);
  if(!match)return null;
  const parsed=strictKeyValues(match[2]!);
  if(parsed.errors.length)return null;
  const keys=Object.keys(parsed.fields);
  if(!keys.length||keys.length>64||keys.some(key=>UNSAFE_KEYS.has(key))||bytes(match[3]!)>4096)return null;
  return {structured_id:match[1],params:parsed.fields,message:match[3]};
}
