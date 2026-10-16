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
  const match=/^(\S+) +(\S+) +(\S+) +\[([^\]]+)\] +"((?:\\.|[^"\\])*)" +(\d{3}|-) +(\d+|-)(?: +"((?:\\.|[^"\\])*)" +"((?:\\.|[^"\\])*)")?$/.exec(raw);
  if(!match||!ip(match[1]!))return null;
  const timestamp=parseHttpTimestamp(match[4]!);
  if(!timestamp)return null;
  const request=decodeQuoted(match[5]!);
  const referer=match[8]===undefined?undefined:decodeQuoted(match[8]);
  const userAgent=match[9]===undefined?undefined:decodeQuoted(match[9]);
  if(request===null||referer===null||userAgent===null)return null;
  const requestMatch=/^([A-Z][A-Z0-9_-]{1,15}) +(\S{1,8192}) +HTTP\/(\d(?:\.\d)?)$/.exec(request);
  if(!requestMatch)return null;
  const status=match[6]==='-'?undefined:Number(match[6]);
  if(status!==undefined&&(status<100||status>599))return null;
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
  const resultStatus=result?Number(result[2]):NaN;
  if(!result||!Number.isInteger(resultStatus)||!(resultStatus===0||(resultStatus>=100&&resultStatus<=599))||!/^\d+$/.test(parts[4]!))return null;
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

export function parseApacheErrorLog(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>16384)return null;
  const match=/^\[([A-Z][a-z]{2}) +([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\d{4})\] +\[([^\]]{1,128})\](?: +\[pid +(\d{1,10})(?::tid +(\d{1,20}))?\])?(?: +\[client +([^\]]{1,255})\])? +(.+)$/.exec(raw);
  if(!match)return null;
  const month=MONTHS.indexOf(match[2] as typeof MONTHS[number])+1;
  if(month<1||!calendar(Number(match[5]),month,Number(match[3]))||!clock(match[4]!))return null;
  const levelToken=match[6]!;
  const levelParts=levelToken.split(':');
  if(levelParts.length>2||levelParts.some(part=>!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(part)))return null;
  let clientIp:string|undefined,clientPort:string|undefined;
  if(match[9]){
    const client=match[9]!;
    if(ip(client))clientIp=client;
    else{
      const cut=client.lastIndexOf(':');
      if(cut<=0)return null;
      const host=client.slice(0,cut),portText=client.slice(cut+1);
      if(!ip(host)||!port(portText))return null;
      clientIp=host;clientPort=portText;
    }
  }
  if(bytes(match[10]!)>8192)return null;
  return {
    apache_error:{
      weekday:match[1],month:match[2],day:match[3],time:match[4],year:match[5],
      ...(levelParts.length===2?{module:levelParts[0],level:levelParts[1]}:{level:levelParts[0]}),
      ...(match[7]?{pid:match[7]}:{}),...(match[8]?{tid:match[8]}:{}),
      ...(clientIp?{client_ip:clientIp}:{}),...(clientPort?{client_port:clientPort}:{}),
      message:match[10],source_raw:raw,
    },
    generic:{mode:'apache_error_log',source_raw:raw},
  };
}

function safeIdentity(value:string):boolean{
  return /^[A-Za-z0-9_.@-]{1,128}$/.test(value);
}

export function parsePamMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  let service:string|undefined,module='pam_unix',phase:string|undefined,pid:string|undefined;
  let body=text;
  const prefixed=/^([A-Za-z0-9_.-]+)\(pam_unix\)(?:\[(\d{1,10})\])?: +(.+)$/.exec(body);
  if(prefixed){service=prefixed[1];pid=prefixed[2];body=prefixed[3]!;}
  const header=/^pam_unix\(([^):]{1,64}):([^)\r\n]{1,64})\): +(.+)$/.exec(body);
  if(header){
    service=header[1];phase=header[2];body=header[3]!;
  }else if(!prefixed)return null;

  const opened=/^session +(opened|closed) +for +user +([A-Za-z0-9_.@-]{1,128})(?:\(uid=(\d{1,10})\))?(?: +by +(?:([A-Za-z0-9_.@-]{1,128})\(uid=(\d{1,10})\)|\(uid=(\d{1,10})\)))?$/.exec(body);
  if(opened)return {
    module,service,...(phase?{phase}:{}),...(pid?{pid}:{}),
    event:'session_'+opened[1],user:opened[2],...(opened[3]?{uid:opened[3]}:{}),
    ...(opened[4]?{actor:opened[4]}:{}),...(opened[5]?{actor_uid:opened[5]}:{}),
    ...(opened[6]?{actor_uid:opened[6]}:{}),
  };

  const changed=/^password +changed +for +([A-Za-z0-9_.@-]{1,128})$/.exec(body);
  if(changed)return {module,service,...(phase?{phase}:{}),...(pid?{pid}:{}),event:'password_changed',user:changed[1]};

  const failure=/^authentication failure;(?: +(.*))?$/.exec(body);
  if(failure){
    const fields:Record<string,unknown>={};
    if(failure[1]){
      const tokens=failure[1].split(/ +/);
      if(tokens.length>64)return null;
      for(const token of tokens){
        const pair=/^([A-Za-z_][A-Za-z0-9_.-]{0,63})=(.*)$/.exec(token);
        if(!pair||UNSAFE_KEYS.has(pair[1]!)||Object.prototype.hasOwnProperty.call(fields,pair[1]!))return null;
        if(bytes(pair[2]!)>512||/[\r\n\0]/.test(pair[2]!))return null;
        fields[pair[1]!]=pair[2]!;
      }
    }
    return {module,service,...(phase?{phase}:{}),...(pid?{pid}:{}),event:'authentication_failure',fields};
  }
  return null;
}

export function parseSshdMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  let match=/^(Accepted|Failed) +(password|publickey) +for +(invalid user +)?([A-Za-z0-9_.@-]{1,128}) +from +(\S+) +port +(\d{1,5}) +ssh2(?: +.*)?$/.exec(text);
  if(match){
    if(!ip(match[5]!)||!port(match[6]!))return null;
    return {event:match[1]==='Accepted'?'authentication_success':'authentication_failure',method:match[2],user:match[4],src_ip:match[5],src_port:match[6],...(match[3]?{invalid_user:true}:{})};
  }
  match=/^Invalid +user +([A-Za-z0-9_.@-]{1,128}) +from +(\S+)$/.exec(text);
  if(match)return ip(match[2]!)?{event:'invalid_user',user:match[1],src_ip:match[2]}:null;
  match=/^Connection +closed +by +(\S+)(?: +port +(\d{1,5}))?.*$/.exec(text);
  if(match){if(!ip(match[1]!)||(match[2]&&!port(match[2]!)))return null;return {event:'connection_closed',src_ip:match[1],...(match[2]?{src_port:match[2]}:{})};}
  match=/^Received +disconnect +from +(\S+): +(\d{1,3}): +(.{1,512})$/.exec(text);
  if(match)return ip(match[1]!)?{event:'disconnect',src_ip:match[1],code:match[2],reason:match[3]}:null;
  match=/^reverse mapping checking getaddrinfo for +([A-Za-z0-9_.:-]{1,255}) +failed - POSSIBLE BREAKIN ATTEMPT!$/.exec(text);
  if(match)return {event:'reverse_mapping_failure',peer:match[1]};
  match=/^User +([A-Za-z0-9_.@-]{1,128}) +not allowed because listed in +(DenyUsers|DenyGroups)$/.exec(text);
  if(match)return {event:'access_denied_by_policy',user:match[1],policy:match[2]};
  match=/^error: +Bind to port +(\d{1,5}) +on +(\S+) +failed: +(.{1,512})$/.exec(text);
  if(match){if(!port(match[1]!)||!ip(match[2]!))return null;return {event:'bind_failure',port:match[1],address:match[2],reason:match[3]};}
  return null;
}

export function parseBindSecurityMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  const match=/^client(?: +@0x([0-9A-Fa-f]+))? +(\S+)#(\d{1,5}): +(update|query) +'([^'\r\n]{1,255})' +(denied|approved|refused)$/.exec(text);
  if(!match||!ip(match[2]!)||!port(match[3]!))return null;
  const target=match[5]!.split('/');
  if(target.length<1||target.length>2||!target[0]||bytes(target[0]!)>255)return null;
  const zone=target[0]!,queryClass=target[1];
  if(queryClass!==undefined&&!/^(?:IN|CH|HS)$/.test(queryClass))return null;
  return {
    ...(match[1]?{client_handle:match[1]}:{}),client_ip:match[2],client_port:match[3],
    operation:match[4],zone,...(queryClass?{query_class:queryClass}:{}),action:match[6],
  };
}

export function parseWindowsFirewallLog(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n\t]/.test(raw)||bytes(raw)>8192)return null;
  const parts=raw.trim().split(/ +/);
  if(parts.length!==17)return null;
  const date=/^(\d{4})-(\d{2})-(\d{2})$/.exec(parts[0]!);
  if(!date||!calendar(Number(date[1]),Number(date[2]),Number(date[3]))||!clock(parts[1]!))return null;
  if(!/^(?:OPEN|CLOSE|DROP|INFO|OPEN-INBOUND)$/.test(parts[2]!))return null;
  if(!/^(?:TCP|UDP|ICMP|ICMPV6|GRE|ESP|AH|\d{1,3})$/i.test(parts[3]!))return null;
  if(!ip(parts[4]!)||!ip(parts[5]!))return null;
  for(const index of [6,7])if(parts[index]!=='-'&&!port(parts[index]!))return null;
  const names=['date','time','action','protocol','src_ip','dst_ip','src_port','dst_port','size','tcp_flags','tcp_syn','tcp_ack','tcp_win','icmp_type','icmp_code','info','path'] as const;
  const fields:Record<string,string>=Object.create(null);
  names.forEach((name,index)=>{fields[name]=parts[index]!;});
  return {windows_firewall:fields,generic:{mode:'windows_firewall_log',source_raw:raw}};
}

function parseSpaceKvAllowEmpty(text:string):Record<string,string>|null{
  const fields:Record<string,string>=Object.create(null);
  const tokens=text.trim().split(/ +/);
  if(!tokens.length||tokens.length>128)return null;
  for(const token of tokens){
    const match=/^([A-Za-z_][A-Za-z0-9_.-]{0,63})=(.*)$/.exec(token);
    if(!match||UNSAFE_KEYS.has(match[1]!)||Object.prototype.hasOwnProperty.call(fields,match[1]!))return null;
    if(bytes(match[2]!)>2048||/[\r\n\0]/.test(match[2]!))return null;
    fields[match[1]!]=match[2]!;
  }
  return fields;
}

export function parseSudoMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  const head=/^([A-Za-z0-9_.@-]{1,128}) +: +(.+)$/.exec(text);
  if(!head||!safeIdentity(head[1]!))return null;
  let body=head[2]!,attempts:string|undefined;
  const failed=/^(\d{1,4}) +incorrect password attempts? +; +(.+)$/.exec(body);
  if(failed){attempts=failed[1];body=failed[2]!;}
  const segments=body.split(/ +; +/);
  if(segments.length<2||segments.length>32)return null;
  const fields:Record<string,string>=Object.create(null);
  for(const segment of segments){
    const eq=segment.indexOf('=');
    if(eq<=0)return null;
    const key=segment.slice(0,eq),value=segment.slice(eq+1);
    if(!/^[A-Z][A-Z0-9_]{0,31}$/.test(key)||UNSAFE_KEYS.has(key)||Object.prototype.hasOwnProperty.call(fields,key))return null;
    if(bytes(value)>4096||/[\r\n\0]/.test(value))return null;
    fields[key]=value;
  }
  if(!fields.USER||!fields.COMMAND)return null;
  return {event:attempts?'authentication_failure':'command',actor:head[1],...(attempts?{attempts}:{}),fields};
}

export function parseUfwMessage(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>8192)return null;
  const match=/^\[([0-9]{1,12}(?:\.[0-9]{1,9})?)\] +\[UFW +(BLOCK|ALLOW|AUDIT|LIMIT)\] +(.+)$/.exec(text);
  if(!match)return null;
  const fields=parseSpaceKvAllowEmpty(match[3]!);
  if(!fields||Object.keys(fields).length<5)return null;
  if(fields.SRC!==undefined&&!ip(fields.SRC))return null;
  if(fields.DST!==undefined&&!ip(fields.DST))return null;
  for(const key of ['SPT','DPT'])if(fields[key]!==undefined&&!port(fields[key]!))return null;
  if(fields.PROTO!==undefined&&!/^[A-Za-z0-9_-]{1,16}$/.test(fields.PROTO))return null;
  return {kernel_timestamp:match[1],action:match[2],fields};
}
