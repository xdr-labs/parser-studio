import {jsonSourcePreflightError} from './jsonSourcePreflight';
import {extractStructuredFamily,strictKeyValues} from './structuredFamilies';
import {envelopeToSyslogFields,parseSyslogEnvelope} from './syslogEnvelope';
import {unwrapSingleSyslogRecord} from './syslogFraming';
import {extractVpcFlowStructural,parseVpcFlowLogV2} from './awsVpcFlow';
import {extractAlbStructural,parseAlbAccessLog} from './awsAlbAccess';
import {parseApacheErrorLog,parseBindQueryMessage,parseBindSecurityMessage,parseCiscoIosMessage,parseCiscoIosSequenceSyslog,parseHttpAccessLog,parseLegacyOriginatorMessage,parsePamMessage,parseSshdMessage,parseSquidAccessLog,parseSudoMessage,parseUfwMessage,parseWindowsFirewallLog} from './commonSecurityProfiles';
import {extractLinuxAuditStructural,parseLinuxAuditRecord} from './linuxAudit';
import {extractCiscoFirewallEnvelope,parseCiscoFirewallEnvelope} from './ciscoFirewallEnvelope';
import {parseBindQueryLog} from './bindQueryLog';
import {extractClassicElbAccess,extractS3Access} from './awsLegacyAccess';
import {parseCiscoIseBody,parseF5AsmBody,parseFortinetKvBody,parseSophosKvBody} from './applianceSecurityProfiles';
import {isIpToken as ipToken,isIpv4Token as ipv4Token,isIpv6Token as ipv6Token,isPortToken as validPortToken} from './networkTokens';
import {parseRfc4180SingleDataRow} from './rfc4180Csv';
import {parseJunosBareBracketEvent,parseJunosBracketEvent} from './junosBracketBody';

/**
 * Browser twin of the backend's bounded Generic Structural compiler subset.
 * This is not a universal parser: only explicit closed grammars are accepted.
 */
export interface GenericStructuralExtraction {
  fields: Record<string, unknown>;
  errors: string[];
}

function validRfc3339(value:string):boolean{
  const match=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)(Z|[+-]\d{2}:\d{2})$/.exec(value);
  return !!match&&validIsoPriClock(match[1]!,match[2]!,match[3]!);
}

function shortRfc5424Json(raw:string):Record<string,unknown>|null{
  const match=raw.match(/^<(\d{1,3})>(1) (\S{1,64}) ([!-~]{1,255}) (\{.*\})$/);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validRfc3339(match[3]!))return null;
  if(jsonSourcePreflightError(match[5]!))return null;
  let body:unknown;
  try{body=JSON.parse(match[5]!);}catch{return null;}
  if(!body||Array.isArray(body)||typeof body!=='object')return null;
  return {
    syslog:{pri:match[1],version:match[2],timestamp:match[3],hostname:match[4]},
    body:body as Record<string,unknown>,
  };
}

function prefixedJson(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const match=/^([A-Za-z0-9_.:/-]{1,64})[ \t]+(\{.*\})$/.exec(raw);
  if(!match)return null;
  if(jsonSourcePreflightError(match[2]!))return null;
  let body:unknown;
  try{body=JSON.parse(match[2]!);}catch{return null;}
  if(!body||Array.isArray(body)||typeof body!=='object')return null;
  return {
    generic:{mode:'prefixed_json',prefix:match[1],source_raw:raw},
    body:body as Record<string,unknown>,
  };
}

function shortRfc5424Structured(raw:string):Record<string,unknown>|null{
  const match=raw.match(/^<(\d{1,3})>(1) (\S{1,64}) ([!-~]{1,255}) ((?:CEF:0\|.*|LEEF:(?:1\.0|2\.0)\|.*))$/);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validRfc3339(match[3]!))return null;
  const source=match[5]!;
  const parsed=extractStructuredFamily(source,source.startsWith('CEF:')?'cef':'leef');
  if(parsed.errors.length)return null;
  return {
    syslog:{pri:match[1],version:match[2],timestamp:match[3],hostname:match[4]},
    body:parsed.fields,
  };
}

const UNSAFE_SOURCE_KEYS=new Set(['__proto__','constructor','prototype']);

function sourceKeySafe(key:string):boolean{
  return !UNSAFE_SOURCE_KEYS.has(key);
}


function splitEscaped(value:string,delimiter:string):string[]|null{
  const parts:string[]=[];let token='';let quote:string='';let escaped=false;
  for(const char of value){
    if(escaped){token+=char;escaped=false;continue;}
    if(char==='\\'){token+=char;escaped=true;continue;}
    if(quote){token+=char;if(char===quote)quote='';continue;}
    if(char==='"'||char==="'"){quote=char;token+=char;continue;}
    if(char===delimiter){parts.push(token);token='';continue;}
    token+=char;
  }
  if(escaped||quote)return null;
  parts.push(token);return parts;
}

function validUnzonedTimestamp(value:string):boolean{
  const match=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)$/.exec(value);
  return !!match&&validIsoPriClock(match[1]!,match[2]!,'Z');
}

function bracketColonKv(raw:string):Record<string,unknown>|null{
  const match=raw.match(/^<(\d{1,3})>(1) (\S+) ([!-~]{1,255}) ([!-~]{1,48}) ([!-~]{1,128}) ([!-~]{1,32}) (\[.*\])[ \t]*$/);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||
     !(validRfc3339(match[3]!)||validUnzonedTimestamp(match[3]!)))return null;
  const inner=match[8]!.slice(1,-1);
  if(new TextEncoder().encode(inner).byteLength>8192)return null;
  const segments=splitEscaped(inner,';');
  if(!segments)return null;
  const body:Record<string,unknown>={};
  for(const rawSegment of segments){
    const segment=rawSegment.trim();
    if(!segment)continue;
    const delimiter=/:\s*"/.exec(segment);
    if(!delimiter||delimiter.index<=0)return null;
    const key=segment.slice(0,delimiter.index).trim();
    if(!/^[A-Za-z_][A-Za-z0-9_.#:-]{0,127}$/.test(key)||!sourceKeySafe(key))return null;
    const encoded=segment.slice(delimiter.index+1).trim();
    if(encoded.length<2||!encoded.startsWith('"')||!encoded.endsWith('"'))return null;
    const value=encoded.slice(1,-1),previous=body[key];
    body[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    if(Object.keys(body).length>100)return null;
  }
  if(Object.keys(body).length<2)return null;
  return {syslog:{pri:match[1],version:match[2],timestamp:match[3],hostname:match[4],appname:match[5],procid:match[6],msgid:match[7]},body};
}

function junosRfc5424Sd(raw:string):Record<string,unknown>|null{
  const match=raw.match(/^<(\d{1,3})>(1) (\S+) ([!-~]{1,255}) ([!-~]{1,48}) ([!-~]{1,128}) ([!-~]{1,32}) (\[junos@[A-Za-z0-9.:-]{1,64}(?: [^\]]*)?\])$/);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validRfc3339(match[3]!))return null;
  const structuredDataRaw=match[8]!;
  if(new TextEncoder().encode(structuredDataRaw).byteLength>8192)return null;
  const inner=structuredDataRaw.slice(1,-1);
  const head=/^junos@[A-Za-z0-9.:-]{1,64}/.exec(inner);
  if(!head)return null;
  let pos=head[0].length;
  const fields:Record<string,unknown>={};
  while(pos<inner.length){
    if(inner[pos]!==' ')return null;
    pos++;
    const keyMatch=/^[A-Za-z_][A-Za-z0-9_-]{0,63}/.exec(inner.slice(pos));
    if(!keyMatch)return null;
    const key=keyMatch[0]!;
    pos+=key.length;
    if(inner.slice(pos,pos+2)!=='="')return null;
    pos+=2;
    let value='';
    let closed=false;
    while(pos<inner.length){
      const ch=inner[pos]!;
      if(ch==='"'){closed=true;pos++;break;}
      if(ch==='\\'){
        const next=inner[pos+1];
        if(next===undefined||!['"','\\',']'].includes(next))return null;
        value+=next;pos+=2;continue;
      }
      if(ch.charCodeAt(0)<32||ch.charCodeAt(0)===127)return null;
      value+=ch;pos++;
    }
    if(!closed)return null;
    const safe=key.replaceAll('-','_');
    if(!sourceKeySafe(key)||!sourceKeySafe(safe)||Object.prototype.hasOwnProperty.call(fields,safe))return null;
    fields[safe]=value;
    if(Object.keys(fields).length>64)return null;
  }
  if(Object.keys(fields).length<1)return null;
  return {syslog:{pri:match[1],version:match[2],timestamp:match[3],hostname:match[4],
    appname:match[5],procid:match[6],msgid:match[7],structured_data_raw:structuredDataRaw},
    junos_sd:fields};
}

function sourceQualifiedZonedJunosBare(raw:string):Record<string,unknown>|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||
     new TextEncoder().encode(raw).byteLength>8192)return null;
  const header=/^<(\d{1,3})>1 +/.exec(raw);
  if(!header||Number(header[1])>191)return null;
  const rest=raw.slice(header[0].length);
  const first=rest.indexOf(' '),second=first<0?-1:rest.indexOf(' ',first+1);
  if(first<=0||second<=first+1)return null;
  const timestamp=rest.slice(0,first),hostname=rest.slice(first+1,second);
  if(!validRfc3339(timestamp)||!/^[!-~]{1,255}$/.test(hostname))return null;
  const message=rest.slice(second+1);
  const event=parseJunosBareBracketEvent(message);
  if(!event)return null;
  return {
    syslog:{
      pri:header[1],version:'1',timestamp,hostname,appname:event.appname,
      procid:event.procid,msgid:event.msgid,source_grammar:'junos_bare_bracket',
    },
    juniper_flow_kv:event.fields,
    juniper:{source_raw:raw,message_raw:message,source_envelope:'rfc5424_bare_bracket_candidate'},
  };
}

function sourceQualifiedUnzonedJunos(raw:string):Record<string,unknown>|null{
  if(raw.includes('\0')||/[\r\n]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return null;
  const marker=raw.indexOf(' [junos@');
  if(marker<0)return null;
  const tokens=raw.slice(0,marker).split(' ');
  if(tokens.length!==6)return null;
  const priVersion=/^<(\d{1,3})>1$/.exec(tokens[0]??'');
  if(!priVersion||Number(priVersion[1])>191||!validUnzonedTimestamp(tokens[1]??'')||
     !/^[!-~]{1,255}$/.test(tokens[2]??''))return null;
  const message=tokens.slice(3).join(' ')+' '+raw.slice(marker+1);
  const event=parseJunosBracketEvent(message);
  if(!event)return null;
  return {
    syslog:{
      pri:priVersion[1],version:'1',timestamp:tokens[1],hostname:tokens[2],
      appname:event.appname,procid:event.procid,msgid:event.msgid,
      timezone_missing:true,structured_data_raw:event.structuredDataRaw,
    },
    junos_sd:event.fields,
    juniper:{source_raw:raw,message_raw:message,source_envelope:'unzoned_rfc5424_candidate'},
  };
}

function commaKv(raw:string):Record<string,unknown>|null{
  const parts=splitEscaped(raw,',');
  if(!parts||parts.length<3)return null;
  let prefix=parts[0]!.trim();
  const syslog:Record<string,unknown>={};
  const pri=prefix.match(/^<(\d{1,3})>/);
  if(pri){
    const value=Number(pri[1]);
    if(!Number.isInteger(value)||value<0||value>191)return null;
    syslog.pri=pri[1];prefix=prefix.slice(pri[0].length).trim();
  }
  if(!/(?:^|[ \t])\d{4}-\d{2}-\d{2}(?:[ \t]|$)/.test(prefix))return null;
  const tokens=prefix.split(/[ \t]+/).map(value=>
    value.length>1&&[':',','].includes(value[value.length-1]!)?value.slice(0,-1):value);
  if(tokens.length<8||tokens.length>64||
     tokens.some(value=>value.length<1||new TextEncoder().encode(value).byteLength>256))return null;
  const fields:Record<string,unknown>={};
  for(const rawSegment of parts.slice(1)){
    const segment=rawSegment.trim();
    if(!segment)continue;
    const eq=segment.indexOf('=');
    if(eq<=0)return null;
    const key=segment.slice(0,eq).trim();
    if(!/^[A-Za-z_][A-Za-z0-9_.#\/-]{0,127}$/.test(key)||!sourceKeySafe(key))return null;
    let value=segment.slice(eq+1).trim();
    if(value.length>=2&&((value.startsWith('"')&&value.endsWith('"'))||
       (value.startsWith("'")&&value.endsWith("'"))))value=value.slice(1,-1);
    else if(value.startsWith('"')||value.startsWith("'")||value.endsWith('"')||value.endsWith("'"))return null;
    const previous=fields[key];
    fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
  }
  if(Object.keys(fields).length<2)return null;
  const generic:Record<string,unknown>={mode:'comma_kv'};
  tokens.forEach((value,index)=>{generic['prefix_'+String(index+1).padStart(3,'0')]=value;});
  generic.kv=fields;
  return Object.keys(syslog).length?{syslog,generic}:{generic};
}

function spaceKvEntries(raw:string):Array<{key:string;start:number;valueStart:number}>|null{
  const entries:Array<{key:string;start:number;valueStart:number}>=[];
  let quote='';let escaped=false;
  for(let pos=0;pos<raw.length;pos++){
    const char=raw[pos]!;
    if(quote){
      if(escaped){escaped=false;continue;}
      if(char==='\\'){escaped=true;continue;}
      if(char===quote)quote='';
      continue;
    }
    const boundary=pos===0||raw[pos-1]===' '||raw[pos-1]==='\t';
    if(boundary){
      const match=/^([A-Za-z_][A-Za-z0-9_.-]{0,63})=/.exec(raw.slice(pos));
      if(match){
        entries.push({key:match[1]!,start:pos,valueStart:pos+match[0].length});
        if(entries.length>100)return null;
      }
    }
    if(char==='"'||char==="'")quote=char;
  }
  return quote||escaped?null:entries;
}

function spaceKv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const entries=spaceKvEntries(raw);
  if(!entries)return null;
  if(entries.length<5)return null;
  const prefix=raw.slice(0,entries[0]!.start).trim();
  const tokens=prefix?prefix.split(/[ \t]+/).map(value=>
    value.length>1&&[':',','].includes(value[value.length-1]!)?value.slice(0,-1):value):[];
  if(prefix&&(tokens.length<2||tokens.length>16||
    tokens.some(value=>!value||new TextEncoder().encode(value).byteLength>256)))return null;
  const fields:Record<string,unknown>={};
  const atoms:Record<string,unknown>={};
  for(let index=0;index<entries.length;index++){
    const entry=entries[index]!;
    if(!sourceKeySafe(entry.key)||Object.prototype.hasOwnProperty.call(fields,entry.key))return null;
    const end=index+1<entries.length?entries[index+1]!.start:raw.length;
    let value=raw.slice(entry.valueStart,end).trim();
    const quoted=value.length>=2&&
      ((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'")));
    if(quoted)value=value.slice(1,-1);
    else if(value.startsWith('"')||value.startsWith("'")||value.endsWith('"')||value.endsWith("'"))return null;
    if(/[\u0000-\u001f\u007f]/.test(value)||new TextEncoder().encode(value).byteLength>512)return null;
    fields[entry.key]=value;
    if(!quoted&&/[ \t]/.test(value)){
      const pieces=value.split(/[ \t]+/).filter(Boolean);
      if(pieces.length>32)return null;
      for(let pieceIndex=0;pieceIndex<pieces.length;pieceIndex++){
        const piece=pieces[pieceIndex]!;
        if(new TextEncoder().encode(piece).byteLength>256)return null;
        const safe=entry.key.replaceAll('-','_')+'_'+String(pieceIndex+1).padStart(3,'0');
        if(Object.prototype.hasOwnProperty.call(atoms,safe))return null;
        atoms[safe]=piece;
        if(Object.keys(atoms).length>100)return null;
      }
    }
  }
  const generic:Record<string,unknown>={mode:'space_kv',source_raw:raw,kv:fields};
  tokens.forEach((value,index)=>{generic['prefix_'+String(index+1).padStart(3,'0')]=value;});
  if(Object.keys(atoms).length)generic.atoms=atoms;
  return {generic};
}

function claimsJunosBareFlow(raw:string):boolean{
  return /(?:^|[ \t])[A-Z][A-Z0-9_]{2,48} - [A-Z][A-Z0-9_]{2,79} \[/.test(raw)&&
    /(?:^|[ \t])source-port=/.test(raw)&&
    /(?:^|[ \t])destination-address=/.test(raw)&&
    /(?:^|[ \t])destination-port=/.test(raw);
}

function claimsSophosXgShape(raw:string):boolean{
  const text=raw.replace(/^<\d{1,3}>/,'');
  return /^device="[A-Za-z0-9_.-]{1,64}"[ \t]+date=\d{4}-\d{2}-\d{2}[ \t]+time=/.test(text)&&
    /(?:^|[ \t])device_name=/.test(text)&&/(?:^|[ \t])log_id=/.test(text)&&
    /(?:^|[ \t])log_type=/.test(text);
}

function priSpaceKv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const match=/^<(\d{1,3})>(.+)$/.exec(raw);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191)return null;
  const body=match[2]!;
  if(body.includes(' [junos@')||claimsJunosBareFlow(body))return null;
  if(/^date=\d{4}-\d{2}-\d{2}\s+time=/.test(body)&&/\bdevname=/.test(body)&&/\bdevid=/.test(body)&&
     !parseFortinetKvBody(body))return null;
  if(claimsSophosXgShape(body)&&!parseSophosKvBody(body))return null;
  const parsed=spaceKv(body);
  if(!parsed||!parsed.generic||typeof parsed.generic!=='object')return null;
  return {
    syslog:{pri:match[1]},
    generic:{...(parsed.generic as Record<string,unknown>),source_raw:raw},
  };
}

function validBsdClock(month:string,dayText:string,time:string):boolean{
  const monthDays:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
  const day=Number(dayText),clock=time.split(':').map(Number);
  return !!monthDays[month]&&Number.isInteger(day)&&day>=1&&day<=monthDays[month]!&&
    clock.length===3&&clock[0]!>=0&&clock[0]!<=23&&clock[1]!>=0&&clock[1]!<=59&&clock[2]!>=0&&clock[2]!<=59;
}

function bsdMonthNumber(month:string):number{
  return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(month)+1;
}

function validBsdClockWithYear(month:string,dayText:string,yearText:string,time:string):boolean{
  const monthIndex=bsdMonthNumber(month);
  if(monthIndex<1||!/^\d{4}$/.test(yearText))return false;
  const date=yearText+'-'+String(monthIndex).padStart(2,'0')+'-'+String(Number(dayText)).padStart(2,'0');
  return validIsoPriClock(date,time,'Z');
}

function scanProfileTokens(raw:string,start:number):{tokens:string[];kv:Record<string,unknown>;groups:string[]}|null{
  if(start<0||start>raw.length||new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const tokens:string[]=[],groups:string[]=[];const kv:Record<string,unknown>={};let pos=start,count=0;
  while(pos<raw.length){
    while(pos<raw.length&&/\s/.test(raw[pos]!))pos++;
    if(pos===raw.length)break;
    if(++count>100)return null;
    if(raw[pos]==='"'||raw[pos]==="'"){
      const quote=raw[pos]!,begin=pos+1;let cursor=begin,closed=false;
      while(cursor<raw.length){
        if(raw[cursor]==='\\'&&cursor+1<raw.length){cursor+=2;continue;}
        if(raw[cursor]===quote){closed=true;break;}
        cursor++;
      }
      if(!closed)return null;
      tokens.push(raw.slice(begin,cursor));cursor++;
      if(cursor<raw.length&&'.,:!?'.includes(raw[cursor]!))cursor++;
      if(cursor<raw.length&&!/\s/.test(raw[cursor]!)&&![';',','].includes(raw[cursor]!))return null;
      pos=cursor;
      if(pos<raw.length&&[';',','].includes(raw[pos]!))pos++;
      continue;
    }
    if(raw[pos]==='('){
      const end=raw.indexOf(')',pos+1);
      if(end<0||(end+1<raw.length&&!/\s/.test(raw[end+1]!)))return null;
      groups.push(raw.slice(pos+1,end));pos=end+1;continue;
    }
    const keyMatch=/^([A-Za-z_][A-Za-z0-9_.-]{0,127})=/.exec(raw.slice(pos));
    if(keyMatch){
      const key=keyMatch[1]!;
      if(!sourceKeySafe(key))return null;
      let cursor=pos+keyMatch[0].length,startValue=cursor,end=cursor;
      const quote=raw[cursor];
      if(quote==='"'||quote==="'"){
        startValue=++cursor;let closed=false;
        while(cursor<raw.length){
          if(raw[cursor]==='\\'&&cursor+1<raw.length){cursor+=2;continue;}
          if(raw[cursor]===quote){end=cursor;cursor++;closed=true;break;}
          cursor++;
        }
        if(!closed||(cursor<raw.length&&!/\s/.test(raw[cursor]!)))return null;
      }else{
        while(cursor<raw.length&&!/\s/.test(raw[cursor]!))cursor++;
        end=cursor;
      }
      const value=raw.slice(startValue,end),previous=kv[key];
      kv[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
      pos=cursor;continue;
    }
    const begin=pos;
    while(pos<raw.length&&!/\s/.test(raw[pos]!))pos++;
    tokens.push(raw.slice(begin,pos));
  }
  return {tokens,kv,groups};
}

function flowTupleToken(value:string):boolean{
  const arrow=value.indexOf('->');
  if(arrow<=0||arrow!==value.lastIndexOf('->'))return false;
  const source=value.slice(0,arrow),destination=value.slice(arrow+2);
  const sourceSlash=source.lastIndexOf('/'),destinationSlash=destination.lastIndexOf('/');
  if(sourceSlash<=0||destinationSlash<=0)return false;
  const sourceIp=source.slice(0,sourceSlash),sourcePort=source.slice(sourceSlash+1);
  const destinationIp=destination.slice(0,destinationSlash),destinationPort=destination.slice(destinationSlash+1);
  return ipToken(sourceIp)&&ipToken(destinationIp)&&
    validPortToken(sourcePort)&&validPortToken(destinationPort);
}

function validIsoPriClock(date:string,time:string,timezone:string):boolean{
  const d=/^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  const t=/^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?$/.exec(time);
  if(!d||!t)return false;
  const year=Number(d[1]),month=Number(d[2]),day=Number(d[3]);
  const hour=Number(t[1]),minute=Number(t[2]),second=Number(t[3]);
  if(year<1||year>9999||month<1||month>12||hour>23||minute>59||second>59)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  if(day<1||day>days[month-1]!)return false;
  if(timezone==='Z')return true;
  const zone=/^([+-])(\d{2}):?(\d{2})$/.exec(timezone);
  return !!zone&&Number(zone[2])<=23&&Number(zone[3])<=59;
}

function securityEndpoint(value:string):{ip:string;port?:string}|null{
  const bracket=/^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(value);
  if(bracket){
    if(!ipToken(bracket[1]!))return null;
    if(bracket[2]!==undefined&&!validPortToken(bracket[2]!))return null;
    return {ip:bracket[1]!,...(bracket[2]?{port:bracket[2]}:{})};
  }

  const v4=/^((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?$/.exec(value);
  if(v4){
    if(!ipv4Token(v4[1]!))return null;
    if(v4[2]!==undefined&&!validPortToken(v4[2]!))return null;
    return {ip:v4[1]!,...(v4[2]?{port:v4[2]}:{})};
  }

  if(ipv6Token(value))return {ip:value};
  return null;
}

function snortAlertBody(text:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(text).byteLength>8192||text.includes('\0'))return null;
  const match=/^\[(\d{1,10}):(\d{1,10}):(\d{1,10})\] +(.{1,256}?) +\[Classification: ([^\]\r\n]{1,128})\] +\[Priority: (\d{1,3})\] +\{([A-Za-z0-9_.-]{1,16})\} +(\S+) +-> +(\S+)$/.exec(text);
  if(!match)return null;
  const priority=Number(match[6]);
  if(!Number.isInteger(priority)||priority<0||priority>255)return null;
  const source=securityEndpoint(match[8]!);
  const destination=securityEndpoint(match[9]!);
  if(!source||!destination)return null;
  return {
    gid:match[1],sid:match[2],rev:match[3],
    signature:match[4],classification:match[5],priority:match[6],protocol:match[7],
    src_ip:source.ip,...(source.port?{src_port:source.port}:{}),
    dst_ip:destination.ip,...(destination.port?{dst_port:destination.port}:{}),
  };
}

function validExtendedIsoTimestamp(value:string,allowUnzoned:boolean):boolean{
  const match=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(Z|[+-]\d{2}:?\d{2})?$/.exec(value);
  if(!match||(!allowUnzoned&&!match[3]))return false;
  return validIsoPriClock(match[1]!,match[2]!,match[3]??'Z');
}

function isoPriMixed(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const head=/^<(\d{1,3})>(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{4}|[+-]\d{2}:\d{2}) +/.exec(raw);
  if(!head)return null;
  const pri=Number(head[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validIsoPriClock(head[2]!,head[3]!,head[4]!))return null;
  const body=scanProfileTokens(raw,head[0].length);
  if(!body||body.tokens.length<16)return null;
  const values:string[]=[...body.tokens];
  for(const value of Object.values(body.kv)){
    if(Array.isArray(value))values.push(...value.map(String));
    else values.push(String(value));
  }
  if(values.filter(ipToken).length<2)return null;
  return {
    syslog:{pri:head[1],date:head[2],time:head[3],timezone:head[4]},
    generic:body,
  };
}

function isoPriPositional(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const head=/^<(\d{1,3})>(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{4}|[+-]\d{2}:\d{2}) +/.exec(raw);
  if(!head)return null;
  const pri=Number(head[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validIsoPriClock(head[2]!,head[3]!,head[4]!))return null;
  const body=scanProfileTokens(raw,head[0].length);
  if(!body||body.tokens.length<8||body.tokens.length>64)return null;
  const anchors=body.tokens.slice(0,5);
  if(anchors.length<5||anchors.some(value=>!/^[A-Za-z0-9_.:/-]{1,128}$/.test(value))||
     !/^[A-Z][A-Z0-9_]{1,15}$/.test(body.tokens[1]!))return null;
  const portLike=(value:string|undefined)=>!!value&&/^\d{1,5}$/.test(value);
  // Do not let this source-only positional fallback mask a failed strict
  // network tuple. Long records with IP/port/IP/port positions belong to the
  // stronger isoPriMixed grammar and must fail closed if either IP is invalid.
  if(body.tokens.length>=16&&portLike(body.tokens[5])&&portLike(body.tokens[7])&&
     (!ipToken(body.tokens[4]!)||!ipToken(body.tokens[6]!)))return null;
  return {
    syslog:{pri:head[1],date:head[2],time:head[3],timezone:head[4]},
    generic:{mode:'iso_pri_positional',source_raw:raw,...body},
  };
}

function watchguardProfile(raw:string):Record<string,unknown>|null{
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +([^\s]{1,255})(?: +([A-Za-z0-9.-]{2,64}))?(?: +\(([0-9T:+-]{19,35})\))? +(firewall(?:\[\d{1,8}\])?): +/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  if(head[7]!==undefined&&!validExtendedIsoTimestamp(head[7]!,true))return null;
  const body=scanProfileTokens(raw,head[0].length);
  if(!body||!body.tokens.length||!['Allow','Deny','Drop'].includes(body.tokens[0]!))return null;
  const msgId=body.kv.msg_id;
  if(typeof msgId!=='string'||!/^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$/.test(msgId))return null;
  if(body.tokens.filter(ipToken).length<2)return null;
  const header:Record<string,unknown>={month:head[2],day:head[3],time:head[4],hostname:head[5],app_tag:head[8]};
  if(head[1]!==undefined)header.pri=head[1];
  if(head[6]!==undefined)header.serial=head[6];
  if(head[7]!==undefined)header.device_time=head[7];
  return {watchguard_header:header,watchguard:body};
}

function watchguardMessageProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +([^\s]{1,255})(?: +([A-Za-z0-9.-]{2,64}))? +\(([0-9T:+-]{19,35})\) +(firewall(?:\[\d{1,8}\])?): +msg_id="([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})" +(.+)$/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  if(!validExtendedIsoTimestamp(head[7]!,true))return null;
  const header:Record<string,unknown>={
    month:head[2],day:head[3],time:head[4],hostname:head[5],
    device_time:head[7],app_tag:head[8],
  };
  if(head[1]!==undefined)header.pri=head[1];
  if(head[6]!==undefined)header.serial=head[6];
  return {
    watchguard_header:header,
    watchguard_message:{source_raw:raw,msg_id:head[9],message:head[10]},
  };
}

function dualTimestampSessionProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const match=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +1 +(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) +(\S{1,255}) +([A-Za-z0-9_.-]{1,64}): +- +- +- +(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}) +- +(\S{1,255}) +- +\[([^\]\r\n]{1,255})\] +(.+?) +- +(.+)$/.exec(raw);
  if(!match||!validBsdClock(match[1]!,match[2]!,match[3]!))return null;
  if(!validExtendedIsoTimestamp(match[5]!,false)||!validIsoPriClock(match[8]!,match[9]!,'Z'))return null;
  return {
    syslog:{month:match[1],day:match[2],time:match[3],hostname:match[4],
      version:'1',timestamp:match[5],source:match[6],app_tag:match[7]},
    session_envelope:{source_raw:raw,event_date:match[8],event_time:match[9],
      node:match[10],client:match[11],identity:match[12],message:match[13]},
  };
}

function bsdBracketPidMessageProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const match=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +([A-Za-z0-9_.-]{1,128}): +\[(\d{1,8})\]: +(.+)$/.exec(raw);
  if(!match||!validBsdClock(match[2]!,match[3]!,match[4]!))return null;
  if(match[1]!==undefined&&(Number(match[1])<0||Number(match[1])>191))return null;
  return {
    syslog:{...(match[1]!==undefined?{pri:match[1]}:{}),month:match[2],day:match[3],
      time:match[4],hostname:match[5],app_tag:match[6]},
    generic:{mode:'bsd_bracket_pid_message',source_raw:raw,pid:match[7],message:match[8]},
  };
}

function bsdClassicPidMessageProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  // Bounded legacy shape seen in device logs:
  // "Mon DD HH:MM:SS app[pid]: TAG: message". There is no separate host token,
  // so preserve the app token as the source hostname instead of letting the
  // looser tagged-message grammar absorb "app[pid]:" as a hostname.
  const match=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +([A-Za-z0-9_.-]{1,128})\[(\d{1,8})\]: +([A-Za-z0-9_.-]{1,128}): +(.+)$/.exec(raw);
  if(!match||!validBsdClock(match[2]!,match[3]!,match[4]!))return null;
  if(match[1]!==undefined&&(Number(match[1])<0||Number(match[1])>191))return null;
  return {
    syslog:{...(match[1]!==undefined?{pri:match[1]}:{}),month:match[2],day:match[3],
      time:match[4],hostname:match[5],app_tag:match[7]},
    generic:{mode:'bsd_classic_pid_message',source_raw:raw,pid:match[6],message:match[8]},
  };
}

function bsdTaggedMessageProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const match=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +([A-Za-z0-9_.-]{1,128}): +(.+)$/.exec(raw);
  if(!match||!validBsdClock(match[2]!,match[3]!,match[4]!))return null;
  if(match[1]!==undefined&&(Number(match[1])<0||Number(match[1])>191))return null;
  // Do not let malformed bracket-id messages bypass the stricter bracket-id
  // profile by falling through to this generic tagged-message grammar.
  if(/^\[\d+\]:/.test(match[7]!))return null;
  return {
    syslog:{...(match[1]!==undefined?{pri:match[1]}:{}),month:match[2],day:match[3],
      time:match[4],hostname:match[5],app_tag:match[6]},
    generic:{mode:'bsd_tagged_message',source_raw:raw,message:match[7]},
  };
}

function juniperLegacyProfile(raw:string):Record<string,unknown>|null{
  const head=/^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +(\S+) +([^:\s]{1,128}): +/.exec(raw);
  if(!head||head[5]!=='RT_FLOW'||!validBsdClock(head[1]!,head[2]!,head[3]!))return null;
  const after=raw.slice(head[0].length);
  const event=/^(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.exec(after);
  if(!event)return null;
  const body=scanProfileTokens(raw,head[0].length+event[0].length);
  if(!body)return null;
  const tuples=body.tokens.filter(value=>value.includes('->'));
  if(!tuples.length||tuples.some(value=>!flowTupleToken(value)))return null;
  return {
    syslog:{month:head[1],day:head[2],time:head[3],hostname:head[4],app_tag:head[5]},
    juniper:{event:event[1],...body},
  };
}

function delimitedCommaKv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const parts=splitEscaped(raw,',');
  if(!parts||parts.length<4)return null;
  const fields:Record<string,unknown>={};let prefix='';let parsed=0;
  const safe=/^[A-Za-z0-9][A-Za-z0-9 ._:/()#-]{0,127}$/;
  for(let index=0;index<parts.length;index++){
    const segment=parts[index]!.trim();
    if(!segment)continue;
    const eq=segment.indexOf('=');
    if(eq<=0)return null;
    const before=segment.slice(0,eq).trimEnd();
    let key=before.trim();
    if(index===0){
      const cut=Math.max(before.lastIndexOf(': '),before.lastIndexOf('. '));
      if(cut>=0){
        const suffix=before.slice(cut+2).trim();
        if(safe.test(suffix)){key=suffix;prefix=before.slice(0,cut+2).trim();}
      }
    }
    if(!safe.test(key)||!sourceKeySafe(key))return null;
    let value=segment.slice(eq+1).trim();
    if(value.length>=2&&((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'"))))value=value.slice(1,-1);
    else if(value.startsWith('"')||value.startsWith("'")||value.endsWith('"')||value.endsWith("'"))return null;
    const previous=fields[key];
    fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    parsed++;
  }
  if(parsed<4)return null;
  const prefixTokens=prefix?prefix.split(/[ \t]+/).map(value=>
    value.length>1&&[':',','].includes(value[value.length-1]!)?value.slice(0,-1):value):[];
  if(prefixTokens.length>64||prefixTokens.some(value=>!value||new TextEncoder().encode(value).byteLength>256))return null;
  return {generic:{mode:'delimited_kv',delimiter:',',prefix_tokens:prefixTokens,fields}};
}

function rfc3164DelimitedCommaKv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +([A-Za-z0-9_.-]{1,128}): +/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  const body=delimitedCommaKv(raw.slice(head[0].length));
  if(!body)return null;
  const syslog:Record<string,unknown>={
    month:head[2],day:head[3],time:head[4],host:head[5],tag:head[6],
  };
  if(head[1]!==undefined)syslog.pri=head[1];
  return {syslog,...body};
}

function positionalCsvValues(text:string):string[]|null{
  if(!text||text.includes('\0'))return null;
  const values:string[]=[];let token='',quoted=false,afterQuote=false;
  for(let i=0;i<text.length;i++){
    const ch=text[i]!;
    if(quoted){
      if(ch==='"'){
        if(text[i+1]==='"'){token+='"';i++;continue;}
        quoted=false;afterQuote=true;continue;
      }
      token+=ch;continue;
    }
    if(afterQuote){
      if(ch===','){values.push(token);token='';afterQuote=false;continue;}
      return null;
    }
    if(ch==='"'&&token===''){quoted=true;continue;}
    if(ch===','){values.push(token);token='';continue;}
    token+=ch;
  }
  if(quoted)return null;
  values.push(token);
  return values;
}

function rfc3164PositionalCsv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  const body=raw.slice(head[0].length);
  if(/^[A-Za-z_][A-Za-z0-9_.-]*=/.test(body))return null;
  const columns=panosPositionalCsvBody(body);
  if(!columns)return null;
  const syslog:Record<string,unknown>={
    month:head[2],day:head[3],time:head[4],hostname:head[5],
  };
  if(head[1]!==undefined)syslog.pri=head[1];
  return {
    syslog,
    generic:{mode:'rfc3164_positional_csv',delimiter:',',source_raw:raw,columns},
  };
}


function boundedEnvelopeJson(text:string):Record<string,unknown>|null{
  if(!text.startsWith('{')||new TextEncoder().encode(text).byteLength>8192||text.includes('\0'))return null;
  if(jsonSourcePreflightError(text))return null;
  let parsed:unknown;
  try{parsed=JSON.parse(text);}catch{return null;}
  if(!parsed||Array.isArray(parsed)||typeof parsed!=='object')return null;
  let nodes=0;
  function safe(value:unknown,depth:number):boolean{
    if(depth>8||++nodes>2048)return false;
    if(Array.isArray(value))return value.length<=1024&&value.every(item=>safe(item,depth+1));
    if(value&&typeof value==='object'){
      for(const [key,item] of Object.entries(value as Record<string,unknown>)){
        if(!sourceKeySafe(key)||new TextEncoder().encode(key).byteLength>256||!safe(item,depth+1))return false;
      }
    }
    return true;
  }
  return safe(parsed,0)?parsed as Record<string,unknown>:null;
}

function boundedEmbeddedJsonBody(text:string):{
  mode:'cee_json'|'embedded_json';
  body:Record<string,unknown>;
  prefix:string;
}|null{
  if(new TextEncoder().encode(text).byteLength>8192||text.includes('\0'))return null;

  if(text.startsWith('@cee:')){
    const payload=text.slice(5).replace(/^ +/,'');
    const body=boundedEnvelopeJson(payload);
    return body?{mode:'cee_json',body,prefix:'@cee:'}:null;
  }

  let quote='',escaped=false;
  for(let index=0;index<text.length;index++){
    const ch=text[index]!;
    if(quote){
      if(escaped){escaped=false;continue;}
      if(ch==='\\'){escaped=true;continue;}
      if(ch===quote)quote='';
      continue;
    }
    if(ch==='"'||ch==="'"){quote=ch;continue;}
    if(ch!=='{')continue;
    const prefix=text.slice(0,index);
    if(prefix.includes('\uFEFF')||new TextEncoder().encode(prefix).byteLength>256)return null;
    const candidate=text.slice(index).trimEnd();
    const body=boundedEnvelopeJson(candidate);
    if(body)return {mode:'embedded_json',body,prefix:prefix.trimEnd()};
  }
  return null;
}

function boundedXmlBody(text:string):{root:string;fields:Record<string,unknown>}|null{
  if(new TextEncoder().encode(text).byteLength>8192||text.includes('\0'))return null;
  const source=text.trim();
  if(!source.startsWith('<')||/<!DOCTYPE|<!ENTITY|<\?xml-stylesheet/i.test(source))return null;
  let document:Document;
  try{document=new DOMParser().parseFromString(source,'application/xml');}catch{return null;}
  if(document.getElementsByTagName('parsererror').length)return null;
  const root=document.documentElement;
  if(!root)return null;
  const safeSegment=(value:string)=>/^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$/.test(value)&&sourceKeySafe(value);
  if(!safeSegment(root.localName))return null;
  const fields:Record<string,unknown>={};let nodes=0;
  const add=(key:string,value:string):boolean=>{
    if(!key||value.length>4096||value.includes('\0'))return false;
    const previous=fields[key];
    fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    return Object.keys(fields).length<=256;
  };
  const walk=(element:Element,parentPath:string,depth:number):boolean=>{
    if(depth>16||++nodes>256||!safeSegment(element.localName))return false;
    const semanticName=element.localName==='Data'?element.getAttribute('Name'):null;
    if(semanticName!==null&&(!safeSegment(semanticName)||semanticName.length>128))return false;
    const path=semanticName&&parentPath?parentPath+'.'+semanticName:
      parentPath?parentPath+'.'+element.localName:element.localName;
    for(const attribute of Array.from(element.attributes)){
      if(attribute.name==='xmlns'||attribute.prefix==='xmlns')continue;
      const name=attribute.localName;
      if(!safeSegment(name)||new TextEncoder().encode(attribute.value).byteLength>2048)return false;
      if(semanticName&&name==='Name')continue;
      if(!add(path+'.@'+name,attribute.value))return false;
    }
    const children=Array.from(element.children);
    if(!children.length){
      const value=element.textContent??'';
      if(value.trim()&&!add(path,value))return false;
      return true;
    }
    const direct=Array.from(element.childNodes)
      .filter(node=>node.nodeType===Node.TEXT_NODE)
      .map(node=>node.textContent??'').join('');
    if(direct.trim())return false;
    return children.every(child=>walk(child,path,depth+1));
  };
  if(!walk(root,'',0)||Object.keys(fields).length<3)return null;
  return {root:root.localName,fields};
}

function zeekConnTsvBody(text:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(text).byteLength>8192||text.includes('\0')||/[\r\n]/.test(text))return null;
  const values=text.split('\t');
  if(values.length<7||values.length>64)return null;
  if(!/^\d{9,12}(?:\.\d{1,9})?$/.test(values[0]??'')||
     !/^[A-Za-z0-9]{8,32}$/.test(values[1]??'')||
     !ipToken(values[2]??'')||!validPortToken(values[3]??'')||
     !ipToken(values[4]??'')||!validPortToken(values[5]??'')||
     !/^(?:tcp|udp|icmp|icmp6)$/.test(values[6]??''))return null;
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{
    if(new TextEncoder().encode(value).byteLength<=2048)columns['column_'+String(index)]=value;
  });
  return Object.keys(columns).length===values.length?columns:null;
}

function standaloneBindQueryProfile(raw:string):Record<string,unknown>|null{
  const query=parseBindQueryMessage(raw);
  return query?{bind_query:{...query,source_raw:raw}}:null;
}

function commaLabelValueBody(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||new TextEncoder().encode(text).byteLength>8192)return null;
  const segments=splitEscaped(text,',');
  if(!segments||segments.length<3||segments.length>128)return null;
  const fields:Record<string,unknown>={};
  for(const rawSegment of segments){
    const segment=rawSegment.trim();
    if(!segment)return null;
    const colon=segment.indexOf(':');
    if(colon<=0)return null;
    const key=segment.slice(0,colon).trim();
    if(!/^[A-Za-z][A-Za-z0-9 _./()#-]{0,127}$/.test(key)||!sourceKeySafe(key))return null;
    let value=segment.slice(colon+1).trim();
    if(value.length>=2&&((value.startsWith('"')&&value.endsWith('"'))||
       (value.startsWith("'")&&value.endsWith("'"))))value=value.slice(1,-1);
    else if(value.startsWith('"')||value.startsWith("'")||value.endsWith('"')||value.endsWith("'"))return null;
    if(/[\u0000-\u001f\u007f]/.test(value)||new TextEncoder().encode(value).byteLength>4096)return null;
    const previous=fields[key];
    fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    if(Object.keys(fields).length>100)return null;
  }
  return Object.keys(fields).length>=3?fields:null;
}

function standaloneXmlProfile(raw:string):Record<string,unknown>|null{
  const xml=boundedXmlBody(raw);
  return xml?{xml,generic:{mode:'bounded_xml',source_raw:raw}}:null;
}

function standaloneZeekTsvProfile(raw:string):Record<string,unknown>|null{
  const columns=zeekConnTsvBody(raw);
  return columns?{generic:{mode:'zeek_conn_tsv',profile:'zeek_conn_candidate',delimiter:'\t',source_raw:raw,columns}}:null;
}

function claimsPanosSignature(raw:string):boolean{
  if(!raw||/[\r\n\0]/.test(raw)||new TextEncoder().encode(raw).byteLength>8192)return false;
  return /(?:^| )\d{1,10},\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,9})?,[^,]{0,64},(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION|GTP|IPTAG|SCTP|TUNNEL|URL|DATA|WILDFIRE)(?:,|$)/.test(raw);
}

function looksLikePanosBody(text:string):boolean{
  const values=positionalCsvValues(text);
  if(!values||values.length<4)return false;
  return /^\d{1,10}$/.test(values[0]??'')&&
    /^\d{4}\/\d{2}\/\d{2} +\d{2}:\d{2}:\d{2}/.test(values[1]??'')&&
    /^(?:[A-Za-z0-9_.:-]{4,64})?$/.test(values[2]??'')&&
    /^[A-Z][A-Z0-9_]{2,31}$/.test(values[3]??'');
}

function panosPositionalCsvBody(text:string):Record<string,unknown>|null{
  const values=positionalCsvValues(text);
  if(!values||values.length<7||values.length>150)return null;
  if(!/^\d{0,10}$/.test(values[0]??''))return null;
  const received=/^(\d{4})\/(\d{2})\/(\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)$/.exec(values[1]??'');
  if(!received||!validIsoPriClock(
    received[1]+'-'+received[2]+'-'+received[3],received[4]!,'Z'
  ))return null;
  if(!/^(?:[A-Za-z0-9_.:-]{4,64})?$/.test(values[2]??''))return null;
  if(!/^(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION|GTP|IPTAG|SCTP|TUNNEL|URL|DATA|WILDFIRE)$/.test(values[3]??''))return null;
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{columns['column_'+String(index)]=value;});
  return columns;
}


function panosAuditPositionalCsvBody(text:string):Record<string,string>|null{
  if(new TextEncoder().encode(text).byteLength>8192)return null;
  const values=positionalCsvValues(text);
  if(!values||values.length!==8||!/^[0-9]{8,20}$/.test(values[0]??'')||
     values[2]!=='audit'||!/^[0-9]{1,10}$/.test(values[3]??'')||
     !/^[a-z][a-z0-9-]{1,63}$/.test(values[4]??'')||
     !(values[5]&&values[6])||!/^(?:success|failed|none)$/.test(values[7]??''))return null;
  const timestamp=/^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}:\d{2}:\d{2})$/.exec(values[1]??'');
  if(!timestamp||!validIsoPriClock(
    timestamp[1]+'-'+timestamp[2]+'-'+timestamp[3],timestamp[4]!,'Z'
  ))return null;
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{columns['column_'+String(index)]=value;});
  return columns;
}

function standalonePanosCsv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||/[\r\n\0]/.test(raw))return null;
  if(!looksLikePanosBody(raw))return null;
  const columns=panosPositionalCsvBody(raw);
  return columns?{
    generic:{mode:'standalone_positional_csv',profile:'panos',delimiter:',',source_raw:raw,columns},
  }:null;
}

function standalonePanosAuditCsv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||/[\r\n\0]/.test(raw))return null;
  const columns=panosAuditPositionalCsvBody(raw);
  return columns?{
    generic:{mode:'standalone_positional_csv',profile:'panos_audit',delimiter:',',source_raw:raw,columns},
  }:null;
}

function standaloneUnlabeledCsv(raw:string):Record<string,unknown>|null{
  const parsed=parseRfc4180SingleDataRow(raw);
  if(!parsed||parsed.values.length<7||parsed.values.length>150)return null;
  const {values,quotedFields}=parsed;
  const firstTimestamp=/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})$/.exec(values[0]??'');
  const secondTimestamp=/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})$/.exec(values[1]??'');
  const timestamp=firstTimestamp??(
    quotedFields===values.length&&/^\d{6,24}$/.test(values[0]??'')?secondTimestamp:null
  );
  if(!timestamp||!validIsoPriClock(timestamp[1]!,timestamp[2]!,'Z'))return null;
  if(quotedFields===0){
    if(values.length<12||values.filter(ipToken).length<2)return null;
  }else if(quotedFields!==values.length)return null;
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{columns['column_'+String(index)]=value;});
  return {generic:{
    mode:quotedFields===values.length?'quoted_csv_unlabeled':'csv_unlabeled_row',
    delimiter:',',source_raw:raw,columns,
  }};
}

function decodeDelimitedEqualsValue(raw:string,delimiter:string):string|null{
  let value=raw.trim();
  if(!value)return '';
  let quote='';
  if(value.startsWith('"')||value.startsWith("'")){
    quote=value[0]!;
    if(value.length<2||value[value.length-1]!==quote)return null;
    value=value.slice(1,-1);
  }else if(value.endsWith('"')||value.endsWith("'")){
    return null;
  }
  let decoded='';
  for(let index=0;index<value.length;index++){
    const ch=value[index]!;
    if(ch!=='\\'){decoded+=ch;continue;}
    const next=value[index+1];
    if(next===undefined)return null;
    if(next===delimiter||next==='\\'||next==='='||next==='"'||next==="'"){
      decoded+=next;index++;continue;
    }
    decoded+='\\'+next;index++;
  }
  if(/[\u0000-\u001f\u007f]/.test(decoded)&&!decoded.includes('\t'))return null;
  if(new TextEncoder().encode(decoded).byteLength>2048)return null;
  return decoded;
}

function shortEnvelopeSpaceKvBody(text:string):Record<string,unknown>|null{
  if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}=/.test(text))return null;
  const parsed=strictKeyValues(text);
  if(parsed.errors.length)return null;
  const keys=Object.keys(parsed.fields);
  if(keys.length<3||keys.length>4||keys.some(key=>!sourceKeySafe(key)))return null;
  return parsed.fields;
}

function delimitedEqualsKvBody(text:string,delimiter:string):Record<string,unknown>|null{
  if(!['|',';','\t'].includes(delimiter)||new TextEncoder().encode(text).byteLength>8192||text.includes('\0'))return null;
  const parts=splitEscaped(text,delimiter);
  if(!parts||parts.length<3||parts.length>128)return null;
  const fields:Record<string,unknown>={};
  for(const rawPart of parts){
    const part=rawPart.trim();
    if(!part)return null;
    const eq=part.indexOf('=');
    if(eq<=0)return null;
    const key=part.slice(0,eq).trim();
    if(!/^[A-Za-z_][A-Za-z0-9_.#\/-]{0,127}$/.test(key)||!sourceKeySafe(key))return null;
    const value=decodeDelimitedEqualsValue(part.slice(eq+1),delimiter);
    if(value===null)return null;
    const previous=fields[key];
    fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    if(Object.keys(fields).length>100)return null;
  }
  return Object.keys(fields).length>=3?fields:null;
}

function securityPositionalCsvBody(text:string):Record<string,unknown>|null{
  const values=positionalCsvValues(text);
  if(!values||values.length<12||values.length>150)return null;
  if(values.filter(ipToken).length<2)return null;
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{columns['column_'+String(index)]=value;});
  return columns;
}

function bracketColonKvBody(text:string):Record<string,unknown>|null{
  if(!text.startsWith('[')||!text.endsWith(']')||new TextEncoder().encode(text).byteLength>8192)return null;
  const inner=text.slice(1,-1);
  const segments=splitEscaped(inner,';');
  if(!segments)return null;
  const body:Record<string,unknown>={};
  for(const rawSegment of segments){
    const segment=rawSegment.trim();
    if(!segment)continue;
    const delimiter=/:\s*"/.exec(segment);
    if(!delimiter||delimiter.index<=0)return null;
    const key=segment.slice(0,delimiter.index).trim();
    if(!/^[A-Za-z_][A-Za-z0-9_.#:-]{0,127}$/.test(key)||!sourceKeySafe(key))return null;
    const encoded=segment.slice(delimiter.index+1).trim();
    if(encoded.length<2||!encoded.startsWith('"')||!encoded.endsWith('"'))return null;
    const value=encoded.slice(1,-1),previous=body[key];
    body[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    if(Object.keys(body).length>100)return null;
  }
  return Object.keys(body).length>=2?body:null;
}

function juniperRtFlowBody(text:string):Record<string,unknown>|null{
  const event=/^(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.exec(text);
  if(!event)return null;
  const body=scanProfileTokens(text,event[0].length);
  if(!body)return null;
  const tuples=body.tokens.filter(value=>value.includes('->'));
  if(!tuples.length||tuples.some(value=>!flowTupleToken(value)))return null;
  return {event:event[1],...body};
}

function looksLikeWatchguardBody(text:string):boolean{
  return /^(?:[A-Za-z0-9.-]{2,64} +)?(?:\([0-9T:+-]{19,35}\) +)?firewall(?:\[\d{1,8}\])?: +/.test(text);
}

function watchguardTrafficBody(text:string):{
  header:Record<string,unknown>;
  body:{tokens:string[];kv:Record<string,unknown>;groups:string[]};
}|null{
  const head=/^(?:([A-Za-z0-9.-]{2,64}) +)?(?:\(([0-9T:+-]{19,35})\) +)?(firewall(?:\[\d{1,8}\])?): +/.exec(text);
  if(!head)return null;
  if(head[2]!==undefined&&!validExtendedIsoTimestamp(head[2]!,true))return null;
  const body=scanProfileTokens(text,head[0].length);
  if(!body||!body.tokens.length||!['Allow','Deny','Drop'].includes(body.tokens[0]!))return null;
  const msgId=body.kv.msg_id;
  if(typeof msgId!=='string'||!/^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$/.test(msgId))return null;
  if(body.tokens.filter(ipToken).length<2)return null;
  return {
    header:{
      ...(head[1]?{serial:head[1]}:{}),
      ...(head[2]?{device_time:head[2]}:{}),
      app_tag:head[3],
    },
    body,
  };
}

function normalizedEnvelopeMessage(envelope:{variant:string;message:string}):string{
  return envelope.variant==='rfc5424'&&envelope.message.startsWith('\uFEFF')
    ?envelope.message.slice(1):envelope.message;
}

function junosStructuredDataElementsValid(
  elements:Array<{id:string;params:Record<string,string|string[]>}>,
):boolean{
  for(const element of elements){
    if(!element.id.startsWith('junos@'))continue;
    if(!/^junos@[A-Za-z0-9.:-]{1,64}$/.test(element.id))return false;
    const normalized=new Set<string>();
    for(const key of Object.keys(element.params)){
      if(Array.isArray(element.params[key]))return false;
      if(!/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(key)||!sourceKeySafe(key))return false;
      const safe=key.replaceAll('-','_');
      if(!sourceKeySafe(safe)||normalized.has(safe))return false;
      normalized.add(safe);
    }
  }
  return true;
}

function standaloneFortinetProfile(raw:string):Record<string,unknown>|null{
  const parsed=parseFortinetKvBody(raw);
  return parsed?{
    fortinet:{...parsed,source_raw:raw},
    generic:{mode:'fortinet_kv',source_raw:raw},
  }:null;
}

function standaloneSophosProfile(raw:string):Record<string,unknown>|null{
  const parsed=parseSophosKvBody(raw);
  return parsed?{
    sophos:{...parsed,source_raw:raw},
    generic:{mode:'sophos_kv',source_raw:raw},
  }:null;
}

function sophosUtmColonProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>16384||raw.includes('\0')||/[\r\n]/.test(raw))return null;
  const match=/^(?:<(\d{1,3})>)?(\d{4}):(\d{2}):(\d{2})-(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255}) +ulogd\[(\d{1,10})\]: +(.+)$/.exec(raw);
  if(!match)return null;
  if(match[1]!==undefined&&(Number(match[1])<0||Number(match[1])>191))return null;
  if(!validIsoPriClock(match[2]+'-'+match[3]+'-'+match[4],match[5]!,'Z'))return null;
  const body=parseSophosKvBody(match[8]!);
  if(!body||body.variant!=='utm')return null;
  const existing=spaceKv(raw);
  return {
    ...(existing??{}),
    syslog:{
      ...(match[1]!==undefined?{pri:match[1]}:{}),
      timestamp:match[2]+':'+match[3]+':'+match[4]+'-'+match[5],
      hostname:match[6],appname:'ulogd',procid:match[7],
    },
    sophos:{...body,source_raw:raw,message_raw:match[8]},
  };
}

function syslogEnvelopeStructuredFallback(raw:string):Record<string,unknown>|null{
  const envelope=parseSyslogEnvelope(raw);
  if(!envelope||envelope.variant==='colon_date')return null;
  const syslog=envelopeToSyslogFields(envelope);
  const messageRaw=envelope.message;
  const message=normalizedEnvelopeMessage(envelope);

  const junos=parseJunosBracketEvent(message);
  if(junos)return {
    syslog:{...syslog,appname:junos.appname,procid:junos.procid,msgid:junos.msgid,
      structured_data_raw:junos.structuredDataRaw},
    junos_sd:junos.fields,
    juniper:{source_raw:raw,message_raw:messageRaw,source_envelope:envelope.variant},
  };
  if(/^RT_[A-Z0-9_]+ - [A-Z][A-Z0-9_]+ \[junos@/.test(message))return null;

  const bareJunos=parseJunosBareBracketEvent(message);
  if(bareJunos)return {
    syslog:{...syslog,appname:bareJunos.appname,procid:bareJunos.procid,msgid:bareJunos.msgid,
      source_grammar:'junos_bare_bracket'},
    juniper_flow_kv:bareJunos.fields,
    juniper:{source_raw:raw,message_raw:messageRaw,source_envelope:envelope.variant},
  };
  if(claimsJunosBareFlow(message))return null;

  const fortinet=parseFortinetKvBody(message);
  if(fortinet)return {
    syslog,
    fortinet:{...fortinet,source_raw:raw,message_raw:messageRaw},
  };
  if(/^date=\d{4}-\d{2}-\d{2}\s+time=/.test(message)&&/\bdevname=/.test(message)&&/\bdevid=/.test(message))
    return null;

  if(message.startsWith('CISE_')){
    const ise=parseCiscoIseBody(message);
    if(ise)return {
      syslog,
      cisco_ise:{...ise,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  const sophos=parseSophosKvBody(message);
  if(sophos)return {
    syslog,
    sophos:{...sophos,source_raw:raw,message_raw:messageRaw},
  };
  if(claimsSophosXgShape(message)||/\bsys="SecureNet"(?:\s|$)/.test(message))return null;

  if(/^%(?:ASA|FTD)-/.test(message)){
    const parsed=asa(message);
    if(parsed?.asa&&typeof parsed.asa==='object'){
      const vendorSyslog=parsed.syslog&&typeof parsed.syslog==='object'
        ? parsed.syslog as Record<string,unknown>:{};
      return {
        syslog:{...syslog,...vendorSyslog},
        asa:{...(parsed.asa as Record<string,unknown>),source_raw:raw,message_raw:messageRaw},
      };
    }
    const generic=parseCiscoFirewallEnvelope(message);
    if(generic)return {
      syslog,
      cisco_firewall:{...generic,source_raw:raw,message_raw:messageRaw},
      generic:{mode:'syslog_envelope_cisco_firewall_message',source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(envelope.appname&&/^(?:ASA|FTD)-[0-7]-\d{6}$/.test(envelope.appname)){
    const generic=parseCiscoFirewallEnvelope(envelope.appname+': '+message);
    if(generic)return {
      syslog,
      cisco_firewall:{...generic,source_raw:raw,message_raw:messageRaw},
      generic:{mode:'syslog_envelope_cisco_firewall_message',source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(envelope.appname==='RT_FLOW'&&/^RT_FLOW_SESSION_[A-Z_]+:/.test(message)){
    const juniper=juniperRtFlowBody(message);
    if(juniper)return {
      syslog,
      juniper:{...juniper,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(/^%[A-Z0-9_]+-\d-[A-Z0-9_]+:/.test(message)){
    const cisco=parseCiscoIosMessage(message);
    if(cisco)return {
      syslog,
      cisco_ios:{...cisco,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(envelope.appname?.toLowerCase()==='named'&&message.startsWith('client ')){
    const bind=parseBindQueryMessage(message);
    if(bind)return {
      syslog,
      bind_query:{...bind,source_raw:raw,message_raw:messageRaw},
    };
    const security=parseBindSecurityMessage(message);
    if(security)return {
      syslog,
      bind_security:{...security,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(envelope.appname?.toLowerCase()==='sshd'){
    const ssh=parseSshdMessage(message);
    if(ssh)return {
      syslog,
      sshd:{...ssh,source_raw:raw,message_raw:messageRaw},
    };
  }

  const pam=parsePamMessage(message);
  if(pam)return {
    syslog,
    pam:{...pam,source_raw:raw,message_raw:messageRaw},
  };

  if(envelope.appname?.toLowerCase()==='sudo'){
    const sudo=parseSudoMessage(message);
    if(sudo)return {
      syslog,
      sudo:{...sudo,source_raw:raw,message_raw:messageRaw},
    };
  }

  if(message.startsWith('[')&&message.includes('[UFW ')){
    const ufw=parseUfwMessage(message);
    if(ufw)return {
      syslog,
      ufw:{...ufw,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(['hostd','vpxd'].includes(envelope.appname?.toLowerCase()??'')&&message.startsWith('[Originator@')){
    const originator=parseLegacyOriginatorMessage(message);
    if(originator)return {
      syslog,
      legacy_originator:{...originator,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  const audit=parseLinuxAuditRecord(message);
  if(audit)return {
    syslog,
    linux_audit:{...audit,source_raw:raw,message_raw:messageRaw},
    generic:{mode:'syslog_envelope_linux_audit_record',source_raw:raw,message_raw:messageRaw},
  };

  const wrappedHttp=parseHttpAccessLog(message);
  if(wrappedHttp?.http_access&&typeof wrappedHttp.http_access==='object'){
    const generic=wrappedHttp.generic&&typeof wrappedHttp.generic==='object'
      ? wrappedHttp.generic as Record<string,unknown>:{};
    return {
      syslog,
      http_access:{...(wrappedHttp.http_access as Record<string,unknown>),source_raw:raw,message_raw:messageRaw},
      generic:{...generic,mode:'syslog_envelope_'+String(generic.mode??'http_access'),source_raw:raw,message_raw:messageRaw},
    };
  }

  const wrappedSquid=parseSquidAccessLog(message);
  if(wrappedSquid?.squid_access&&typeof wrappedSquid.squid_access==='object')return {
    syslog,
    squid_access:{...(wrappedSquid.squid_access as Record<string,unknown>),source_raw:raw,message_raw:messageRaw},
    generic:{mode:'syslog_envelope_squid_native_access',source_raw:raw,message_raw:messageRaw},
  };

  const snort=snortAlertBody(message);
  if(snort)return {
    syslog,
    snort:{...snort,source_raw:raw,message_raw:messageRaw},
  };
  if(envelope.appname?.toLowerCase()==='snort'&&message.startsWith('['))return null;

  const bracket=bracketColonKvBody(message);
  if(bracket)return {
    syslog,
    body:bracket,
    generic:{mode:'syslog_envelope_bracket_colon_kv',source_raw:raw,message_raw:messageRaw},
  };

  if(looksLikeWatchguardBody(message)){
    const watchguard=watchguardTrafficBody(message);
    if(watchguard)return {
      syslog,
      watchguard_header:watchguard.header,
      watchguard:{...watchguard.body,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  if(/^CEF:/.test(message)){
    const parsed=extractStructuredFamily(message,'cef');
    if(!parsed.errors.length)return {
      syslog,body:parsed.fields,
      generic:{mode:'syslog_envelope_cef',source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }
  if(/^LEEF:/.test(message)){
    const parsed=extractStructuredFamily(message,'leef');
    if(!parsed.errors.length)return {
      syslog,body:parsed.fields,
      generic:{mode:'syslog_envelope_leef',source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  const json=boundedEnvelopeJson(message);
  if(json)return {
    syslog,body:json,
    generic:{mode:'syslog_envelope_json',source_raw:raw,message_raw:messageRaw},
  };

  const xml=boundedXmlBody(message);
  if(xml)return {
    syslog,xml,
    generic:{mode:'syslog_envelope_xml',source_raw:raw,message_raw:messageRaw},
  };
  if(message.trimStart().startsWith('<'))return null;

  const auditColumns=panosAuditPositionalCsvBody(message);
  if(auditColumns)return {
    syslog,
    generic:{
      mode:'syslog_envelope_positional_csv',profile:'panos_audit',delimiter:',',
      source_raw:raw,message_raw:messageRaw,columns:auditColumns,
    },
  };

  const panosMessage=message.startsWith('- ')?message.slice(2):message;
  if(looksLikePanosBody(panosMessage)){
    const panos=panosPositionalCsvBody(panosMessage);
    if(!panos)return null;
    return {
      syslog,
      generic:{
        mode:'syslog_envelope_positional_csv',profile:'panos',delimiter:',',
        ...(panosMessage!==message?{source_prefix:'-'}:{}),
        source_raw:raw,message_raw:messageRaw,columns:panos,
      },
    };
  }

  const embeddedJson=boundedEmbeddedJsonBody(message);
  if(embeddedJson)return {
    syslog,body:embeddedJson.body,
    generic:{
      mode:embeddedJson.mode==='cee_json'
        ?'syslog_envelope_cee_json':'syslog_envelope_embedded_json',
      prefix:embeddedJson.prefix,
      source_raw:raw,message_raw:messageRaw,
    },
  };
  if(message.startsWith('@cee:'))return null;

  for(const delimiter of ['\t','|',';']){
    const kv=delimitedEqualsKvBody(message,delimiter);
    if(kv)return {
      syslog,
      generic:{
        mode:'syslog_envelope_delimited_kv',delimiter,
        source_raw:raw,message_raw:messageRaw,kv,
      },
    };
  }

  const zeekColumns=zeekConnTsvBody(message);
  if(zeekColumns)return {
    syslog,
    generic:{
      mode:'syslog_envelope_zeek_tsv',profile:'zeek_conn_candidate',delimiter:'\t',
      source_raw:raw,message_raw:messageRaw,columns:zeekColumns,
    },
  };

  const vpcFlow=parseVpcFlowLogV2(message);
  if(vpcFlow)return {
    syslog,
    aws_vpc_flow:vpcFlow,
    generic:{mode:'syslog_envelope_aws_vpc_flow_v2',source_raw:raw,message_raw:messageRaw},
  };

  const albAccess=parseAlbAccessLog(message);
  if(albAccess)return {
    syslog,
    aws_alb_access:albAccess,
    generic:{mode:'syslog_envelope_aws_alb_access',source_raw:raw,message_raw:messageRaw},
  };

  const labelValues=commaLabelValueBody(message);
  if(labelValues)return {
    syslog,
    generic:{
      mode:'syslog_envelope_comma_label_value',
      source_raw:raw,message_raw:messageRaw,fields:labelValues,
    },
  };

  const shortKv=envelope.confidence==='partial'?null:shortEnvelopeSpaceKvBody(message);
  if(shortKv)return {
    syslog,
    generic:{
      mode:'syslog_envelope_space_kv',
      source_raw:raw,message_raw:messageRaw,kv:shortKv,
    },
  };

  if(claimsPanosSignature(raw))return null;
  const positional=securityPositionalCsvBody(message);
  if(positional)return {
    syslog,
    generic:{mode:'syslog_envelope_positional_csv',delimiter:',',source_raw:raw,message_raw:messageRaw,columns:positional},
  };

  if(envelope.appname?.toUpperCase()==='ASM'&&/^unit_hostname=/.test(message)){
    const f5=parseF5AsmBody(message);
    if(f5)return {
      syslog,
      f5_bigip:{module:'ASM',...f5,source_raw:raw,message_raw:messageRaw},
    };
    return null;
  }

  const comma=delimitedCommaKv(message);
  if(comma?.generic&&typeof comma.generic==='object'){
    const generic={...(comma.generic as Record<string,unknown>),source_raw:raw,message_raw:messageRaw};
    return {syslog,generic};
  }

  const spaced=spaceKv(message);
  if(spaced?.generic&&typeof spaced.generic==='object')return {
    syslog,
    generic:{...(spaced.generic as Record<string,unknown>),source_raw:raw,message_raw:messageRaw},
  };

  if(envelope.structuredDataElements?.length){
    if(!junosStructuredDataElementsValid(envelope.structuredDataElements))return null;
    return {
      syslog,
      generic:{mode:'syslog_envelope_structured_data',source_raw:raw,message_raw:messageRaw},
    };
  }

  return null;
}

function asa(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const id=/%(ASA|FTD)-(\d)-(\d{6}):[ \t]*/.exec(raw);
  if(!id||id.index===undefined)return null;
  const after=raw.slice(id.index+id[0].length);
  if(/%(?:ASA|FTD)-\d-\d{6}:[ \t]*/.test(after))return null;
  const severity=Number(id[2]);
  if(!Number.isInteger(severity)||severity<0||severity>7)return null;
  const built=after.match(/^(?<action>Built) (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>[0-9]{1,20}) for (?<src_interface>[A-Za-z0-9_.-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) \((?<mapped_src_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_src_port>[0-9]{1,5})\) to (?<dst_interface>[A-Za-z0-9_.-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5}) \((?<mapped_dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_dst_port>[0-9]{1,5})\)$/);
  const deny=after.match(/^(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?<src_interface>[A-Za-z0-9_.-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) dst (?<dst_interface>[A-Za-z0-9_.-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5})$/);
  const denyAccess=after.match(/^(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?:(?<src_context>v[12]):)?(?<src_interface>[A-Za-z0-9_.-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<src_port>[0-9]{1,5}))? dst (?:(?<dst_context>v[12]):)?(?<dst_interface>[A-Za-z0-9_.-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<dst_port>[0-9]{1,5}))? by access-group \"(?<access_group>[^\"\r\n]{0,128})\" \[(?<flag_1>0x[0-9A-Fa-f]+), (?<flag_2>0x[0-9A-Fa-f]+)\]$/);
  const full=built??deny??denyAccess;
  if(!full?.groups)return null;
  const fields:Record<string,unknown>={source_raw:raw,product:id[1],severity:id[2],message_id:id[3],...full.groups};
  for(const name of ['src_ip','dst_ip','mapped_src_ip','mapped_dst_ip']){
    const value=fields[name];
    if(value!==undefined&&(!ipToken(String(value))))return null;
  }
  for(const name of ['src_port','dst_port','mapped_src_port','mapped_dst_port']){
    const value=fields[name];
    if(value===undefined)continue;
    const port=Number(value);
    if(!Number.isInteger(port)||port<0||port>65535)return null;
  }
  const syslog:Record<string,unknown>={app_tag:`%${id[1]}-${id[2]}-${id[3]}`};
  const prefix=raw.slice(0,id.index);
  if(prefix){
    const header=prefix.match(/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(?:(\d{4}) +)?(\d{2}):(\d{2}):(\d{2}) +([^\s:]{1,255})(?: +([A-Za-z_][A-Za-z0-9_.-]{0,95}(?:\[\d{1,8}\])?))? *:? *$/);
    if(header){
      const pri=header[1]===undefined?undefined:Number(header[1]);
      const year=header[4]===undefined?undefined:Number(header[4]);
      const time=header[5]+':'+header[6]+':'+header[7];
      if((pri!==undefined&&(pri<0||pri>191))||
         (year!==undefined&&(year<1||year>9999))||
         (header[4]!==undefined
           ?!validBsdClockWithYear(header[2]!,header[3]!,header[4]!,time)
           :!validBsdClock(header[2]!,header[3]!,time)))return null;
      Object.assign(syslog,{
        ...(pri!==undefined?{pri:String(pri)}:{}),month:header[2],day:header[3],
        ...(year!==undefined?{year:header[4]}:{}),
        time:header[5]+':'+header[6]+':'+header[7],hostname:header[8],
        ...(header[9]?{source_tag:header[9]}:{}),
      });
    }else{
      const facility=prefix.match(/^([A-Z0-9]{2,16})\.([A-Z]{2,16}): +([!-~]{1,255}) +$/);
      const hostOnly=prefix.match(/^([!-~]{1,255}) +: +$/);
      if(facility)Object.assign(syslog,{source_facility:facility[1],source_level:facility[2],hostname:facility[3]});
      else if(hostOnly)Object.assign(syslog,{hostname:hostOnly[1]});
      else return null;
    }
  }
  return {syslog,asa:fields};
}

function nestedRelayStructuredSyslog(raw:string):Record<string,unknown>|null{
  const outer=parseSyslogEnvelope(raw);
  if(!outer||!outer.message.startsWith('<'))return null;
  const innerRaw=outer.message;
  const innerEnvelope=parseSyslogEnvelope(innerRaw);
  if(!innerEnvelope||innerEnvelope.message.startsWith('<'))return null;
  const inner=syslogEnvelopeStructuredFallback(innerRaw);
  if(!inner)return null;
  const fields=JSON.parse(JSON.stringify(inner)) as Record<string,unknown>;
  rewriteSyntheticSource(fields,innerRaw,raw);
  if(!fields.syslog||typeof fields.syslog!=='object'||Array.isArray(fields.syslog))return null;
  return {
    ...fields,
    relay:{
      depth:1,
      outer_syslog:envelopeToSyslogFields(outer),
      outer_message_raw:innerRaw,
      source_raw:raw,
    },
  };
}

function explicitHostlessBodyCandidate(message:string):boolean{
  if(/^CEF:|^LEEF:|^@cee:|^\{|^</.test(message))return true;
  if(/^%(?:ASA|FTD)-/.test(message)||/^RT_FLOW:/.test(message))return true;
  if(looksLikePanosBody(message))return true;
  if(parseVpcFlowLogV2(message)||parseAlbAccessLog(message)||zeekConnTsvBody(message))return true;
  if(boundedXmlBody(message))return true;
  for(const delimiter of ['\t','|',';']){
    if(delimitedEqualsKvBody(message,delimiter))return true;
  }
  if(shortEnvelopeSpaceKvBody(message))return true;
  const strictKv=strictKeyValues(message);
  if(!strictKv.errors.length&&Object.keys(strictKv.fields).length>=3)return true;
  return false;
}

function hostlessTimestampPrefix(raw:string):{pri?:string;prefix:string;message:string}|null{
  const pri=/^<(\d{1,3})>(.*)$/.exec(raw);
  if(!pri&&raw.startsWith('<'))return null;
  const rest=(pri?pri[2]!:raw).trimStart();
  const patterns=[
    /^([A-Z][a-z]{2} +\d{1,2} +(?:\d{4} +)?\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?: +\d{4})?(?: +(?:Z|[+-]\d{2}:?\d{2}))?) +(.+)$/,
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) +(.+)$/,
    /^(\d{4}[-/]\d{2}[-/]\d{2} +\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?: +(?:Z|[+-]\d{2}:?\d{2}))?) +(.+)$/,
    /^(\d{4}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(.+)$/,
  ] as const;
  for(const pattern of patterns){
    const match=pattern.exec(rest);
    if(match&&explicitHostlessBodyCandidate(match[2]!)&&
       (pri!==null||looksLikePanosBody(match[2]!)))
      return {...(pri?{pri:pri[1]!}:{}),prefix:match[1]!,message:match[2]!};
  }
  return null;
}

function rewriteSyntheticSource(value:unknown,synthetic:string,original:string):void{
  if(Array.isArray(value)){
    value.forEach(item=>rewriteSyntheticSource(item,synthetic,original));return;
  }
  if(!value||typeof value!=='object')return;
  const object=value as Record<string,unknown>;
  for(const [key,item] of Object.entries(object)){
    if(key==='source_raw'&&item===synthetic)object[key]=original;
    else rewriteSyntheticSource(item,synthetic,original);
  }
}

function hostlessStructuredSyslog(raw:string):Record<string,unknown>|null{
  const candidate=hostlessTimestampPrefix(raw);
  if(!candidate)return null;
  const synthetic=(candidate.pri!==undefined?'<'+candidate.pri+'>':'')+candidate.prefix+' __HOSTLESS__ '+candidate.message;
  const envelope=parseSyslogEnvelope(synthetic);
  if(!envelope||envelope.hostname!=='__HOSTLESS__')return null;
  const parsed=extractGenericStructuralUnframed(synthetic);
  if(parsed.errors.length)return null;
  const fields=JSON.parse(JSON.stringify(parsed.fields)) as Record<string,unknown>;
  const syslog=fields.syslog;
  if(!syslog||typeof syslog!=='object'||Array.isArray(syslog))return null;
  delete (syslog as Record<string,unknown>).hostname;
  (syslog as Record<string,unknown>).hostname_missing=true;
  rewriteSyntheticSource(fields,synthetic,raw);
  const generic=fields.generic;
  if(generic&&typeof generic==='object'&&!Array.isArray(generic))
    (generic as Record<string,unknown>).hostless_syslog=true;
  return fields;
}

function knownVendorStructuredFailure(raw:string):boolean{
  if(claimsJunosBareFlow(raw))return true;
  if(/^<\d{1,3}>1 /.test(raw)&&raw.includes(' [junos@'))return true;
  if(claimsPanosSignature(raw)||looksLikePanosBody(raw)||/^\d{8,20},\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2},audit,/.test(raw))return true;
  if(/^%?(?:ASA|FTD)-[0-7]-\d{6}:/.test(raw))return true;
  if(/^date=\d{4}-\d{2}-\d{2}\s+time=/.test(raw)&&/\bdevname=/.test(raw)&&/\bdevid=/.test(raw))return true;
  if(claimsSophosXgShape(raw))return true;
  if(/^(?:<\d{1,3}>)?\d{4}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\S+\s+ulogd\[\d+\]:/.test(raw))return true;
  const envelope=parseSyslogEnvelope(raw);
  if(!envelope)return false;
  const message=normalizedEnvelopeMessage(envelope);
  if(claimsJunosBareFlow(message))return true;
  if(/^RT_[A-Z0-9_]+ - [A-Z][A-Z0-9_]+ \[junos@/.test(message))return true;
  if(envelope.appname==='RT_FLOW'&&/^RT_FLOW_SESSION_[A-Z_]+:/.test(message))return true;
  if(/^%(?:ASA|FTD)-\d-\d{6}:/.test(message))return true;
  if(/^date=\d{4}-\d{2}-\d{2}\s+time=/.test(message)&&/\bdevname=/.test(message)&&/\bdevid=/.test(message))return true;
  if(message.startsWith('CISE_'))return true;
  if(envelope.appname?.toUpperCase()==='ASM'&&/^unit_hostname=/.test(message))return true;
  if((/\bdevice="SFW"\b/.test(message)&&/\blog_type=/.test(message))||/\bsys="SecureNet"\b/.test(message))return true;
  if(envelope.appname?.toLowerCase()==='sudo'&&/^[A-Za-z0-9_.@-]+ +: +/.test(message))return true;
  if(message.startsWith('[')&&message.includes('[UFW '))return true;
  if(looksLikePanosBody(message))return true;
  return false;
}

function extractGenericStructuralUnframed(raw:string):GenericStructuralExtraction{
  const strict=shortRfc5424Structured(raw)??shortRfc5424Json(raw)??prefixedJson(raw)??isoPriMixed(raw)??isoPriPositional(raw)??asa(raw)??watchguardProfile(raw)??watchguardMessageProfile(raw)??dualTimestampSessionProfile(raw)??bsdBracketPidMessageProfile(raw)??
    juniperLegacyProfile(raw)??junosRfc5424Sd(raw)??sourceQualifiedUnzonedJunos(raw)??sourceQualifiedZonedJunosBare(raw)??bracketColonKv(raw)??
    rfc3164DelimitedCommaKv(raw)??rfc3164PositionalCsv(raw)??standalonePanosCsv(raw)??standalonePanosAuditCsv(raw)??standaloneUnlabeledCsv(raw)??
    extractCiscoFirewallEnvelope(raw)??parseBindQueryLog(raw)??standaloneBindQueryProfile(raw)??
    parseCiscoIosSequenceSyslog(raw)??parseHttpAccessLog(raw)??parseApacheErrorLog(raw)??parseSquidAccessLog(raw)??parseWindowsFirewallLog(raw)??
    standaloneFortinetProfile(raw)??standaloneSophosProfile(raw)??sophosUtmColonProfile(raw)??
    extractClassicElbAccess(raw)??extractS3Access(raw)??extractLinuxAuditStructural(raw)??
    standaloneXmlProfile(raw)??standaloneZeekTsvProfile(raw)??extractVpcFlowStructural(raw)??extractAlbStructural(raw)??
    nestedRelayStructuredSyslog(raw)??hostlessStructuredSyslog(raw)??syslogEnvelopeStructuredFallback(raw)??priSpaceKv(raw);
  if(strict)return {fields:strict,errors:[]};
  if(hostlessTimestampPrefix(raw))
    return {fields:{},errors:['Hostless structured Syslog body failed strict validation']};
  if(knownVendorStructuredFailure(raw))
    return {fields:{},errors:['Known vendor structure failed strict validation']};
  const loose=commaKv(raw)??delimitedCommaKv(raw)??spaceKv(raw)??
    bsdClassicPidMessageProfile(raw)??bsdTaggedMessageProfile(raw);
  return loose?{fields:loose,errors:[]}:
    {fields:{},errors:['Event does not match the bounded Generic Structural compiler grammar']};
}

export function extractGenericStructural(raw:string):GenericStructuralExtraction{
  const frame=unwrapSingleSyslogRecord(raw);
  if(!frame.ok)return {fields:{},errors:[frame.error]};
  const parsed=extractGenericStructuralUnframed(frame.message);
  if(parsed.errors.length||frame.mode==='unframed')return parsed;
  return {
    fields:{
      ...parsed.fields,
      framing:{
        mode:frame.mode,
        ...(frame.octets!==undefined?{octets:frame.octets}:{}),
        source_raw:raw,
      },
    },
    errors:[],
  };
}
