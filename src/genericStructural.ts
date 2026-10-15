import {extractStructuredFamily} from './structuredFamilies';

/**
 * Browser twin of the backend's bounded Generic Structural compiler subset.
 * This is not a universal parser: only explicit closed grammars are accepted.
 */
export interface GenericStructuralExtraction {
  fields: Record<string, unknown>;
  errors: string[];
}

function validRfc3339(value:string):boolean{
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
    Number.isFinite(Date.parse(value));
}

function shortRfc5424Json(raw:string):Record<string,unknown>|null{
  const match=raw.match(/^<(\d{1,3})>(1) (\S{1,64}) ([!-~]{1,255}) (\{.*\})$/);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validRfc3339(match[3]!))return null;
  let body:unknown;
  try{body=JSON.parse(match[5]!);}catch{return null;}
  if(!body||Array.isArray(body)||typeof body!=='object')return null;
  return {
    syslog:{pri:match[1],version:match[2],timestamp:match[3],hostname:match[4]},
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
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?$/.exec(value);
  if(!match)return false;
  const month=Number(match[2]),day=Number(match[3]),hour=Number(match[4]),minute=Number(match[5]),second=Number(match[6]);
  const monthDays=[31,29,31,30,31,30,31,31,30,31,30,31];
  return month>=1&&month<=12&&day>=1&&day<=monthDays[month-1]!&&
    hour<=23&&minute<=59&&second<=59;
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

function spaceKv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const pattern=/(?:^|[ \t])([A-Za-z_][A-Za-z0-9_.-]{0,63})=/g;
  const entries:Array<{key:string;start:number;valueStart:number}>=[];
  let match:RegExpExecArray|null;
  while((match=pattern.exec(raw))!==null){
    const start=match.index+(match[0]![0]===' '||match[0]![0]==='\t'?1:0);
    entries.push({key:match[1]!,start,valueStart:match.index+match[0]!.length});
    if(entries.length>100)return null;
  }
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

function validBsdClock(month:string,dayText:string,time:string):boolean{
  const monthDays:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
  const day=Number(dayText),clock=time.split(':').map(Number);
  return !!monthDays[month]&&Number.isInteger(day)&&day>=1&&day<=monthDays[month]!&&
    clock.length===3&&clock[0]!>=0&&clock[0]!<=23&&clock[1]!>=0&&clock[1]!<=59&&clock[2]!>=0&&clock[2]!<=59;
}

function scanProfileTokens(raw:string,start:number):{tokens:string[];kv:Record<string,unknown>;groups:string[]}|null{
  if(start<0||start>raw.length||new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const tokens:string[]=[],groups:string[]=[];const kv:Record<string,unknown>={};let pos=start,count=0;
  while(pos<raw.length){
    while(pos<raw.length&&/\s/.test(raw[pos]!))pos++;
    if(pos===raw.length)break;
    if(++count>100)return null;
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

function ipToken(value:string):boolean{
  const v4=value.split('.');
  if(v4.length===4&&v4.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255))return true;
  return value.includes(':')&&/^[0-9A-Fa-f:]+$/.test(value)&&value.split(':').length>=3;
}

function watchguardProfile(raw:string):Record<string,unknown>|null{
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +([^\s]{1,255})(?: +([A-Za-z0-9.-]{2,64}))?(?: +\(([0-9T:+-]{19,35})\))? +(firewall(?:\[\d{1,8}\])?): +/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  if(head[7]!==undefined&&Number.isNaN(Date.parse(head[7]!)))return null;
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

function juniperLegacyProfile(raw:string):Record<string,unknown>|null{
  const head=/^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +(\S+) +([^:\s]{1,128}): +/.exec(raw);
  if(!head||head[5]!=='RT_FLOW'||!validBsdClock(head[1]!,head[2]!,head[3]!))return null;
  const after=raw.slice(head[0].length);
  const event=/^(RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+/.exec(after);
  if(!event)return null;
  const body=scanProfileTokens(raw,head[0].length+event[0].length);
  if(!body||!body.tokens.some(value=>/^[^/\s]+\/[0-9]{1,5}->[^/\s]+\/[0-9]{1,5}$/.test(value)))return null;
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

function asa(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const id=/%(ASA|FTD)-(\d)-(\d{6}):[ \t]*/.exec(raw);
  if(!id||id.index===undefined)return null;
  const after=raw.slice(id.index+id[0].length);
  if(/%(?:ASA|FTD)-\d-\d{6}:[ \t]*/.test(after))return null;
  const severity=Number(id[2]);
  if(!Number.isInteger(severity)||severity<0||severity>7)return null;
  const built=after.match(/^(?<action>Built) (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>[0-9]{1,20}) for (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) \((?<mapped_src_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_src_port>[0-9]{1,5})\) to (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5}) \((?<mapped_dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_dst_port>[0-9]{1,5})\)$/);
  const deny=after.match(/^(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) dst (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5})$/);
  const denyAccess=after.match(/^(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?:(?<src_context>v[12]):)?(?<src_interface>[A-Za-z0-9_.-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<src_port>[0-9]{1,5}))? dst (?:(?<dst_context>v[12]):)?(?<dst_interface>[A-Za-z0-9_.-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})(?:\/(?<dst_port>[0-9]{1,5}))? by access-group \"(?<access_group>[^\"\r\n]{0,128})\" \[(?<flag_1>0x[0-9A-Fa-f]+), (?<flag_2>0x[0-9A-Fa-f]+)\]$/);
  const full=built??deny??denyAccess;
  if(!full?.groups)return null;
  const fields:Record<string,unknown>={source_raw:raw,product:id[1],severity:id[2],message_id:id[3],...full.groups};
  for(const name of ['src_port','dst_port','mapped_src_port','mapped_dst_port']){
    const value=fields[name];
    if(value===undefined)continue;
    const port=Number(value);
    if(!Number.isInteger(port)||port<0||port>65535)return null;
  }
  const syslog:Record<string,unknown>={app_tag:`%${id[1]}-${id[2]}-${id[3]}`};
  const prefix=raw.slice(0,id.index);
  if(prefix){
    const header=prefix.match(/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}):(\d{2}):(\d{2}) +([!-~]{1,255}) *$/);
    if(header){
      const monthDays:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
      const day=Number(header[2]),hour=Number(header[3]),minute=Number(header[4]),second=Number(header[5]);
      if(!monthDays[header[1]!]||day<1||day>monthDays[header[1]!]!||
         hour<0||hour>23||minute<0||minute>59||second<0||second>59)return null;
      Object.assign(syslog,{month:header[1],day:header[2],time:`${header[3]}:${header[4]}:${header[5]}`,hostname:header[6]});
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

export function extractGenericStructural(raw:string):GenericStructuralExtraction{
  const fields=shortRfc5424Structured(raw)??shortRfc5424Json(raw)??asa(raw)??watchguardProfile(raw)??
    juniperLegacyProfile(raw)??junosRfc5424Sd(raw)??bracketColonKv(raw)??commaKv(raw)??
    rfc3164DelimitedCommaKv(raw)??delimitedCommaKv(raw)??spaceKv(raw);
  return fields?{fields,errors:[]}:
    {fields:{},errors:['Event does not match the bounded Generic Structural compiler grammar']};
}
