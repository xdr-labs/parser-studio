import {extractStructuredFamily} from './structuredFamilies';
import {envelopeToSyslogFields,parseSyslogEnvelope} from './syslogEnvelope';
import {extractLeef2ImplicitTab} from './leef2ImplicitTab';
import {GENERIC_STRUCTURAL_MIXED_PROFILE_V1,type GenericStructuralProfile} from './genericStructuralProfiles';
import {hasDuplicateJsonObjectKeys} from './jsonDuplicateKeys';
export type {GenericStructuralProfile} from './genericStructuralProfiles';

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
  if(hasDuplicateJsonObjectKeys(match[5]!))return null;
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
  let body:unknown;
  try{body=JSON.parse(match[2]!);}catch{return null;}
  if(hasDuplicateJsonObjectKeys(match[2]!))return null;
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

function priSpaceKv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const match=/^<(\d{1,3})>(.+)$/.exec(raw);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191)return null;
  const parsed=spaceKv(match[2]!);
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

function ipToken(value:string):boolean{
  const v4=value.split('.');
  if(v4.length===4&&v4.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255))return true;
  return value.includes(':')&&/^[0-9A-Fa-f:]+$/.test(value)&&value.split(':').length>=3;
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

function watchguardMessageProfile(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||raw.includes('\0'))return null;
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) +([^\s]{1,255})(?: +([A-Za-z0-9.-]{2,64}))? +\(([0-9T:+-]{19,35})\) +(firewall(?:\[\d{1,8}\])?): +msg_id="([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})" +(.+)$/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  if(Number.isNaN(Date.parse(head[7]!)))return null;
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
  if(Number.isNaN(Date.parse(match[5]!))||!validIsoPriClock(match[8]!,match[9]!,'Z'))return null;
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
  // Do not let malformed known structures bypass stricter parsers by
  // falling through to this generic tagged-message grammar.
  if(/^\[\d+\]:/.test(match[7]!))return null;
  if(match[6]==='RT_FLOW'&&/^RT_FLOW_SESSION_/.test(match[7]!))return null;
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

function positionalCsvValues(text:string):string[]|null{
  if(!text||text.includes('\0'))return null;
  const values:string[]=[];let token='';let quoted=false;
  for(let i=0;i<text.length;i++){
    const ch=text[i]!;
    if(quoted){
      if(ch==='"'){
        if(text[i+1]==='"'){token+='"';i++;continue;}
        quoted=false;continue;
      }
      token+=ch;continue;
    }
    if(ch==='"'){quoted=true;continue;}
    if(ch===','){values.push(token);token='';continue;}
    token+=ch;
  }
  if(quoted)return null;
  values.push(token);
  return values;
}

const PANOS_TRAFFIC_53=[
  'domain','receive_time','serial','type','subtype','config_version','time_generated',
  'src','dst','natsrc','natdst','rule','srcuser','dstuser','app','vsys','from','to',
  'inbound_if','outbound_if','logset','time_received','sessionid','repeatcnt','sport',
  'dport','natsport','natdport','flags','protocol','action','bytes','bytes_sent',
  'bytes_received','packets','start_time','elapsed','category','seqno','actionflags',
  'srcloc','dstloc','cpadding','pkts_sent','pkts_received','session_end_reason',
  'dg_hier_level_1','dg_hier_level_2','dg_hier_level_3','dg_hier_level_4',
  'vsys_name','device_name','action_source',
] as const;
const PANOS_TRAFFIC_54=[
  ...PANOS_TRAFFIC_53.slice(0,38),'padding',...PANOS_TRAFFIC_53.slice(38),
] as const;

function panosTrafficFields(values:string[]):Record<string,string>|null{
  if(values.length<53||values[3]!=='TRAFFIC')return null;
  const datetime=/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/;
  const ip=/^(?:\d{1,3}\.){3}\d{1,3}$/;
  const validIp=(value:string)=>ip.test(value)&&value.split('.').every(part=>Number(part)<=255);
  if(!datetime.test(values[1]??'')||!datetime.test(values[6]??'')||
     !datetime.test(values[21]??'')||!datetime.test(values[35]??'')||
     !validIp(values[7]??'')||!validIp(values[8]??'')||
     !validIp(values[9]??'')||!validIp(values[10]??''))return null;
  for(const index of [24,25,26,27]){
    const value=values[index]??'';
    if(!/^\d{1,5}$/.test(value)||Number(value)>65535)return null;
  }
  if(!/^[A-Za-z0-9_.-]{1,24}$/.test(values[29]??'')||
     !/^[A-Za-z0-9_. -]{1,64}$/.test(values[30]??''))return null;
  const names=values.length>=54?PANOS_TRAFFIC_54:PANOS_TRAFFIC_53;
  const fields:Record<string,string>={};
  values.forEach((value,index)=>{
    fields[names[index]??('field_'+String(index))]=value;
  });
  return fields;
}

function rfc3164PositionalCsv(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192)return null;
  const head=/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +(\S{1,255}) +/.exec(raw);
  if(!head||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  if(head[1]!==undefined&&(Number(head[1])<0||Number(head[1])>191))return null;
  const body=raw.slice(head[0].length);
  if(/^[A-Za-z_][A-Za-z0-9_.-]*=/.test(body))return null;
  const values=positionalCsvValues(body);
  if(!values||values.length<12||values.length>100||!/^[0-9]{1,10}$/.test(values[0]??''))return null;
  const panosLike=values.length>=7&&
    /^\d{0,10}$/.test(values[0]??'')&&
    /^\d{4}\/\d{2}\/\d{2} +\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$/.test(values[1]??'')&&
    /^[A-Za-z0-9_.:-]{4,64}$/.test(values[2]??'')&&
    /^[A-Z][A-Z0-9_]{2,31}$/.test(values[3]??'');
  if(panosLike&&!panosPositionalCsvBody(body))return null;
  const ip=/^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ips=values.filter(value=>ip.test(value)&&value.split('.').every(part=>Number(part)<=255)).length;
  const securityCategory=values.some(value=>
    /^(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION)$/.test(value));
  if(ips<2||!securityCategory)return null;
  const panos=panosTrafficFields(values);
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{columns['column_'+String(index)]=value;});
  const syslog:Record<string,unknown>={
    month:head[2],day:head[3],time:head[4],hostname:head[5],
  };
  if(head[1]!==undefined)syslog.pri=head[1];
  return {
    syslog,
    generic:panos
      ?{mode:'panos_traffic_csv',delimiter:',',source_raw:raw,fields:panos}
      :{mode:'rfc3164_positional_csv',delimiter:',',source_raw:raw,columns},
  };
}


function boundedEnvelopeJson(text:string):Record<string,unknown>|null{
  if(!text.startsWith('{')||new TextEncoder().encode(text).byteLength>8192||text.includes('\0'))return null;
  let parsed:unknown;
  try{parsed=JSON.parse(text);}catch{return null;}
  if(hasDuplicateJsonObjectKeys(text))return null;
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

function panosPositionalCsvBody(text:string):Record<string,unknown>|null{
  const values=positionalCsvValues(text);
  if(!values||values.length<7||values.length>150)return null;
  if(!/^\d{0,10}$/.test(values[0]??''))return null;
  const received=/^(\d{4})\/(\d{2})\/(\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)$/.exec(values[1]??'');
  if(!received||!validIsoPriClock(
    received[1]+'-'+received[2]+'-'+received[3],received[4]!,'Z'
  ))return null;
  if(!/^[A-Za-z0-9_.:-]{4,64}$/.test(values[2]??''))return null;
  if(!/^(?:TRAFFIC|THREAT|SYSTEM|CONFIG|GLOBALPROTECT|USERID|CORRELATION|DECRYPTION|HIPMATCH|AUTHENTICATION|GTP|IPTAG|SCTP|TUNNEL|URL|DATA|WILDFIRE)$/.test(values[3]??''))return null;
  const columns:Record<string,string>={};
  values.forEach((value,index)=>{columns['column_'+String(index)]=value;});
  return columns;
}

function securityPositionalCsvBody(text:string):Record<string,unknown>|null{
  const values=positionalCsvValues(text);
  if(!values||values.length<12||values.length>150)return null;
  const ip=/^(?:\d{1,3}\.){3}\d{1,3}$/;
  const validIp=(value:string)=>ip.test(value)&&value.split('.').every(part=>Number(part)<=255);
  if(values.filter(validIp).length<2)return null;
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
  if(!body||!body.tokens.some(value=>/^[^/\s]+\/[0-9]{1,5}->[^/\s]+\/[0-9]{1,5}$/.test(value)))return null;
  return {event:event[1],...body};
}

function watchguardTrafficBody(text:string):{
  header:Record<string,unknown>;
  body:{tokens:string[];kv:Record<string,unknown>;groups:string[]};
}|null{
  const head=/^(?:([A-Za-z0-9.-]{2,64}) +)?(?:\(([0-9T:+-]{19,35})\) +)?(firewall(?:\[\d{1,8}\])?): +/.exec(text);
  if(!head)return null;
  if(head[2]!==undefined&&Number.isNaN(Date.parse(head[2]!)))return null;
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

function syslogEnvelopeStructuredFallback(raw:string):Record<string,unknown>|null{
  const envelope=parseSyslogEnvelope(raw);
  if(!envelope||envelope.variant==='colon_date')return null;
  const syslog=envelopeToSyslogFields(envelope);
  const message=envelope.message;

  if(/^%(?:ASA|FTD)-/.test(message)){
    const parsed=asa(message);
    if(!parsed?.asa||typeof parsed.asa!=='object')return null;
    const vendorSyslog=parsed.syslog&&typeof parsed.syslog==='object'
      ?parsed.syslog as Record<string,unknown>:{};
    return {
      syslog:{...syslog,...vendorSyslog},
      asa:{...(parsed.asa as Record<string,unknown>),source_raw:raw,message_raw:message},
    };
  }

  if(envelope.appname==='RT_FLOW'){
    const juniper=juniperRtFlowBody(message);
    if(juniper)return {
      syslog,
      juniper:{...juniper,source_raw:raw,message_raw:message},
    };
    return null;
  }

  if(message.startsWith('[')){
    const bracket=bracketColonKvBody(message);
    if(bracket)return {
      syslog,
      body:bracket,
      generic:{mode:'syslog_envelope_bracket_colon_kv',source_raw:raw,message_raw:message},
    };
    return null;
  }

  const watchguard=watchguardTrafficBody(message);
  if(watchguard)return {
    syslog,
    watchguard_header:watchguard.header,
    watchguard:{...watchguard.body,source_raw:raw,message_raw:message},
  };
  if(/\bfirewall(?:\[\d{1,8}\])?: +msg_id=/.test(message))return null;

  if(message.startsWith('CEF:')){
    if(!/^CEF:0\|/.test(message))return null;
    const parsed=extractStructuredFamily(message,'cef');
    if(parsed.errors.length)return null;
    return {
      syslog,body:parsed.fields,
      generic:{mode:'syslog_envelope_cef',source_raw:raw,message_raw:message},
    };
  }
  if(message.startsWith('LEEF:')){
    if(!/^LEEF:(?:1\.0|2\.0)\|/.test(message))return null;
    const parsed=extractStructuredFamily(message,'leef');
    if(parsed.errors.length)return null;
    return {
      syslog,body:parsed.fields,
      generic:{mode:'syslog_envelope_leef',source_raw:raw,message_raw:message},
    };
  }

  if(message.startsWith('{')){
    const json=boundedEnvelopeJson(message);
    if(!json)return null;
    return {
      syslog,body:json,
      generic:{mode:'syslog_envelope_json',source_raw:raw,message_raw:message},
    };
  }

  const panosValues=positionalCsvValues(message);
  const panosLike=!!panosValues&&panosValues.length>=7&&
    /^\d{0,10}$/.test(panosValues[0]??'')&&
    /^\d{4}\/\d{2}\/\d{2} +\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?$/.test(panosValues[1]??'')&&
    /^[A-Za-z0-9_.:-]{4,64}$/.test(panosValues[2]??'')&&
    /^[A-Z][A-Z0-9_]{2,31}$/.test(panosValues[3]??'');
  const panos=panosPositionalCsvBody(message);
  if(panos){
    const named=panosValues?panosTrafficFields(panosValues):null;
    return {
      syslog,
      generic:named
        ?{mode:'panos_traffic_csv',profile:'panos',delimiter:',',source_raw:raw,message_raw:message,fields:named}
        :{mode:'syslog_envelope_positional_csv',profile:'panos',delimiter:',',source_raw:raw,message_raw:message,columns:panos},
    };
  }
  if(panosLike)return null;

  const positional=securityPositionalCsvBody(message);
  if(positional)return {
    syslog,
    generic:{mode:'syslog_envelope_positional_csv',delimiter:',',source_raw:raw,message_raw:message,columns:positional},
  };

  const comma=delimitedCommaKv(message);
  if(comma?.generic&&typeof comma.generic==='object')return {
    syslog,
    generic:{...(comma.generic as Record<string,unknown>),source_raw:raw,message_raw:message},
  };

  const spaced=spaceKv(message);
  if(spaced?.generic&&typeof spaced.generic==='object')return {
    syslog,
    generic:{...(spaced.generic as Record<string,unknown>),source_raw:raw,message_raw:message},
  };

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
    const header=prefix.match(/^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) +(?:(\d{4}) +)?(\d{2}):(\d{2}):(\d{2}) +([^\s:]{1,255})(?: +([A-Za-z_][A-Za-z0-9_.-]{0,95}(?:\[\d{1,8}\])?))? *:? *$/);
    if(header){
      const monthDays:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
      const pri=header[1]===undefined?undefined:Number(header[1]);
      const day=Number(header[3]),year=header[4]===undefined?undefined:Number(header[4]);
      const hour=Number(header[5]),minute=Number(header[6]),second=Number(header[7]);
      if((pri!==undefined&&(pri<0||pri>191))||!monthDays[header[2]!]||day<1||day>monthDays[header[2]!]!||
         (year!==undefined&&(year<1||year>9999))||
         hour<0||hour>23||minute<0||minute>59||second<0||second>59)return null;
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

/** Additional, explicitly selected grammar; it does not widen the V15 routes. */
function syslogPrefixedKeyValues(raw:string):Record<string,unknown>|null{
  if(new TextEncoder().encode(raw).byteLength>8192||/[\u0000-\u0008\u000a-\u001f\u007f]/.test(raw))return null;
  const head=/^<(\d{1,3})>([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}) +([!-~]{1,255}) +([^\r\n]+)$/.exec(raw);
  if(!head||Number(head[1])>191||!validBsdClock(head[2]!,head[3]!,head[4]!))return null;
  const message=head[6]!;
  const first=/[ \t]([A-Za-z_][A-Za-z0-9_-]{0,63})=/.exec(message);
  if(!first)return null;
  let cursor=first.index+1;
  const prefix=message.slice(0,cursor);
  // A text prefix is retained literally. Do not hide malformed structured
  // payloads, unsafe keys or previously discoverable network tuples in it.
  // Only space and TAB are separators. Other Unicode remains literal data,
  // including Unicode spaces and line/paragraph separators in one record.
  if(!/[^ \t\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/.test(prefix)||
     new TextEncoder().encode(prefix).byteLength>1024||
     /[="'{}\[\]|<>\/]/.test(prefix)||
     /(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{0,4}:){2}|->/.test(prefix))return null;
  const fields:Record<string,unknown>={};
  const token=/^([A-Za-z_][A-Za-z0-9_-]{0,63})=(?:"((?:\\["\\]|[^"\\\u0000-\u001f\u007f])*)"|'((?:\\['\\]|[^'\\\u0000-\u001f\u007f])*)'|([^ \t"'\\]+))(?=[ \t]|$)/;
  while(cursor<message.length){
    const match=token.exec(message.slice(cursor));
    if(!match)return null;
    const key=match[1]!,value=match[2]??match[3]??match[4]!;
    if(!sourceKeySafe(key)||Object.prototype.hasOwnProperty.call(fields,key)||
       new TextEncoder().encode(value).byteLength>512)return null;
    fields[key]=value;
    if(Object.keys(fields).length>60)return null;
    cursor+=match[0].length;
    while(cursor<message.length&&/[ \t]/.test(message[cursor]!))cursor++;
  }
  if(Object.keys(fields).length<2)return null;
  return {
    syslog:{pri:head[1],month:head[2],day:head[3],time:head[4],hostname:head[5],
      time_policy:'YEAR_AND_ZONE_UNKNOWN'},
    generic:{mode:'syslog_prefix_kv',prefix,message_raw:message,source_raw:raw,kv:fields},
  };
}

export function extractGenericStructural(raw:string,profile?:GenericStructuralProfile):GenericStructuralExtraction{
  // Physical C0 control separators must not be misread as unquoted KV spacing.
  if(/[\x0b\x0c\x0d\x1c-\x1f]/.test(raw))
    return {fields:{},errors:['Unsupported physical control separator in Generic Structural source']};
  const includesLeef=profile==='leef2_implicit_tab'||profile===GENERIC_STRUCTURAL_MIXED_PROFILE_V1;
  const includesSyslog=profile==='syslog_prefix_kv'||profile===GENERIC_STRUCTURAL_MIXED_PROFILE_V1;
  // This selected profile owns the standalone LEEF 2.0 family. A legacy KV
  // route must not split its header or trim its TAB-delimited value spelling.
  if(includesLeef&&raw.startsWith('LEEF:2.0|')){
    const fields=extractLeef2ImplicitTab(raw);
    return fields?{fields,errors:[]}:
      {fields:{},errors:['Event does not match the bounded Generic Structural compiler grammar']};
  }
  const fields=shortRfc5424Structured(raw)??shortRfc5424Json(raw)??prefixedJson(raw)??isoPriMixed(raw)??isoPriPositional(raw)??asa(raw)??watchguardProfile(raw)??watchguardMessageProfile(raw)??dualTimestampSessionProfile(raw)??bsdBracketPidMessageProfile(raw)??
    juniperLegacyProfile(raw)??junosRfc5424Sd(raw)??bracketColonKv(raw)??
    rfc3164DelimitedCommaKv(raw)??rfc3164PositionalCsv(raw)??priSpaceKv(raw)??
    syslogEnvelopeStructuredFallback(raw)??commaKv(raw)??delimitedCommaKv(raw)??spaceKv(raw)??
    bsdClassicPidMessageProfile(raw)??bsdTaggedMessageProfile(raw)??
    (includesSyslog?syslogPrefixedKeyValues(raw):null);
  return fields?{fields,errors:[]}:
    {fields:{},errors:['Event does not match the bounded Generic Structural compiler grammar']};
}
