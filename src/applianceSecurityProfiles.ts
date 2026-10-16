import {strictKeyValues} from './structuredFamilies';

const MAX_BYTES=16384;
const UNSAFE=new Set(['__proto__','constructor','prototype']);
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
function clock(value:string):boolean{
  const m=/^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?$/.exec(value);
  return !!m&&Number(m[1])<=23&&Number(m[2])<=59&&Number(m[3])<=59;
}
function date(value:string):boolean{
  const m=/^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if(!m)return false;
  const y=Number(m[1]),mo=Number(m[2]),d=Number(m[3]);
  if(y<1||y>9999||mo<1||mo>12||d<1)return false;
  const leap=y%4===0&&(y%100!==0||y%400===0);
  return d<=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31][mo-1]!;
}
function validZone(value:string):boolean{
  if(/^[A-Z]{2,8}$/.test(value))return true;
  const m=/^([+-])(\d{2}):?(\d{2})$/.exec(value);
  return !!m&&Number(m[2])<=23&&Number(m[3])<=59;
}
function safeRecord(fields:Record<string,unknown>):boolean{
  return Object.keys(fields).length<=256&&Object.entries(fields).every(([key,value])=>
    /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(key)&&!UNSAFE.has(key)&&
    typeof value==='string'&&bytes(value)<=8192
  );
}

export function parseFortinetKvBody(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>MAX_BYTES)return null;
  const parsed=strictKeyValues(text);
  if(parsed.errors.length||!safeRecord(parsed.fields))return null;
  const f=parsed.fields as Record<string,string>;
  if(!date(f.date??'')||!clock(f.time??'')||!f.devname||!f.devid||!f.type)return null;
  if(f.logid!==undefined&&!/^\d{6,16}$/.test(f.logid))return null;
  if(f.tz!==undefined&&!validZone(f.tz))return null;
  for(const key of ['srcip','dstip','transip','remip'])if(f[key]!==undefined&&!ip(f[key]!))return null;
  for(const key of ['srcport','dstport','transport','remport'])if(f[key]!==undefined&&!port(f[key]!))return null;
  return {fields:f};
}

export function parseSophosKvBody(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>MAX_BYTES)return null;
  const parsed=strictKeyValues(text);
  if(parsed.errors.length||!safeRecord(parsed.fields))return null;
  const f=parsed.fields as Record<string,string>;
  const xg=f.device==='SFW'&&date(f.date??'')&&clock(f.time??'')&&!!f.device_name&&!!f.log_type;
  const utm=f.sys==='SecureNet'&&!!f.sub&&!!f.id&&!!f.severity;
  if(!xg&&!utm)return null;
  if(xg&&f.timezone!==undefined&&!validZone(f.timezone))return null;
  for(const key of ['src_ip','dst_ip','srcip','dstip'])if(f[key]!==undefined&&!ip(f[key]!))return null;
  for(const key of ['src_port','dst_port','srcport','dstport'])if(f[key]!==undefined&&!port(f[key]!))return null;
  return {variant:xg?'xg':'utm',fields:f};
}

function splitEscapedComma(text:string):string[]|null{
  const out:string[]=[];let current='';let escaped=false;let quoted=false;
  for(const ch of text){
    if(escaped){current+=ch;escaped=false;continue;}
    if(ch==='\\'){current+=ch;escaped=true;continue;}
    if(ch==='"'){current+=ch;quoted=!quoted;continue;}
    if(ch===','&&!quoted){out.push(current.trim());current='';continue;}
    current+=ch;
  }
  if(escaped||quoted)return null;
  out.push(current.trim());
  return out;
}
function decodeIseValue(value:string):string|null{
  let text=value.trim();
  if(text.startsWith('"')){
    if(text.length<2||!text.endsWith('"'))return null;
    text=text.slice(1,-1);
  }
  text=text.replace(/\\,/g,',').replace(/\\\\/g,'\\');
  return bytes(text)<=8192?text:null;
}

export function parseCiscoIseBody(text:string):Record<string,unknown>|null{
  if(!text||text.includes('\0')||/[\r\n]/.test(text)||bytes(text)>MAX_BYTES)return null;
  const head=/^(CISE_[A-Za-z0-9_]+) +(\d{8,12}) +(\d{1,3}) +(\d{1,3}) +(.*)$/.exec(text);
  if(!head)return null;
  let rest=head[5]!;
  const inner=/^(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{2}:?\d{2}) +(\d{8,12}) +(\d{1,6}) +(DEBUG|INFO|WARN|ERROR|FATAL) +(.*)$/.exec(rest);
  const header:Record<string,unknown>={category:head[1],sequence:head[2],format_major:head[3],format_minor:head[4]};
  if(inner){
    if(!date(inner[1]!)||!clock(inner[2]!)||!validZone(inner[3]!))return null;
    Object.assign(header,{event_date:inner[1],event_time:inner[2],timezone:inner[3],event_sequence:inner[4],message_code:inner[5],level:inner[6]});
    rest=inner[7]!;
  }
  const segments=splitEscapedComma(rest);
  if(!segments||!segments.length)return null;
  const fields:Record<string,string|string[]>=Object.create(null);
  let message='';
  for(const segment of segments){
    if(!segment)continue;
    const eq=segment.indexOf('=');
    if(eq<=0){if(fields && !Object.keys(fields).length){message=message?message+', '+segment:segment;continue;} return null;}
    const key=segment.slice(0,eq).trim(),rawValue=segment.slice(eq+1);
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(key)||UNSAFE.has(key))return null;
    const value=decodeIseValue(rawValue);
    if(value===null)return null;
    const previous=fields[key];
    fields[key]=previous===undefined?value:Array.isArray(previous)?[...previous,value]:[previous,value];
    if(Object.keys(fields).length>256)return null;
  }
  if(!Object.keys(fields).length)return null;
  return {header,message,fields};
}
