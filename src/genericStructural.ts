/**
 * Browser twin of the backend's bounded Generic Structural compiler subset.
 * This is not a universal parser: exactly four closed grammars are accepted.
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
  const match=raw.match(/^<(\d{1,3})>(1) (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?) ([!-~]{1,255}) ([!-~]{1,48}) ([!-~]{1,128}) ([!-~]{1,32}) (\[.*\])$/);
  if(!match)return null;
  const pri=Number(match[1]);
  if(!Number.isInteger(pri)||pri<0||pri>191||!validUnzonedTimestamp(match[3]!))return null;
  const inner=match[8]!.slice(1,-1);
  if(new TextEncoder().encode(inner).byteLength>8192)return null;
  const segments=splitEscaped(inner,';');
  if(!segments)return null;
  const body:Record<string,unknown>={};
  for(const rawSegment of segments){
    const segment=rawSegment.trim();
    if(!segment)continue;
    const colon=segment.indexOf(':');
    if(colon<=0)return null;
    const key=segment.slice(0,colon).trim();
    if(!/^[A-Za-z_][A-Za-z0-9_.#-]{0,127}$/.test(key)||Object.prototype.hasOwnProperty.call(body,key))return null;
    const encoded=segment.slice(colon+1).trim();
    if(encoded.length<2||!encoded.startsWith('"')||!encoded.endsWith('"'))return null;
    body[key]=encoded.slice(1,-1);
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
    if(Object.prototype.hasOwnProperty.call(fields,safe))return null;
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
    if(!/^[A-Za-z_][A-Za-z0-9_.#\/-]{0,127}$/.test(key)||
       Object.prototype.hasOwnProperty.call(fields,key))return null;
    let value=segment.slice(eq+1).trim();
    if(value.length>=2&&((value.startsWith('"')&&value.endsWith('"'))||
       (value.startsWith("'")&&value.endsWith("'"))))value=value.slice(1,-1);
    else if(value.startsWith('"')||value.startsWith("'")||value.endsWith('"')||value.endsWith("'"))return null;
    fields[key]=value;
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
    if(Object.prototype.hasOwnProperty.call(fields,entry.key))return null;
    const end=index+1<entries.length?entries[index+1]!.start:raw.length;
    let value=raw.slice(entry.valueStart,end).trim();
    const quoted=value.length>=2&&
      ((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'")));
    if(quoted)value=value.slice(1,-1);
    else if(value.startsWith('"')||value.startsWith("'")||value.endsWith('"')||value.endsWith("'"))return null;
    if(/[\u0000-\u001f\u007f]/.test(value)||new TextEncoder().encode(value).byteLength>512)return null;
    fields[entry.key]=value;
    if(!quoted&&/[ \t]/.test(value)){
      const first=value.split(/[ \t]+/)[0]!;
      const safe=entry.key.replaceAll('-','_')+'_001';
      atoms[safe]=first;
    }
  }
  const generic:Record<string,unknown>={mode:'space_kv',source_raw:raw,kv:fields};
  tokens.forEach((value,index)=>{generic['prefix_'+String(index+1).padStart(3,'0')]=value;});
  if(Object.keys(atoms).length)generic.atoms=atoms;
  return {generic};
}

function asa(raw:string):Record<string,unknown>|null{
  const id=/%(ASA|FTD)-(\d)-(\d{6}):[ \t]*/.exec(raw);
  if(!id||id.index===undefined)return null;
  const after=raw.slice(id.index+id[0].length);
  if(/%(?:ASA|FTD)-\d-\d{6}:[ \t]*/.test(after))return null;
  const severity=Number(id[2]);
  if(!Number.isInteger(severity)||severity<0||severity>7)return null;
  const built=after.match(/^(?<action>Built) (?<direction>inbound|outbound) (?<protocol>TCP|UDP) connection (?<connection_id>[0-9]{1,20}) for (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) \((?<mapped_src_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_src_port>[0-9]{1,5})\) to (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5}) \((?<mapped_dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<mapped_dst_port>[0-9]{1,5})\)$/);
  const deny=after.match(/^(?<action>Deny) (?<protocol>tcp|udp|icmp) src (?<src_interface>[A-Za-z0-9_.:-]{1,64}):(?<src_ip>[0-9A-Fa-f:.]{2,64})\/(?<src_port>[0-9]{1,5}) dst (?<dst_interface>[A-Za-z0-9_.:-]{1,64}):(?<dst_ip>[0-9A-Fa-f:.]{2,64})\/(?<dst_port>[0-9]{1,5})$/);
  const full=built??deny;
  if(!full?.groups)return null;
  const fields:Record<string,unknown>={product:id[1],severity:id[2],message_id:id[3],...full.groups};
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
    if(!header)return null;
    const monthDays:Record<string,number>={Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31};
    const day=Number(header[2]),hour=Number(header[3]),minute=Number(header[4]),second=Number(header[5]);
    if(!monthDays[header[1]!]||day<1||day>monthDays[header[1]!]!||
       hour<0||hour>23||minute<0||minute>59||second<0||second>59)return null;
    Object.assign(syslog,{month:header[1],day:header[2],time:`${header[3]}:${header[4]}:${header[5]}`,hostname:header[6]});
  }
  return {syslog,asa:fields};
}

export function extractGenericStructural(raw:string):GenericStructuralExtraction{
  const fields=shortRfc5424Json(raw)??asa(raw)??junosRfc5424Sd(raw)??bracketColonKv(raw)??commaKv(raw)??spaceKv(raw);
  return fields?{fields,errors:[]}:
    {fields:{},errors:['Event does not match the bounded Generic Structural compiler grammar']};
}
