/**
 * Browser twin of the backend's bounded Generic Structural compiler subset.
 * This is not a universal parser: exactly three closed grammars are accepted.
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
  const fields=shortRfc5424Json(raw)??asa(raw)??commaKv(raw);
  return fields?{fields,errors:[]}:
    {fields:{},errors:['Event does not match the bounded Generic Structural compiler grammar']};
}
