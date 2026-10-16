export interface LinuxAuditAvc{decision:'denied'|'granted';permissions:string[];}

export interface LinuxAuditRecord{
  node?:string;
  type:string;
  event_seconds:string;
  event_fraction?:string;
  event_serial:string;
  epoch:string;
  serial:string;
  event_id:string;
  fields:Record<string,string|string[]>;
  residual:string;
  avc?:LinuxAuditAvc;
  source_raw:string;
}

export interface LinuxAuditEvent{
  event_id:string;epoch:string;serial:string;
  records:LinuxAuditRecord[];record_types:string[];
}

export type LinuxAuditStreamResult=
  |{ok:true;events:LinuxAuditEvent[];records:LinuxAuditRecord[]}
  |{ok:false;error:string};

const MAX_RECORD_BYTES=16*1024;
const MAX_STREAM_BYTES=1024*1024;
const MAX_RECORDS=2000;
const MAX_EVENTS=1000;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}
function safeNode(value:string):boolean{
  return /^[A-Za-z0-9](?:[A-Za-z0-9_.:-]{0,253}[A-Za-z0-9])?$/.test(value);
}

function decodeValue(raw:string):string|null{
  const value=raw.trim();
  if(value===''||bytes(value)>8192)return value===''?'':null;
  if(value[0]==='"'||value[0]==="'"){
    const quote=value[0];
    if(value.length<2||value[value.length-1]!==quote)return null;
    let out='';
    for(let index=1;index<value.length-1;index++){
      const ch=value[index]!;
      if(ch==='\\'){
        const next=value[index+1];
        if(next===undefined||index+1>=value.length-1)return null;
        if(next===quote||next==='\\'){out+=next;index++;continue;}
        out+='\\'+next;index++;continue;
      }
      if(ch==='\r'||ch==='\n'||ch==='\0')return null;
      out+=ch;
    }
    return out;
  }
  if(value.includes('"')||value.includes("'")||/[\r\n\0]/.test(value))return null;
  return value;
}

function parseKeyValues(text:string):{fields:Record<string,string|string[]>;residual:string}|null{
  const matches=[...text.matchAll(/(?:^|[ \t])([A-Za-z_][A-Za-z0-9_.-]{0,127})=/g)];
  if(!matches.length)return {fields:{},residual:text.trim()};
  const first=matches[0]!;
  const residual=text.slice(0,first.index??0).trim();
  if(bytes(residual)>4096)return null;
  const fields:Record<string,string|string[]>={};
  for(let index=0;index<matches.length;index++){
    const match=matches[index]!,key=match[1]!;
    if(UNSAFE_KEYS.has(key))return null;
    const eq=(match.index??0)+match[0].lastIndexOf('=');
    const end=index+1<matches.length?(matches[index+1]!.index??text.length):text.length;
    const decoded=decodeValue(text.slice(eq+1,end));
    if(decoded===null)return null;
    const previous=fields[key];
    fields[key]=previous===undefined?decoded:Array.isArray(previous)?[...previous,decoded]:[previous,decoded];
    if(Object.keys(fields).length>256)return null;
  }
  return {fields,residual};
}

function parseAuditBody(type:string,text:string):{fields:Record<string,string|string[]>;residual:string;avc?:LinuxAuditAvc}|null{
  if(type!=='AVC')return parseKeyValues(text);
  const match=/^avc: +(denied|granted) +\{ +([A-Za-z0-9_:-]+(?: +[A-Za-z0-9_:-]+)*) +\} +for(?: +(.*))?$/.exec(text);
  if(!match)return null;
  const parsed=parseKeyValues(match[3]??'');
  if(!parsed||parsed.residual)return null;
  return {
    fields:parsed.fields,residual:'avc: '+match[1]+' { '+match[2]+' } for',
    avc:{decision:match[1] as 'denied'|'granted',permissions:match[2]!.split(/ +/)},
  };
}

export function parseLinuxAuditRecord(raw:string):LinuxAuditRecord|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>MAX_RECORD_BYTES)return null;
  const head=/^(?:node=([^ ]+) +)?type=([A-Z][A-Z0-9_]{1,63}) +msg=audit\((\d{9,12})(?:\.(\d{1,9}))?:([1-9]\d{0,19})\):(?: +(.*))?$/.exec(raw);
  if(!head||(head[1]!==undefined&&!safeNode(head[1])))return null;
  const body=parseAuditBody(head[2]!,head[6]??'');
  if(!body)return null;
  const epoch=head[3]!+(head[4]?'.'+head[4]:'');
  return {
    ...(head[1]?{node:head[1]}:{}),type:head[2]!,
    event_seconds:head[3]!,...(head[4]?{event_fraction:head[4]}:{}),event_serial:head[5]!,
    epoch,serial:head[5]!,event_id:epoch+':'+head[5],
    fields:body.fields,residual:body.residual,...(body.avc?{avc:body.avc}:{}),source_raw:raw,
  };
}

export function groupLinuxAuditStream(raw:string):LinuxAuditStreamResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_STREAM_BYTES)return {ok:false,error:'Invalid or oversized Linux Audit stream'};
  const normalized=raw.replace(/\r\n/g,'\n');
  if(normalized.includes('\r'))return {ok:false,error:'Unsupported Linux Audit line ending'};
  const lines=normalized.endsWith('\n')?normalized.slice(0,-1).split('\n'):normalized.split('\n');
  if(!lines.length||lines.length>MAX_RECORDS||lines.some(line=>line===''))return {ok:false,error:'Linux Audit stream contains empty or too many records'};
  const records:LinuxAuditRecord[]=[],events=new Map<string,LinuxAuditEvent>();
  for(const line of lines){
    const record=parseLinuxAuditRecord(line);
    if(!record)return {ok:false,error:'Linux Audit stream contains a malformed record'};
    records.push(record);
    let event=events.get(record.event_id);
    if(!event){
      if(events.size>=MAX_EVENTS)return {ok:false,error:'Linux Audit event limit exceeded'};
      event={event_id:record.event_id,epoch:record.epoch,serial:record.serial,records:[],record_types:[]};events.set(record.event_id,event);
    }
    event.records.push(record);
    if(!event.record_types.includes(record.type))event.record_types.push(record.type);
  }
  return {ok:true,events:[...events.values()],records};
}

export function extractLinuxAuditStructural(raw:string):Record<string,unknown>|null{
  const record=parseLinuxAuditRecord(raw);
  return record?{linux_audit:record,generic:{mode:'linux_audit_record',source_raw:raw}}:null;
}
