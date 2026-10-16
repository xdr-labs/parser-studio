export interface CriLogEvent{
  stream:'stdout'|'stderr';
  first_timestamp:string;
  last_timestamp:string;
  fragments:number;
  content:string;
  raw_lines:string[];
}

export type CriLogStreamResult=
  |{ok:true;events:CriLogEvent[]}
  |{ok:false;error:string};

export interface DockerJsonLogEvent{
  stream:'stdout'|'stderr';
  time:string;
  log:string;
  content:string;
  raw:string;
  extra:Record<string,unknown>;
}

export type DockerJsonLogStreamResult=
  |{ok:true;events:DockerJsonLogEvent[]}
  |{ok:false;error:string};

const MAX_STREAM_BYTES=1024*1024;
const MAX_RECORDS=2000;
const MAX_EVENT_BYTES=256*1024;
const MAX_FRAGMENTS=1024;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function validCalendar(year:number,month:number,day:number):boolean{
  if(year<1||year>9999||month<1||month>12||day<1)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1]!;
}

function validRfc3339Nano(value:string):boolean{
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if(!match)return false;
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  const hour=Number(match[4]),minute=Number(match[5]),second=Number(match[6]);
  if(!validCalendar(year,month,day)||hour>23||minute>59||second>59)return false;
  const zone=match[8]!;
  if(zone==='Z')return true;
  const zoneMatch=/^[+-](\d{2}):(\d{2})$/.exec(zone);
  return !!zoneMatch&&Number(zoneMatch[1])<=23&&Number(zoneMatch[2])<=59;
}

function normalizePayload(value:string):string{
  return value.endsWith('\r\n')?value.slice(0,-2):value.endsWith('\n')?value.slice(0,-1):value;
}

export function parseCriLogStream(raw:string):CriLogStreamResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_STREAM_BYTES||!raw.endsWith('\n'))
    return {ok:false,error:'Invalid or incomplete CRI log stream'};
  if(raw.includes('\r'))return {ok:false,error:'CRI log stream must use LF record separators'};
  const lines=raw.slice(0,-1).split('\n');
  if(!lines.length||lines.length>MAX_RECORDS||lines.some(line=>line===''))
    return {ok:false,error:'CRI log stream contains empty or too many records'};

  type Pending={first_timestamp:string;last_timestamp:string;fragments:number;content:string;raw_lines:string[]};
  const pending:Partial<Record<'stdout'|'stderr',Pending>>={};
  const events:CriLogEvent[]=[];

  for(const line of lines){
    const match=/^(\S+) +(stdout|stderr) +([PF]) +(.*)$/.exec(line);
    if(!match||!validRfc3339Nano(match[1]!))return {ok:false,error:'Malformed CRI log record'};
    const stream=match[2] as 'stdout'|'stderr',tag=match[3]!,content=match[4]!;
    if(bytes(content)>MAX_EVENT_BYTES)return {ok:false,error:'CRI fragment exceeds parser limit'};
    const current=pending[stream];

    if(tag==='P'){
      const next=current??{first_timestamp:match[1]!,last_timestamp:match[1]!,fragments:0,content:'',raw_lines:[]};
      next.last_timestamp=match[1]!;
      next.fragments++;
      next.content+=content;
      next.raw_lines.push(line);
      if(next.fragments>MAX_FRAGMENTS||bytes(next.content)>MAX_EVENT_BYTES)
        return {ok:false,error:'CRI partial event exceeds parser limits'};
      pending[stream]=next;
      continue;
    }

    if(current){
      current.last_timestamp=match[1]!;
      current.fragments++;
      current.content+=content;
      current.raw_lines.push(line);
      if(current.fragments>MAX_FRAGMENTS||bytes(current.content)>MAX_EVENT_BYTES)
        return {ok:false,error:'CRI completed event exceeds parser limits'};
      events.push({
        stream,first_timestamp:current.first_timestamp,last_timestamp:current.last_timestamp,
        fragments:current.fragments,content:normalizePayload(current.content),raw_lines:current.raw_lines,
      });
      delete pending[stream];
    }else{
      events.push({
        stream,first_timestamp:match[1]!,last_timestamp:match[1]!,fragments:1,
        content:normalizePayload(content),raw_lines:[line],
      });
    }
  }

  if(pending.stdout||pending.stderr)return {ok:false,error:'CRI log stream ends with an incomplete partial event'};
  if(!events.length)return {ok:false,error:'CRI log stream contains no complete events'};
  return {ok:true,events};
}

function safeJson(value:unknown,depth:number,state:{nodes:number}):boolean{
  if(depth>16||++state.nodes>10000)return false;
  if(Array.isArray(value))return value.length<=2048&&value.every(item=>safeJson(item,depth+1,state));
  if(value&&typeof value==='object'){
    const entries=Object.entries(value as Record<string,unknown>);
    if(entries.length>512)return false;
    for(const [key,item] of entries){
      if(!key||bytes(key)>256||UNSAFE_KEYS.has(key)||!safeJson(item,depth+1,state))return false;
    }
  }
  if(typeof value==='string'&&bytes(value)>MAX_EVENT_BYTES)return false;
  return true;
}

export function parseDockerJsonLogStream(raw:string):DockerJsonLogStreamResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_STREAM_BYTES||!raw.endsWith('\n'))
    return {ok:false,error:'Invalid or incomplete Docker json-file stream'};
  if(raw.includes('\r'))return {ok:false,error:'Docker json-file stream must use LF record separators'};
  const lines=raw.slice(0,-1).split('\n');
  if(!lines.length||lines.length>MAX_RECORDS||lines.some(line=>line===''))
    return {ok:false,error:'Docker json-file stream contains empty or too many records'};
  const events:DockerJsonLogEvent[]=[];
  for(const line of lines){
    if(bytes(line)>MAX_EVENT_BYTES)return {ok:false,error:'Docker json-file record exceeds parser limit'};
    let parsed:unknown;
    try{parsed=JSON.parse(line);}catch{return {ok:false,error:'Docker json-file record is malformed JSON'};}
    if(!parsed||Array.isArray(parsed)||typeof parsed!=='object'||!safeJson(parsed,0,{nodes:0}))
      return {ok:false,error:'Docker json-file record exceeds bounded object limits'};
    const object=parsed as Record<string,unknown>;
    if(typeof object.log!=='string'||typeof object.stream!=='string'||typeof object.time!=='string'||
       !['stdout','stderr'].includes(object.stream)||!validRfc3339Nano(object.time))
      return {ok:false,error:'Docker json-file record is missing required fields'};
    const extra:Record<string,unknown>={};
    for(const [key,value] of Object.entries(object)){
      if(key==='log'||key==='stream'||key==='time')continue;
      extra[key]=value;
    }
    events.push({
      stream:object.stream as 'stdout'|'stderr',time:object.time,log:object.log,
      content:normalizePayload(object.log),raw:line,extra,
    });
  }
  return {ok:true,events};
}

export function looksLikeDockerJsonLogStream(raw:string):boolean{
  const firstEnd=raw.indexOf('\n');
  if(firstEnd<0)return false;
  const line=raw.slice(0,firstEnd);
  try{
    const parsed=JSON.parse(line);
    return !!parsed&&!Array.isArray(parsed)&&typeof parsed==='object'&&
      Object.prototype.hasOwnProperty.call(parsed,'log')&&
      Object.prototype.hasOwnProperty.call(parsed,'stream')&&
      Object.prototype.hasOwnProperty.call(parsed,'time');
  }catch{return false;}
}
