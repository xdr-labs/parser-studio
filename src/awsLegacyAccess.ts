import {isIpPortToken,isIpToken} from './networkTokens';

interface Token{value:string;quoted:boolean;bracketed:boolean;}

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function splitFields(raw:string):Token[]|null{
  const out:Token[]=[];let token='',quote='',bracket=false,escaped=false,started=false;
  const push=(quoted:boolean,bracketed:boolean)=>{out.push({value:token,quoted,bracketed});token='';started=false;};
  let tokenQuoted=false,tokenBracketed=false;
  for(let i=0;i<raw.length;i++){
    const ch=raw[i]!;
    if(quote){
      if(escaped){token+=ch;escaped=false;continue;}
      if(ch==='\\'){escaped=true;continue;}
      if(ch===quote){quote='';continue;}
      if(ch==='\r'||ch==='\n'||ch==='\0')return null;
      token+=ch;continue;
    }
    if(bracket){
      if(ch===']'){bracket=false;continue;}
      if(ch==='\r'||ch==='\n'||ch==='\0')return null;
      token+=ch;continue;
    }
    if(ch==='"'||ch==="'"){if(started)return null;quote=ch;tokenQuoted=true;started=true;continue;}
    if(ch==='['){if(started)return null;bracket=true;tokenBracketed=true;started=true;continue;}
    if(ch===' '||ch==='\t'){
      if(started){push(tokenQuoted,tokenBracketed);tokenQuoted=false;tokenBracketed=false;}
      continue;
    }
    if(tokenQuoted||tokenBracketed)return null;
    token+=ch;started=true;
  }
  if(quote||bracket||escaped)return null;
  if(started)push(tokenQuoted,tokenBracketed);
  return out;
}

function leap(year:number):boolean{return year%4===0&&(year%100!==0||year%400===0);}
function validCalendar(year:number,month:number,day:number):boolean{
  if(year<1||year>9999||month<1||month>12||day<1)return false;
  const days=[31,leap(year)?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1]!;
}

function isoUtc(value:string):boolean{
  const m=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/.exec(value);
  return !!m&&validCalendar(Number(m[1]),Number(m[2]),Number(m[3]))&&Number(m[4])<=23&&Number(m[5])<=59&&Number(m[6])<=59;
}

const MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'] as const;
function apacheTime(value:string):boolean{
  const m=/^(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) +([+-])(\d{2})(\d{2})$/.exec(value);
  if(!m)return false;
  const month=MONTHS.indexOf(m[2] as typeof MONTHS[number])+1;
  return month>0&&validCalendar(Number(m[3]),month,Number(m[1]))&&Number(m[4])<=23&&Number(m[5])<=59&&Number(m[6])<=59&&Number(m[8])<=23&&Number(m[9])<=59;
}

function decimal(value:string):boolean{return value==='-1'||/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value);}
function uintDash(value:string):boolean{return value==='-'||/^\d+$/.test(value);}
function statusDash(value:string):boolean{return value==='-'||/^\d{3}$/.test(value);}

export interface ClassicElbAccessRecord{fields:Record<string,string>;extra_fields:string[];}

export function parseClassicElbAccessLog(raw:string):ClassicElbAccessRecord|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>32768)return null;
  const t=splitFields(raw);if(!t||t.length<12||t.length>32)return null;
  if(t[0]!.quoted||t[1]!.quoted||!isoUtc(t[0]!.value)||!/^[A-Za-z0-9_.-]{1,255}$/.test(t[1]!.value))return null;
  if(!isIpPortToken(t[2]!.value,false)||!isIpPortToken(t[3]!.value,true))return null;
  if(!decimal(t[4]!.value)||!decimal(t[5]!.value)||!decimal(t[6]!.value))return null;
  if(!statusDash(t[7]!.value)||!statusDash(t[8]!.value)||!uintDash(t[9]!.value)||!uintDash(t[10]!.value))return null;
  if(!t[11]!.quoted)return null;
  const request=/^([A-Z][A-Z0-9_-]{1,15}) +(\S{1,8192}) +HTTP\/(\d(?:\.\d)?)$/.exec(t[11]!.value);
  if(!request)return null;
  const fields:Record<string,string>={
    timestamp:t[0]!.value,load_balancer:t[1]!.value,client_port:t[2]!.value,backend_port:t[3]!.value,
    request_processing_time:t[4]!.value,backend_processing_time:t[5]!.value,response_processing_time:t[6]!.value,
    elb_status_code:t[7]!.value,backend_status_code:t[8]!.value,received_bytes:t[9]!.value,sent_bytes:t[10]!.value,
    request_line:t[11]!.value,method:request[1]!,request_target:request[2]!,http_version:request[3]!,
  };
  if(t[12]){if(!t[12].quoted)return null;fields.user_agent=t[12].value;}
  if(t[13])fields.ssl_cipher=t[13].value;
  if(t[14])fields.ssl_protocol=t[14].value;
  return {fields,extra_fields:t.slice(15).map(x=>x.value)};
}

export interface S3AccessRecord{fields:Record<string,string>;extra_fields:string[];}

export function parseS3AccessLog(raw:string):S3AccessRecord|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||bytes(raw)>65536)return null;
  const t=splitFields(raw);if(!t||t.length<17||t.length>40)return null;
  if(!/^[A-Za-z0-9_-]{1,128}$/.test(t[0]!.value)||!/^[A-Za-z0-9][A-Za-z0-9.-]{0,255}$/.test(t[1]!.value))return null;
  if(!t[2]!.bracketed||!apacheTime(t[2]!.value))return null;
  if(!(isIpToken(t[3]!.value)||t[3]!.value==='-'))return null;
  if(!/^[^\s]{1,512}$/.test(t[4]!.value)||!/^[A-Za-z0-9-]{8,128}$/.test(t[5]!.value)||!/^[A-Z0-9.]+$/.test(t[6]!.value))return null;
  if(t[7]!.value!=='-'&&bytes(t[7]!.value)>4096)return null;
  if(!t[8]!.quoted)return null;
  const request=/^([A-Z][A-Z0-9_-]{1,15}) +(\S{1,8192}) +HTTP\/(\d(?:\.\d)?)$/.exec(t[8]!.value);
  if(!request||!/^\d{3}$/.test(t[9]!.value))return null;
  for(const index of [11,12,13,14])if(!uintDash(t[index]!.value))return null;
  if(!t[15]!.quoted||!t[16]!.quoted)return null;
  const fields:Record<string,string>={
    owner:t[0]!.value,bucket:t[1]!.value,time:t[2]!.value,remote_ip:t[3]!.value,requester:t[4]!.value,request_id:t[5]!.value,
    operation:t[6]!.value,key:t[7]!.value,request_uri:t[8]!.value,http_status:t[9]!.value,error_code:t[10]!.value,
    bytes_sent:t[11]!.value,object_size:t[12]!.value,total_time:t[13]!.value,turn_around_time:t[14]!.value,
    referrer:t[15]!.value,user_agent:t[16]!.value,method:request[1]!,request_target:request[2]!,http_version:request[3]!,
  };
  if(t[17])fields.version_id=t[17].value;
  return {fields,extra_fields:t.slice(18).map(x=>x.value)};
}

export function extractClassicElbAccess(raw:string):Record<string,unknown>|null{
  const record=parseClassicElbAccessLog(raw);
  return record?{aws_classic_elb:record,generic:{mode:'aws_classic_elb_access',source_raw:raw}}:null;
}
export function extractS3Access(raw:string):Record<string,unknown>|null{
  const record=parseS3AccessLog(raw);
  return record?{aws_s3_access:record,generic:{mode:'aws_s3_access',source_raw:raw}}:null;
}
