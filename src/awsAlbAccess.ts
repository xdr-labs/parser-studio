export const ALB_ACCESS_FIELDS=[
  'type','time','elb','client_port','target_port',
  'request_processing_time','target_processing_time','response_processing_time',
  'elb_status_code','target_status_code','received_bytes','sent_bytes',
  'request_line','user_agent','ssl_cipher','ssl_protocol','target_group_arn',
  'trace_id','domain_name','chosen_cert_arn','matched_rule_priority',
  'request_creation_time','actions_executed','redirect_url','error_reason',
  'target_port_list','target_status_code_list','classification','classification_reason',
  'conn_trace_id','transformed_host','transformed_uri','request_transform_status',
  'ip_address','target_error_code','elb_error_code',
] as const;

export type AlbAccessField=typeof ALB_ACCESS_FIELDS[number];

export interface AlbAccessRecord{
  fields:Record<AlbAccessField,string>;
  extra_fields:string[];
}

interface Token{value:string;quoted:boolean;}

function splitQuoted(raw:string):Token[]|null{
  const output:Token[]=[];let token='',quoted=false,inQuote=false,escaped=false,started=false;
  for(let index=0;index<raw.length;index++){
    const ch=raw[index]!;
    if(inQuote){
      if(escaped){token+=ch;escaped=false;continue;}
      if(ch==='\\'){escaped=true;continue;}
      if(ch==='"'){inQuote=false;continue;}
      if(ch==='\r'||ch==='\n'||ch==='\0')return null;
      token+=ch;continue;
    }
    if(ch==='"'){
      if(started)return null;
      quoted=true;inQuote=true;started=true;continue;
    }
    if(ch===' '||ch==='\t'){
      if(started){output.push({value:token,quoted});token='';quoted=false;started=false;}
      continue;
    }
    if(quoted)return null;
    token+=ch;started=true;
  }
  if(inQuote||escaped)return null;
  if(started)output.push({value:token,quoted});
  return output;
}

function ipv4(value:string):boolean{
  const parts=value.split('.');
  return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)<=255);
}

function ipv6(value:string):boolean{
  if(!value.includes(':')||!/^[0-9A-Fa-f:]+$/.test(value)||value.indexOf('::')!==value.lastIndexOf('::'))return false;
  const sides=value.split('::');
  const groups=sides.flatMap(side=>side?side.split(':'):[]);
  if(groups.some(group=>!/^[0-9A-Fa-f]{1,4}$/.test(group)))return false;
  return sides.length===2?groups.length<8:groups.length===8;
}

function endpoint(value:string,allowDash:boolean):boolean{
  if(allowDash&&value==='-')return true;
  const colon=value.lastIndexOf(':');
  if(colon<=0)return false;
  const host=value.slice(0,colon),port=value.slice(colon+1);
  return (ipv4(host)||ipv6(host))&&/^\d{1,5}$/.test(port)&&Number(port)<=65535;
}

function iso(value:string):boolean{
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/.exec(value);
  if(!match)return false;
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  const hour=Number(match[4]),minute=Number(match[5]),second=Number(match[6]);
  if(year<1||year>9999||month<1||month>12||hour>23||minute>59||second>59)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  return day>=1&&day<=days[month-1]!;
}
function decimal(value:string):boolean{
  return value==='-1'||/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value);
}
function status(value:string,allowDash:boolean):boolean{
  return (allowDash&&value==='-')||/^\d{3}$/.test(value);
}
function unsigned(value:string):boolean{return /^\d+$/.test(value);}

const QUOTED_POSITIONS=new Set([12,13,17,18,19,22,23,24,25,26,27,28,30,31,32]);

export function parseAlbAccessLog(raw:string):AlbAccessRecord|null{
  if(!raw||raw.includes('\0')||/[\r\n]/.test(raw)||
     new TextEncoder().encode(raw).byteLength>32768)return null;
  const tokens=splitQuoted(raw);
  if(!tokens||tokens.length<ALB_ACCESS_FIELDS.length||tokens.length>64)return null;
  for(const index of QUOTED_POSITIONS){
    if(!tokens[index]?.quoted)return null;
  }
  if(!/^(?:http|https|h2|grpcs|ws|wss)$/.test(tokens[0]!.value))return null;
  if(!iso(tokens[1]!.value)||!/^app\/[A-Za-z0-9_.\/-]{3,255}$/.test(tokens[2]!.value))return null;
  if(!endpoint(tokens[3]!.value,false)||!endpoint(tokens[4]!.value,true))return null;
  if(!decimal(tokens[5]!.value)||!decimal(tokens[6]!.value)||!decimal(tokens[7]!.value))return null;
  if(!status(tokens[8]!.value,false)||!status(tokens[9]!.value,true))return null;
  if(!unsigned(tokens[10]!.value)||!unsigned(tokens[11]!.value))return null;

  const request=tokens[12]!.value.split(' ');
  if(request.length<3||!/^[A-Z][A-Z0-9_-]{1,15}$/.test(request[0]!)||
     !/^HTTP\/\d(?:\.\d)?$/.test(request[request.length-1]!))return null;
  if(new TextEncoder().encode(tokens[13]!.value).byteLength>8192)return null;
  if(tokens[16]!.value!=='-'&&!/^arn:aws[a-z-]*:elasticloadbalancing:[^\s]{10,}$/.test(tokens[16]!.value))return null;
  if(!iso(tokens[21]!.value))return null;
  if(!/^(?:-|-1|\d+)$/.test(tokens[20]!.value))return null;
  if(tokens[33]!.value!=='-'&&!ipv4(tokens[33]!.value)&&!ipv6(tokens[33]!.value))return null;
  for(const index of [34,35]){
    if(!/^(?:-|0x[0-9A-Fa-f]+)$/.test(tokens[index]!.value))return null;
  }
  const fields={} as Record<AlbAccessField,string>;
  ALB_ACCESS_FIELDS.forEach((field,index)=>{fields[field]=tokens[index]!.value;});
  return {fields,extra_fields:tokens.slice(ALB_ACCESS_FIELDS.length).map(token=>token.value)};
}

export function extractAlbStructural(raw:string):Record<string,unknown>|null{
  const alb=parseAlbAccessLog(raw);
  return alb?{
    aws_alb_access:alb,
    generic:{mode:'aws_alb_access',source_raw:raw},
  }:null;
}
