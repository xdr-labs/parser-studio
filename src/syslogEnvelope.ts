import { isSupportedRfc5424Version } from './grammar/syslogHeader';

export type SyslogEnvelopeVariant=
  'rfc5424'|
  'rfc3164'|
  'rfc3164_year_before_time'|
  'rfc3164_year_after_time'|
  'rfc3339_loose'|
  'iso_space'|
  'slash_date'|
  'colon_date'|
  'pri_only';

export interface SyslogEnvelope{
  variant:SyslogEnvelopeVariant;
  confidence:'strict'|'strong'|'partial';
  pri?:string;
  facility?:number;
  severity?:number;
  version?:string;
  timestamp?:string;
  month?:string;
  day?:string;
  year?:string;
  time?:string;
  timezone?:string;
  hostname?:string;
  appname?:string;
  procid?:string;
  msgid?:string;
  structuredData?:string;
  message:string;
}

const MONTH_DAYS:Record<string,number>={
  Jan:31,Feb:29,Mar:31,Apr:30,May:31,Jun:30,
  Jul:31,Aug:31,Sep:30,Oct:31,Nov:30,Dec:31,
};

function utf8Size(value:string):number{
  return new TextEncoder().encode(value).byteLength;
}

function leapYear(year:number):boolean{
  return year%4===0&&(year%100!==0||year%400===0);
}

function validCalendarDate(year:number,month:number,day:number):boolean{
  if(!Number.isInteger(year)||year<1||year>9999||
     !Number.isInteger(month)||month<1||month>12||
     !Number.isInteger(day)||day<1)return false;
  const days=[31,leapYear(year)?29:28,31,30,31,30,31,31,30,31,30,31];
  return day<=days[month-1]!;
}

function validClock(value:string):boolean{
  const match=/^(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?$/.exec(value);
  if(!match)return false;
  return Number(match[1])<=23&&Number(match[2])<=59&&Number(match[3])<=59;
}

function validZone(value:string):boolean{
  if(value==='Z')return true;
  const match=/^([+-])(\d{2}):?(\d{2})$/.exec(value);
  return !!match&&Number(match[2])<=23&&Number(match[3])<=59;
}

function validBsdTimestamp(month:string,dayText:string,time:string):boolean{
  const day=Number(dayText);
  return !!MONTH_DAYS[month]&&Number.isInteger(day)&&day>=1&&day<=MONTH_DAYS[month]!&&validClock(time);
}

function validIsoTimestamp(value:string,requireZone:boolean):boolean{
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(Z|[+-]\d{2}:?\d{2})?$/.exec(value);
  if(!match)return false;
  if(requireZone&&!match[5])return false;
  return validCalendarDate(Number(match[1]),Number(match[2]),Number(match[3]))&&
    validClock(match[4]!)&&(!match[5]||validZone(match[5]));
}

function decomposePri(priText:string|undefined):Pick<SyslogEnvelope,'pri'|'facility'|'severity'>|null{
  if(priText===undefined)return {};
  if(!/^\d{1,3}$/.test(priText))return null;
  const pri=Number(priText);
  if(!Number.isInteger(pri)||pri<0||pri>191)return null;
  return {pri:priText,facility:Math.floor(pri/8),severity:pri%8};
}

function splitPri(raw:string):{pri?:string;rest:string}|null{
  const match=/^<(\d{1,3})>/.exec(raw);
  if(!match)return {rest:raw};
  const decoded=decomposePri(match[1]);
  if(!decoded)return null;
  return {pri:match[1],rest:raw.slice(match[0].length)};
}

function fieldTokenValid(value:string,max:number):boolean{
  return value==='-'||(
    value.length>=1&&value.length<=max&&
    /^[\x21-\x7e]+$/.test(value)
  );
}

function parseStructuredData(input:string):{structuredData:string;message:string}|null{
  if(input.startsWith('-')){
    const rest=input.slice(1);
    if(rest===''||rest.startsWith(' '))return {structuredData:'-',message:rest.trimStart()};
    return null;
  }
  if(!input.startsWith('['))return null;
  let cursor=0;
  while(cursor<input.length&&input[cursor]==='['){
    let quoted=false,escaped=false,closed=false;
    cursor++;
    while(cursor<input.length){
      const ch=input[cursor]!;
      if(escaped){escaped=false;cursor++;continue;}
      if(ch==='\\'&&quoted){escaped=true;cursor++;continue;}
      if(ch==='"'){quoted=!quoted;cursor++;continue;}
      if(ch===']'&&!quoted){cursor++;closed=true;break;}
      if(ch==='\r'||ch==='\n')return null;
      cursor++;
    }
    if(!closed||quoted||escaped)return null;
  }
  const structuredData=input.slice(0,cursor);
  const rest=input.slice(cursor);
  if(rest!==''&&!rest.startsWith(' '))return null;
  return {structuredData,message:rest.trimStart()};
}

// Every expression below that captures the message with '.' carries the dotAll flag: the input never
// contains CR or LF (parseSyslogEnvelope rejects them), and without the flag '.' would stop at U+2028,
// which the Ruby export (/m) reads as ordinary message text.
function decorateMessage(envelope:SyslogEnvelope):SyslogEnvelope{
  const body=envelope.message;
  const tag=/^([A-Za-z0-9_.@\/-]{1,128})(?:\[(\d{1,10})\])?:[ \t]*(.*)$/s.exec(body);
  if(!tag||tag[1]==='CEF'||tag[1]==='LEEF')return envelope;
  return {...envelope,appname:tag[1],...(tag[2]?{procid:tag[2]}:{}),message:tag[3]!};
}

function parseRfc5424(pri:string|undefined,rest:string):SyslogEnvelope|null{
  if(pri===undefined)return null;
  const match=/^([1-9]\d{0,2}) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +(.*)$/s.exec(rest);
  if(!match)return null;
  const version=match[1]!,timestamp=match[2]!,hostname=match[3]!,appname=match[4]!,
    procid=match[5]!,msgid=match[6]!;
  // One VERSION policy for every consumer (contracts/syslog-header-grammar.v1.json):
  // an RFC 5424 shaped header with an unsupported VERSION is not an RFC 5424 envelope.
  if(!isSupportedRfc5424Version(version))return null;
  if(!(timestamp==='-'||validIsoTimestamp(timestamp,true))||
     !fieldTokenValid(hostname,255)||!fieldTokenValid(appname,48)||
     !fieldTokenValid(procid,128)||!fieldTokenValid(msgid,32))return null;
  const sd=parseStructuredData(match[7]!);
  if(!sd)return null;
  const priParts=decomposePri(pri);
  if(!priParts)return null;
  return {
    variant:'rfc5424',confidence:'strict',...priParts,version,
    ...(timestamp!=='-'?{timestamp}:{}),
    ...(hostname!=='-'?{hostname}:{}),
    ...(appname!=='-'?{appname}:{}),
    ...(procid!=='-'?{procid}:{}),
    ...(msgid!=='-'?{msgid}:{}),
    structuredData:sd.structuredData,
    message:sd.message,
  };
}

function withPri(pri:string|undefined):Pick<SyslogEnvelope,'pri'|'facility'|'severity'>{
  return decomposePri(pri)??{};
}

function parseBsd(pri:string|undefined,rest:string):SyslogEnvelope|null{
  const yearBefore=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{4}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?$/s.exec(rest);
  if(yearBefore&&validBsdTimestamp(yearBefore[1]!,yearBefore[2]!,yearBefore[4]!)&&
     Number(yearBefore[3])>=1900&&Number(yearBefore[3])<=9999){
    return decorateMessage({
      variant:'rfc3164_year_before_time',confidence:'strong',...withPri(pri),
      month:yearBefore[1],day:yearBefore[2],year:yearBefore[3],time:yearBefore[4],
      hostname:yearBefore[5],message:yearBefore[6]??'',
    });
  }

  const yearAfter=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\d{4}) +(\S{1,255})(?: +(.*))?$/s.exec(rest);
  if(yearAfter&&validBsdTimestamp(yearAfter[1]!,yearAfter[2]!,yearAfter[3]!)&&
     Number(yearAfter[4])>=1900&&Number(yearAfter[4])<=9999){
    return decorateMessage({
      variant:'rfc3164_year_after_time',confidence:'strong',...withPri(pri),
      month:yearAfter[1],day:yearAfter[2],time:yearAfter[3],year:yearAfter[4],
      hostname:yearAfter[5],message:yearAfter[6]??'',
    });
  }

  const classic=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?$/s.exec(rest);
  if(classic&&validBsdTimestamp(classic[1]!,classic[2]!,classic[3]!)){
    return decorateMessage({
      variant:'rfc3164',confidence:'strict',...withPri(pri),
      month:classic[1],day:classic[2],time:classic[3],hostname:classic[4],message:classic[5]??'',
    });
  }
  return null;
}

function parseRfc3339Loose(pri:string|undefined,rest:string):SyslogEnvelope|null{
  const match=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) +(\S{1,255})(?: +(.*))?$/s.exec(rest);
  if(!match||!validIsoTimestamp(match[1]!,false))return null;
  return decorateMessage({
    variant:'rfc3339_loose',confidence:'strong',...withPri(pri),
    timestamp:match[1],hostname:match[2],message:match[3]??'',
  });
}

function parseSeparatedDate(pri:string|undefined,rest:string,slash:boolean):SyslogEnvelope|null{
  const datePattern=slash?'(\\d{4})\\/(\\d{2})\\/(\\d{2})':'(\\d{4})-(\\d{2})-(\\d{2})';
  const match=new RegExp(
    '^'+datePattern+' +(\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?)'+
    '(?: +(Z|[+-]\\d{2}:?\\d{2}))? +(\\S{1,255})(?: +(.*))?$','s'
  ).exec(rest);
  if(!match)return null;
  const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]);
  const time=match[4]!,zone=match[5];
  if(!validCalendarDate(year,month,day)||!validClock(time)||(zone&&!validZone(zone)))return null;
  return decorateMessage({
    variant:slash?'slash_date':'iso_space',confidence:'strong',...withPri(pri),
    year:match[1],timestamp:(slash?`${match[1]}/${match[2]}/${match[3]}`:`${match[1]}-${match[2]}-${match[3]}`)+' '+time,
    time,...(zone?{timezone:zone}:{}),hostname:match[6],message:match[7]??'',
  });
}

function parseColonDate(pri:string|undefined,rest:string):SyslogEnvelope|null{
  const match=/^(\d{4}):(\d{2}):(\d{2})-(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?$/s.exec(rest);
  if(!match||!validCalendarDate(Number(match[1]),Number(match[2]),Number(match[3]))||!validClock(match[4]!))return null;
  return decorateMessage({
    variant:'colon_date',confidence:'strong',...withPri(pri),
    year:match[1],timestamp:`${match[1]}:${match[2]}:${match[3]}-${match[4]}`,
    time:match[4],hostname:match[5],message:match[6]??'',
  });
}

function looksLikeMalformedTimestamp(rest:string):boolean{
  return /^[A-Z][a-z]{2} +\d{1,2} +/.test(rest)||
    /^\d{4}[-/:]\d{2}[-/:]\d{2}/.test(rest)||
    /^\d{1,3} +\d{4}-\d{2}-\d{2}T/.test(rest);
}

export function parseSyslogEnvelope(raw:string):SyslogEnvelope|null{
  if(!raw||raw.includes('\0')||utf8Size(raw)>8192||/[\r\n]/.test(raw))return null;
  const split=splitPri(raw);
  if(!split)return null;
  const rest=split.rest.trimStart();
  if(!rest)return null;

  const rfc5424=parseRfc5424(split.pri,rest);
  if(rfc5424)return rfc5424;

  const bsd=parseBsd(split.pri,rest);
  if(bsd)return bsd;

  const rfc3339=parseRfc3339Loose(split.pri,rest);
  if(rfc3339)return rfc3339;

  const iso=parseSeparatedDate(split.pri,rest,false);
  if(iso)return iso;

  const slash=parseSeparatedDate(split.pri,rest,true);
  if(slash)return slash;

  const colon=parseColonDate(split.pri,rest);
  if(colon)return colon;

  if(split.pri!==undefined&&!looksLikeMalformedTimestamp(rest)){
    return {variant:'pri_only',confidence:'partial',...withPri(split.pri),message:rest};
  }
  return null;
}

export function envelopeToSyslogFields(envelope:SyslogEnvelope):Record<string,unknown>{
  const fields:Record<string,unknown>={
    variant:envelope.variant,
    confidence:envelope.confidence,
  };
  for(const key of [
    'pri','facility','severity','version','timestamp','month','day','year','time','timezone',
    'hostname','appname','procid','msgid','structuredData',
  ] as const){
    const value=envelope[key];
    if(value!==undefined)fields[key]=value;
  }
  return fields;
}
