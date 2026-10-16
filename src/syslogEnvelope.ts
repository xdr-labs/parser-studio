export type SyslogEnvelopeVariant=
  'rfc5424'|
  'rfc3164'|
  'rfc3164_year_before_time'|
  'rfc3164_year_after_time'|
  'rfc3164_tz'|
  'rfc3164_year_before_time_tz'|
  'rfc3164_year_after_time_tz'|
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
  structuredDataElements?:Array<{id:string;params:Record<string,string|string[]>}>;
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

const BSD_NAMED_ZONES=new Set([
  'UTC','GMT','KST','JST','CET','CEST','EET','EEST',
  'PST','PDT','MST','MDT','CST','CDT','EST','EDT',
]);

function validBsdZone(value:string):boolean{
  return validZone(value)||BSD_NAMED_ZONES.has(value);
}

function validBsdTimestamp(month:string,dayText:string,time:string):boolean{
  const day=Number(dayText);
  return !!MONTH_DAYS[month]&&Number.isInteger(day)&&day>=1&&day<=MONTH_DAYS[month]!&&validClock(time);
}

function monthNumber(month:string):number{
  return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(month)+1;
}

function validBsdTimestampWithYear(
  month:string,dayText:string,yearText:string,time:string,
):boolean{
  const year=Number(yearText),monthIndex=monthNumber(month),day=Number(dayText);
  return monthIndex>=1&&validClock(time)&&validCalendarDate(year,monthIndex,day);
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

const UNSAFE_SD_NAMES=new Set(['__proto__','constructor','prototype']);

function validSdName(value:string):boolean{
  return value.length>=1&&value.length<=32&&
    /^[\x21-\x7e]+$/.test(value)&&
    !/[=\]" ]/.test(value)&&
    !UNSAFE_SD_NAMES.has(value);
}

function parseStructuredDataElements(
  raw:string,
):Array<{id:string;params:Record<string,string|string[]>}>|null{
  if(raw==='-')return [];
  if(!raw.startsWith('[')||utf8Size(raw)>8192)return null;
  const elements:Array<{id:string;params:Record<string,string|string[]>}>=[];
  const ids=new Set<string>();
  let cursor=0;
  while(cursor<raw.length){
    if(raw[cursor]!=='['||elements.length>=64)return null;
    cursor++;
    const idStart=cursor;
    while(cursor<raw.length&&raw[cursor]!==' '&&raw[cursor]!==']')cursor++;
    const id=raw.slice(idStart,cursor);
    if(!validSdName(id)||ids.has(id))return null;
    ids.add(id);
    const params:Record<string,string|string[]>=Object.create(null);
    let paramCount=0;
    while(cursor<raw.length&&raw[cursor]===' '){
      if(++paramCount>128)return null;
      cursor++;
      const nameStart=cursor;
      while(cursor<raw.length&&raw[cursor]!=='=')cursor++;
      if(cursor>=raw.length)return null;
      const name=raw.slice(nameStart,cursor);
      if(!validSdName(name)||raw.slice(cursor,cursor+2)!=='="')return null;
      cursor+=2;
      let value='',closed=false;
      while(cursor<raw.length){
        const ch=raw[cursor]!;
        if(ch==='"'){cursor++;closed=true;break;}
        if(ch==='\\'){
          const next=raw[cursor+1];
          if(next===undefined)return null;
          if(next==='"'||next==='\\'||next===']'){
            value+=next;cursor+=2;continue;
          }
          value+='\\'+next;cursor+=2;continue;
        }
        value+=ch;cursor++;
      }
      if(!closed||utf8Size(value)>2048)return null;
      const previous=params[name];
      params[name]=previous===undefined?value:
        Array.isArray(previous)?[...previous,value]:[previous,value];
    }
    if(raw[cursor]!==']')return null;
    cursor++;
    elements.push({id,params});
  }
  return elements;
}

function parseStructuredData(input:string):{
  structuredData:string;
  elements:Array<{id:string;params:Record<string,string|string[]>}>;
  message:string;
}|null{
  if(input.startsWith('-')){
    const rest=input.slice(1);
    if(rest===''||rest.startsWith(' '))return {
      structuredData:'-',elements:[],message:rest===''?'':rest.slice(1),
    };
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
  const elements=parseStructuredDataElements(structuredData);
  if(!elements)return null;
  const rest=input.slice(cursor);
  if(rest!==''&&!rest.startsWith(' '))return null;
  return {structuredData,elements,message:rest===''?'':rest.slice(1)};
}

function decorateMessage(envelope:SyslogEnvelope):SyslogEnvelope{
  const body=envelope.message;
  const tag=/^([A-Za-z0-9_.@\/-]{1,128})(?:\[(\d{1,10})\])?:[ \t]*(.*)$/.exec(body);
  if(!tag||tag[1]==='CEF'||tag[1]==='LEEF')return envelope;
  return {...envelope,appname:tag[1],...(tag[2]?{procid:tag[2]}:{}),message:tag[3]!};
}

function parseRfc5424(pri:string|undefined,rest:string):SyslogEnvelope|null{
  if(pri===undefined)return null;
  const match=/^([1-9]\d{0,2}) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +([^ ]+) +(.*)$/.exec(rest);
  if(!match)return null;
  const version=match[1]!,timestamp=match[2]!,hostname=match[3]!,appname=match[4]!,
    procid=match[5]!,msgid=match[6]!;
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
    ...(sd.elements.length?{structuredDataElements:sd.elements}:{}),
    message:sd.message,
  };
}

function withPri(pri:string|undefined):Pick<SyslogEnvelope,'pri'|'facility'|'severity'>{
  return decomposePri(pri)??{};
}

function parseBsd(pri:string|undefined,rest:string):SyslogEnvelope|null{
  const yearBeforeNamed=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{4}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +([A-Z]{2,8}) +([A-Za-z0-9][A-Za-z0-9_.-]{0,254})(?: +(.*))?$/.exec(rest);
  if(yearBeforeNamed&&BSD_NAMED_ZONES.has(yearBeforeNamed[5]!)&&
     validBsdTimestampWithYear(yearBeforeNamed[1]!,yearBeforeNamed[2]!,yearBeforeNamed[3]!,yearBeforeNamed[4]!)){
    return decorateMessage({
      variant:'rfc3164_year_before_time_tz',confidence:'strong',...withPri(pri),
      month:yearBeforeNamed[1],day:yearBeforeNamed[2],year:yearBeforeNamed[3],time:yearBeforeNamed[4],
      timezone:yearBeforeNamed[5],hostname:yearBeforeNamed[6],message:yearBeforeNamed[7]??'',
    });
  }

  const yearBeforeTz=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{4}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{2}:?\d{2}) +(\S{1,255})(?: +(.*))?$/.exec(rest);
  if(yearBeforeTz){
    if(!validBsdTimestampWithYear(yearBeforeTz[1]!,yearBeforeTz[2]!,yearBeforeTz[3]!,yearBeforeTz[4]!)||
       !validBsdZone(yearBeforeTz[5]!))return null;
    return decorateMessage({
      variant:'rfc3164_year_before_time_tz',confidence:'strong',...withPri(pri),
      month:yearBeforeTz[1],day:yearBeforeTz[2],year:yearBeforeTz[3],time:yearBeforeTz[4],
      timezone:yearBeforeTz[5],hostname:yearBeforeTz[6],message:yearBeforeTz[7]??'',
    });
  }

  const yearAfterNamed=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\d{4}) +([A-Z]{2,8}) +([A-Za-z0-9][A-Za-z0-9_.-]{0,254})(?: +(.*))?$/.exec(rest);
  if(yearAfterNamed&&BSD_NAMED_ZONES.has(yearAfterNamed[5]!)&&
     validBsdTimestampWithYear(yearAfterNamed[1]!,yearAfterNamed[2]!,yearAfterNamed[4]!,yearAfterNamed[3]!)){
    return decorateMessage({
      variant:'rfc3164_year_after_time_tz',confidence:'strong',...withPri(pri),
      month:yearAfterNamed[1],day:yearAfterNamed[2],time:yearAfterNamed[3],year:yearAfterNamed[4],
      timezone:yearAfterNamed[5],hostname:yearAfterNamed[6],message:yearAfterNamed[7]??'',
    });
  }

  const yearAfterTz=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\d{4}) +(Z|[+-]\d{2}:?\d{2}) +(\S{1,255})(?: +(.*))?$/.exec(rest);
  if(yearAfterTz){
    if(!validBsdTimestampWithYear(yearAfterTz[1]!,yearAfterTz[2]!,yearAfterTz[4]!,yearAfterTz[3]!)||
       !validBsdZone(yearAfterTz[5]!))return null;
    return decorateMessage({
      variant:'rfc3164_year_after_time_tz',confidence:'strong',...withPri(pri),
      month:yearAfterTz[1],day:yearAfterTz[2],time:yearAfterTz[3],year:yearAfterTz[4],
      timezone:yearAfterTz[5],hostname:yearAfterTz[6],message:yearAfterTz[7]??'',
    });
  }

  const classicNamed=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +([A-Z]{2,8}) +([A-Za-z0-9][A-Za-z0-9_.-]{0,254})(?: +(.*))?$/.exec(rest);
  if(classicNamed&&BSD_NAMED_ZONES.has(classicNamed[4]!)&&
     validBsdTimestamp(classicNamed[1]!,classicNamed[2]!,classicNamed[3]!)){
    return decorateMessage({
      variant:'rfc3164_tz',confidence:'strong',...withPri(pri),
      month:classicNamed[1],day:classicNamed[2],time:classicNamed[3],timezone:classicNamed[4],
      hostname:classicNamed[5],message:classicNamed[6]??'',
    });
  }

  const classicTz=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(Z|[+-]\d{2}:?\d{2}) +(\S{1,255})(?: +(.*))?$/.exec(rest);
  if(classicTz){
    if(!validBsdTimestamp(classicTz[1]!,classicTz[2]!,classicTz[3]!)||
       !validBsdZone(classicTz[4]!))return null;
    return decorateMessage({
      variant:'rfc3164_tz',confidence:'strong',...withPri(pri),
      month:classicTz[1],day:classicTz[2],time:classicTz[3],timezone:classicTz[4],
      hostname:classicTz[5],message:classicTz[6]??'',
    });
  }

  const yearBefore=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{4}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?$/.exec(rest);
  if(yearBefore){
    if(!validBsdTimestampWithYear(yearBefore[1]!,yearBefore[2]!,yearBefore[3]!,yearBefore[4]!))return null;
    return decorateMessage({
      variant:'rfc3164_year_before_time',confidence:'strong',...withPri(pri),
      month:yearBefore[1],day:yearBefore[2],year:yearBefore[3],time:yearBefore[4],
      hostname:yearBefore[5],message:yearBefore[6]??'',
    });
  }

  const yearAfter=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\d{4}) +(\S{1,255})(?: +(.*))?$/.exec(rest);
  if(yearAfter){
    if(!validBsdTimestampWithYear(yearAfter[1]!,yearAfter[2]!,yearAfter[4]!,yearAfter[3]!))return null;
    return decorateMessage({
      variant:'rfc3164_year_after_time',confidence:'strong',...withPri(pri),
      month:yearAfter[1],day:yearAfter[2],time:yearAfter[3],year:yearAfter[4],
      hostname:yearAfter[5],message:yearAfter[6]??'',
    });
  }

  const classic=/^([A-Z][a-z]{2}) +(\d{1,2}) +(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?$/.exec(rest);
  if(classic&&validBsdTimestamp(classic[1]!,classic[2]!,classic[3]!)){
    return decorateMessage({
      variant:'rfc3164',confidence:'strict',...withPri(pri),
      month:classic[1],day:classic[2],time:classic[3],hostname:classic[4],message:classic[5]??'',
    });
  }
  return null;
}

function parseRfc3339Loose(pri:string|undefined,rest:string):SyslogEnvelope|null{
  const match=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) +(\S{1,255})(?: +(.*))?$/.exec(rest);
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
    '(?: +(Z|[+-]\\d{2}:?\\d{2}))? +(\\S{1,255})(?: +(.*))?$'
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
  const match=/^(\d{4}):(\d{2}):(\d{2})-(\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +(\S{1,255})(?: +(.*))?$/.exec(rest);
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
  if(split.pri!==undefined&&/^\d{1,3} +/.test(rest))return null;

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
  if(envelope.structuredDataElements?.length){
    fields.structured_data=Object.fromEntries(
      envelope.structuredDataElements.map(element=>[element.id,element.params])
    );
  }
  return fields;
}
