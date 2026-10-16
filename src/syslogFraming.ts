export type SyslogFramingMode=
  'unframed'|
  'rfc6587_octet_counting'|
  'rfc6587_non_transparent_lf'|
  'rfc6587_non_transparent_crlf'|
  'rfc6587_non_transparent_nul';

export type SyslogFrameResult=
  |{ok:true;mode:SyslogFramingMode;message:string;octets?:number}
  |{ok:false;error:string};

const MAX_SYSLOG_OCTETS=8192;

function byteLength(value:string):number{
  return new TextEncoder().encode(value).byteLength;
}

export function unwrapSingleSyslogRecord(raw:string):SyslogFrameResult{
  if(!raw)return {ok:false,error:'Empty Syslog record'};

  const prefix=/^([^\s]+) (.*)$/s.exec(raw);
  if(prefix&&/^\d/.test(prefix[1]!)&&/^<\d{1,3}>/.test(prefix[2]!)){
    const token=prefix[1]!;
    if(!/^[1-9]\d*$/.test(token))
      return {ok:false,error:'Malformed RFC6587 octet count'};
    if(token.length>7)return {ok:false,error:'RFC6587 octet count is too large'};
    const octets=Number(token);
    if(!Number.isSafeInteger(octets)||octets<1||octets>MAX_SYSLOG_OCTETS)
      return {ok:false,error:'RFC6587 octet count exceeds parser limit'};
    const actual=byteLength(prefix[2]!);
    if(actual!==octets)
      return {ok:false,error:'RFC6587 octet count does not match message length'};
    return {ok:true,mode:'rfc6587_octet_counting',message:prefix[2]!,octets};
  }

  if(raw.endsWith('\r\n')){
    const message=raw.slice(0,-2);
    if(/[\r\n\0]/.test(message))return {ok:false,error:'Embedded framing delimiter'};
    return {ok:true,mode:'rfc6587_non_transparent_crlf',message};
  }
  if(raw.endsWith('\n')){
    const message=raw.slice(0,-1);
    if(/[\r\n\0]/.test(message))return {ok:false,error:'Embedded framing delimiter'};
    return {ok:true,mode:'rfc6587_non_transparent_lf',message};
  }
  if(raw.endsWith('\0')){
    const message=raw.slice(0,-1);
    if(/[\r\n\0]/.test(message))return {ok:false,error:'Embedded framing delimiter'};
    return {ok:true,mode:'rfc6587_non_transparent_nul',message};
  }

  if(/^[^\s]+ +<\d{1,3}>/.test(raw)&&/^\d/.test(raw))
    return {ok:false,error:'Malformed RFC6587 framing prefix'};

  return {ok:true,mode:'unframed',message:raw};
}

export type SyslogStreamMode='rfc6587_octet_counting_stream'|'rfc6587_non_transparent_stream';

export type SyslogStreamSplitResult=
  |{ok:true;mode:SyslogStreamMode;records:string[]}
  |{ok:false;error:string};

const MAX_SYSLOG_STREAM_OCTETS=1024*1024;
const MAX_SYSLOG_STREAM_RECORDS=1024;

function decodeUtf8(bytes:Uint8Array):string|null{
  try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{return null;}
}

function splitOctetCountingStream(raw:string):SyslogStreamSplitResult|null{
  if(!/^[1-9]\d* /.test(raw))return null;
  const bytes=new TextEncoder().encode(raw);
  const records:string[]=[];let cursor=0;
  while(cursor<bytes.length){
    const start=cursor;let digits='';
    while(cursor<bytes.length&&bytes[cursor]!>=48&&bytes[cursor]!<=57){
      if(digits.length>=7)return {ok:false,error:'RFC6587 octet count token is too long'};
      digits+=String.fromCharCode(bytes[cursor]!);cursor++;
    }
    if(!digits||bytes[cursor]!==32)return {ok:false,error:'Malformed RFC6587 octet-counted stream'};
    if(digits.length>1&&digits.startsWith('0'))return {ok:false,error:'RFC6587 octet count must not have a leading zero'};
    cursor++;
    const octets=Number(digits);
    if(!Number.isSafeInteger(octets)||octets<1||octets>MAX_SYSLOG_OCTETS)
      return {ok:false,error:'RFC6587 octet count exceeds parser limit'};
    if(cursor+octets>bytes.length)return {ok:false,error:'Truncated RFC6587 octet-counted stream'};
    const message=decodeUtf8(bytes.slice(cursor,cursor+octets));
    if(message===null||!/^<\d{1,3}>/.test(message))
      return {ok:false,error:'RFC6587 frame is not a valid UTF-8 Syslog record'};
    records.push(message);
    if(records.length>MAX_SYSLOG_STREAM_RECORDS)return {ok:false,error:'RFC6587 stream record limit exceeded'};
    cursor+=octets;
    if(cursor===start)return {ok:false,error:'RFC6587 parser made no progress'};
  }
  return records.length?{ok:true,mode:'rfc6587_octet_counting_stream',records}:
    {ok:false,error:'RFC6587 stream contains no records'};
}

function splitNonTransparentStream(raw:string):SyslogStreamSplitResult|null{
  const hasNul=raw.includes('\0');
  const hasNewline=/[\r\n]/.test(raw);
  if(!hasNul&&!hasNewline)return null;
  if(hasNul&&hasNewline)return {ok:false,error:'Mixed RFC6587 non-transparent delimiters are unsupported'};
  let records:string[];
  if(hasNul){
    if(!raw.endsWith('\0'))return {ok:false,error:'NUL-delimited Syslog stream must end at a record boundary'};
    records=raw.slice(0,-1).split('\0');
  }else{
    if(!raw.endsWith('\n'))return {ok:false,error:'Line-delimited Syslog stream must end at a record boundary'};
    const crlf=raw.endsWith('\r\n');
    const body=raw.slice(0,crlf?-2:-1);
    records=crlf?body.split('\r\n'):body.split('\n');
  }
  if(!records.length||records.some(record=>!record||/[\r\n\0]/.test(record)||!/^<\d{1,3}>/.test(record)))
    return {ok:false,error:'Malformed RFC6587 non-transparent stream record'};
  if(records.length>MAX_SYSLOG_STREAM_RECORDS)return {ok:false,error:'RFC6587 stream record limit exceeded'};
  if(records.some(record=>byteLength(record)>MAX_SYSLOG_OCTETS))
    return {ok:false,error:'RFC6587 stream record exceeds parser limit'};
  return {ok:true,mode:'rfc6587_non_transparent_stream',records};
}

export function splitSyslogStream(raw:string):SyslogStreamSplitResult{
  if(!raw)return {ok:false,error:'Empty Syslog stream'};
  if(byteLength(raw)>MAX_SYSLOG_STREAM_OCTETS)return {ok:false,error:'Syslog stream exceeds parser limit'};
  return splitOctetCountingStream(raw)??splitNonTransparentStream(raw)??
    {ok:false,error:'Input is not a supported multi-record Syslog stream'};
}
