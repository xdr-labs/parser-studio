import {utf8OriginalByteOffsets} from './utf8OriginalByteOffsets';

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
  if(!utf8OriginalByteOffsets(raw))
    return {ok:false,error:'Unpaired source surrogate cannot be silently replaced'};

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

/** Exact RFC6587 octet-counted byte boundaries before any UTF-8 decoding.
 * MSG-ANY may contain arbitrary octets; no source code units are fabricated.
 */
export interface Rfc6587OctetSourceFrame {
  recordStartByte:number;
  recordEndByte:number;
  recordBytes:Uint8Array;
}
export type Rfc6587OctetByteStream=
  |{ok:true;frames:Rfc6587OctetSourceFrame[]}
  |{ok:false;error:string};

export function splitRfc6587OctetStreamBytes(raw:Uint8Array):
  Rfc6587OctetByteStream{
  if(raw.length===0||raw.length>MAX_SYSLOG_STREAM_OCTETS)
    return {ok:false,error:'Empty or oversized RFC6587 source byte stream'};
  const frames:Rfc6587OctetSourceFrame[]=[];
  let cursor=0;
  while(cursor<raw.length){
    const first=raw[cursor];
    if(first===undefined||first<49||first>57)
      return {ok:false,error:'RFC6587 nonzero decimal count required'};
    let digitCount=0,octets=0;
    while(cursor<raw.length&&raw[cursor]!>=48&&raw[cursor]!<=57){
      if(++digitCount>7)return {ok:false,error:'RFC6587 count token too long'};
      octets=octets*10+raw[cursor]!-48;
      cursor++;
    }
    if(raw[cursor]!==32)
      return {ok:false,error:'Malformed RFC6587 octet-counted stream'};
    cursor++;
    if(octets<1||octets>MAX_SYSLOG_OCTETS)
      return {ok:false,error:'RFC6587 octet count exceeds parser limit'};
    if(cursor+octets>raw.length)
      return {ok:false,error:'Truncated RFC6587 octet-counted stream'};
    const recordStartByte=cursor;
    const recordEndByte=cursor+octets;
    const frame=raw.subarray(recordStartByte,recordEndByte);
    // Retain previous strong transport-family recognition: full Syslog
    // HEADER/SD qualification is performed by the next source stage.
    if(frame[0]!==60)return {ok:false,error:'RFC6587 frame has no PRI'};
    let at=1,priDigits=0;
    while(at<frame.length&&frame[at]!>=48&&frame[at]!<=57){
      if(++priDigits>3)return {ok:false,error:'RFC6587 invalid PRI syntax'};
      at++;
    }
    if(priDigits===0||frame[at]!==62)
      return {ok:false,error:'RFC6587 frame is not a Syslog record'};
    frames.push({recordStartByte,recordEndByte,
      recordBytes:Uint8Array.from(frame)});
    if(frames.length>MAX_SYSLOG_STREAM_RECORDS)
      return {ok:false,error:'RFC6587 stream record limit exceeded'};
    cursor=recordEndByte;
  }
  return frames.length?{ok:true,frames}:
    {ok:false,error:'RFC6587 source stream contains no records'};
}

function splitOctetCountingStream(raw:string):SyslogStreamSplitResult|null{
  if(!/^[1-9]\d* /.test(raw))return null;
  const split=splitRfc6587OctetStreamBytes(new TextEncoder().encode(raw));
  if(!split.ok)return {ok:false,error:split.error};
  const records:string[]=[];
  for(const source of split.frames){
    const decoded=decodeUtf8(source.recordBytes);
    if(decoded===null)
      return {ok:false,error:'RFC6587 stream source is not valid UTF-8'};
    records.push(decoded);
  }
  return {ok:true,mode:'rfc6587_octet_counting_stream',records};
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
  if(utf8OriginalByteOffsets(raw)===null)
    return {ok:false,error:'Source stream contains an unpaired UTF-16 surrogate'};
  if(byteLength(raw)>MAX_SYSLOG_STREAM_OCTETS)return {ok:false,error:'Syslog stream exceeds parser limit'};
  return splitOctetCountingStream(raw)??splitNonTransparentStream(raw)??
    {ok:false,error:'Input is not a supported multi-record Syslog stream'};
}
