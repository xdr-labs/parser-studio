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
