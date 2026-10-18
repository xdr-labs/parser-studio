import {splitSyslogStream} from '../syslogFraming';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {parseSyslogEnvelope} from '../syslogEnvelope';
import {utf8OriginalByteOffsets} from '../utf8OriginalByteOffsets';

/**
 * Independent source-only RFC6587/RFC5424 observation.
 *
 * RFC5424 §6.4 permits control octets in MSG; RFC6587 §3.4.1 octet counting
 * proves physical record boundaries. Never infer such proof for clipboard or
 * non-transparent LF/CRLF transport, where an embedded newline is ambiguous.
 * Native/producer semantics remain unverified.
 */
export type CountedSourceDisposition=
  'REVIEW_ONLY_COUNTED_MSG_SOURCE'|'ABSTAIN_UNSAFE';
export interface CountedRfc5424MsgClaim{
  recordIndex:number;
  recordRaw:string;
  recordStartByte:number;
  recordEndByte:number;
  msg:string|null;
  msgStartByte:number|null;
  msgEndByte:number|null;
  messageEncoding:'MSG_ANY'|'MSG_UTF8_BOM'|'NO_MSG';
  sourceGrammar:'RFC5424_HEADER_SD_MSG_LEXICAL';
}
export interface CountedRfc5424MsgReview{
  disposition:CountedSourceDisposition;
  raw:string;
  sourceBytes:number;
  claims:CountedRfc5424MsgClaim[];
  reason:string;
  sourceComplete:false;
  manufacturerVerified:false;
  nativeVerified:false;
  canAutoPromote:false;
}
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});

/**
 * A lexical match on two parsers is not a certification of source semantics.
 * A malformed record invalidates all claims for this stream (no partial success).
 */
export function inspectCountedRfc5424MsgStream(
  raw:string,
):CountedRfc5424MsgReview{
  const sourceBytes=encoder.encode(raw).length;
  const fallback:CountedRfc5424MsgReview={
    disposition:'ABSTAIN_UNSAFE',raw,sourceBytes,claims:[],
    reason:'RFC5424_MSG_COUNTED_FRAMING_NOT_PROVEN',
    sourceComplete:false,manufacturerVerified:false,nativeVerified:false,
    canAutoPromote:false,
  };
  if(utf8OriginalByteOffsets(raw)===null)return {
    ...fallback,reason:'UTF8_SOURCE_CODE_UNITS_NOT_WELL_FORMED',
  };
  const framed=splitSyslogStream(raw);
  if(!framed.ok||framed.mode!=='rfc6587_octet_counting_stream')
    return fallback;
  const wire=encoder.encode(raw);
  let cursor=0;
  const claims:CountedRfc5424MsgClaim[]=[];
  for(const record of framed.records){
    const bytes=encoder.encode(record);
    const prefix=encoder.encode(String(bytes.length)+' ');
    const recordStartByte=cursor+prefix.length;
    const recordEndByte=recordStartByte+bytes.length;
    if(recordEndByte>wire.length)return {...fallback,
      reason:'COUNTED_RECORD_BYTES_OUTSIDE_SOURCE'};
    for(let i=0;i<prefix.length;i++){
      if(wire[cursor+i]!==prefix[i])return {...fallback,
        reason:'COUNTED_RECORD_ORIGINAL_PREFIX_MISMATCH'};
    }
    for(let i=0;i<bytes.length;i++){
      if(wire[recordStartByte+i]!==bytes[i])return {...fallback,
        reason:'COUNTED_RECORD_ORIGINAL_BYTES_MISMATCH'};
    }

    const browser=parseRfc5424Subset(record,
      {framing:'RFC6587_OCTET_COUNTING'});
    const source=parseSyslogEnvelope(record,
      {framing:'RFC6587_OCTET_COUNTING'});
    if(!browser.ok||source?.variant!=='rfc5424'||
       source.message!==(browser.ok?(browser.message??''):null))
      return {...fallback,reason:'RFC5424_COUNTED_SOURCE_GRAMMAR_UNQUALIFIED'};
    const msg=browser.message;
    let msgStartByte:number|null=null,msgEndByte:number|null=null;
    if(msg!==null){
      const msgBytes=encoder.encode(msg);
      msgStartByte=recordEndByte-msgBytes.length;
      msgEndByte=recordEndByte;
      if(msgStartByte<=recordStartByte||wire[msgStartByte-1]!==32)
        return {...fallback,reason:'RFC5424_MSG_SOURCE_BOUNDARY_CONFLICT'};
      if(decoder.decode(wire.subarray(msgStartByte,msgEndByte))!==msg)
        return {...fallback,reason:'RFC5424_MSG_SOURCE_UTF8_REPLAY_FAILED'};
    }
    claims.push({
      recordIndex:claims.length,recordRaw:record,recordStartByte,recordEndByte,
      msg,msgStartByte,msgEndByte,
      messageEncoding:msg===null?'NO_MSG':msg.charCodeAt(0)===0xfeff?
        'MSG_UTF8_BOM':'MSG_ANY',
      sourceGrammar:'RFC5424_HEADER_SD_MSG_LEXICAL',
    });
    cursor=recordEndByte;
  }
  if(cursor!==wire.length||claims.length===0)
    return {...fallback,reason:'RFC5424_COUNTED_SOURCE_BYTES_UNACCOUNTED'};
  return {...fallback,disposition:'REVIEW_ONLY_COUNTED_MSG_SOURCE',
    claims,reason:'LEXICAL_FRAMING_AND_MSG_BYTES_ONLY_NOT_SOURCE_CERTIFIED'};
}
