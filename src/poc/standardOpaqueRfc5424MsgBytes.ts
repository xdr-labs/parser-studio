import {createHash} from 'node:crypto';
import {splitRfc6587OctetStreamBytes} from '../syslogFraming';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';

/**
 * RFC5424 MSG-ANY has *OCTET content* and may be non-UTF8 without a BOM.
 * Never force opaque original bytes into a JavaScript string or claim native
 * parsing from a transport lexical match. This source observer is review-only.
 */
export type OpaqueMessageReviewDisposition=
  'REVIEW_ONLY_OPAQUE_MSG_BYTES'|'ABSTAIN_UNSAFE';
export interface OpaqueMsgOriginalClaim {
  recordIndex:number;
  recordStartByte:number;
  recordEndByte:number;
  msgStartByte:number|null;
  msgEndByte:number|null;
  encoding:'OPAQUE_MSG_ANY'|'MSG_UTF8_BOM'|'NO_MSG';
  evidence:'EXACT_ORIGINAL_OCTETS';
}
export interface OpaqueMsgReview {
  disposition:OpaqueMessageReviewDisposition;
  sourceSha256:string;
  sourceBytes:number;
  claims:OpaqueMsgOriginalClaim[];
  reason:string;
  originalDeviceIdentity:'NOT_ATTESTED';
  sourceComplete:false;
  manufacturerVerified:false;
  nativeVerified:false;
  canAutoPromote:false;
}
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
const digest=(data:Uint8Array)=>createHash('sha256').update(data).digest('hex');

/**
 * One unqualified record invalidates the entire stream's source claims:
 * otherwise complete-looking event results could hide a malformed tail.
 */
export function inspectOpaqueCountedRfc5424Source(
  received:Uint8Array,
):OpaqueMsgReview{
  const fallback:OpaqueMsgReview={
    disposition:'ABSTAIN_UNSAFE',
    sourceSha256:digest(received),
    sourceBytes:received.length,
    claims:[],reason:'OCTET_COUNTED_FRAMING_NOT_PROVEN',
    originalDeviceIdentity:'NOT_ATTESTED',
    sourceComplete:false,manufacturerVerified:false,nativeVerified:false,
    canAutoPromote:false,
  };
  const stream=splitRfc6587OctetStreamBytes(received);
  if(!stream.ok)return fallback;
  const claims:OpaqueMsgOriginalClaim[]=[];
  for(const frame of stream.frames){
    const lexical=rfc5424SdByteEscapes(frame.recordBytes);
    if(!lexical)return {...fallback,
      reason:'RFC5424_HEADER_STRUCTURED_DATA_SOURCE_UNQUALIFIED'};
    const start=lexical.messageStart;
    const msg=start===null?null:frame.recordBytes.subarray(start);
    let encoding:OpaqueMsgOriginalClaim['encoding']='NO_MSG';
    if(msg!==null){
      const withBom=msg.length>=3&&msg[0]===0xef&&
        msg[1]===0xbb&&msg[2]===0xbf;
      if(withBom){
        // A BOM commits the producer to UTF8, unlike arbitrary MSG-ANY.
        try{decoder.decode(msg.subarray(3));}
        catch{return {...fallback,reason:'RFC5424_MSG_UTF8_BOM_INVALID_BYTES'};}
        encoding='MSG_UTF8_BOM';
      }else encoding='OPAQUE_MSG_ANY';
      // No caller-visible decoded value is fabricated for MSG-ANY.
    }
    claims.push({
      recordIndex:claims.length,
      recordStartByte:frame.recordStartByte,
      recordEndByte:frame.recordEndByte,
      msgStartByte:start===null?null:frame.recordStartByte+start,
      msgEndByte:start===null?null:frame.recordEndByte,
      encoding,evidence:'EXACT_ORIGINAL_OCTETS',
    });
  }
  if(!claims.length)return fallback;
  return {...fallback,
    disposition:'REVIEW_ONLY_OPAQUE_MSG_BYTES',claims,
    reason:'COUNTED_SOURCE_BYTES_OBSERVED_NO_MANUFACTURER_OR_NATIVE_PROOF'};
}
