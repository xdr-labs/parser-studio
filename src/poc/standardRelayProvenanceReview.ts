import {parseSyslogEnvelope,type SyslogEnvelope} from '../syslogEnvelope';

/**
 * Generic, bounded source-vs-relay evidence inspection. RFC5424 HOSTNAME and
 * TIMESTAMP are emitter-controlled message header claims. RFC5425 TLS peer
 * authentication applies to the transport hop, not necessarily the originator.
 * Even exact paired byte equality cannot authenticate the physical device.
 * This audit NEVER upgrades source/native success.
 */
export type RelayProvenanceDisposition=
  'ABSTAIN_UNSAFE_SOURCE'|'REVIEW_ONLY_NOT_NESTED'|
  'REVIEW_ONLY_UNPAIRED'|'REVIEW_ONLY_SOURCE_BYTES_DIFFER'|
  'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH';
export interface RelayHeaderClaim {
  variant:SyslogEnvelope['variant'];
  hostname:string|null;
  rawTimestamp:string|null;
  timestampContext:'ZONED_OR_DECLARED'|'YEAR_OR_ZONE_MISSING'|'NO_TIMESTAMP';
}
export interface RelayByteSpan {
  startByte:number;
  endByte:number;
}
export interface RelayProvenanceReview {
  disposition:RelayProvenanceDisposition;
  receiverBytes:number;
  outer:RelayHeaderClaim|null;
  inner:RelayHeaderClaim|null;
  innerSource:RelayByteSpan|null;
  byteEqualToUpstream:boolean|null;
  originalDeviceIdentity:'NOT_ATTESTED';
  transportPeerAuthentication:'NOT_VERIFIED';
  eventClockOrdering:'UNSCORABLE';
  sourceComplete:false;
  nativeVerified:false;
  canAutoPromote:false;
}
const MAX_WIRE_BYTES=8192;
const textDecoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
const textEncoder=new TextEncoder();

function validString(bytes:Uint8Array):string|null{
  if(bytes.byteLength===0||bytes.byteLength>MAX_WIRE_BYTES)return null;
  try{
    const raw=textDecoder.decode(bytes);
    if(textEncoder.encode(raw).length!==bytes.length)return null;
    return raw;
  }catch{return null;}
}
function claim(envelope:SyslogEnvelope):RelayHeaderClaim{
  const rawTimestamp=envelope.timestamp??(
    envelope.month&&envelope.day&&envelope.time?
      [envelope.month,envelope.day,
        ...(envelope.year?[envelope.year]:[]),envelope.time,
        ...(envelope.timezone?[envelope.timezone]:[])].join(' '):null);
  return {
    variant:envelope.variant,
    hostname:envelope.hostname??null,
    rawTimestamp,
    timestampContext:rawTimestamp===null?'NO_TIMESTAMP':
      envelope.variant.startsWith('rfc3164')&&!envelope.year?
        'YEAR_OR_ZONE_MISSING':envelope.variant==='rfc3339_loose'&&
          !/[+-]\d{2}:?\d{2}$|Z$/.test(rawTimestamp)?
          'YEAR_OR_ZONE_MISSING':'ZONED_OR_DECLARED',
  };
}
function equalBytes(a:Uint8Array,b:Uint8Array):boolean{
  if(a.length!==b.length)return false;
  for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;
  return true;
}

/**
 * No transport auth, capture provenance, or upstream manufacturer correctness
 * can be proved from an arbitrary caller-provided capture string alone.
 * Receives exactly one collector-visible syslog record after transport framing.
 */
export function reviewNestedSyslogProvenance(
  receiverBytes:Uint8Array,
  upstreamBytes?:Uint8Array,
):RelayProvenanceReview{
  const base:RelayProvenanceReview={
    disposition:'ABSTAIN_UNSAFE_SOURCE',receiverBytes:receiverBytes.length,
    outer:null,inner:null,innerSource:null,byteEqualToUpstream:null,
    originalDeviceIdentity:'NOT_ATTESTED',
    transportPeerAuthentication:'NOT_VERIFIED',
    eventClockOrdering:'UNSCORABLE',
    sourceComplete:false,nativeVerified:false,canAutoPromote:false,
  };
  const raw=validString(receiverBytes);
  const upstream=upstreamBytes===undefined?null:validString(upstreamBytes);
  if(raw===null||(upstreamBytes!==undefined&&upstream===null))return base;
  const outer=parseSyslogEnvelope(raw);
  if(!outer||outer.confidence==='partial')return base;
  const outerClaim=claim(outer);
  // One hop only: unframed source without a full nested Syslog message does
  // not prove what originally traveled across any earlier collector hop.
  if(!outer.message.startsWith('<'))
    return {...base,disposition:'REVIEW_ONLY_NOT_NESTED',outer:outerClaim};
  const innerRaw=outer.message;
  const inner=parseSyslogEnvelope(innerRaw);
  if(!inner||inner.confidence==='partial'||inner.message.startsWith('<'))
    return base;
  const suffix=textEncoder.encode(innerRaw);
  if(suffix.length>receiverBytes.length)return base;
  const startByte=receiverBytes.length-suffix.length;
  if(!equalBytes(receiverBytes.subarray(startByte),suffix))return base;
  const observations={
    outer:outerClaim,inner:claim(inner),
    innerSource:{startByte,endByte:receiverBytes.length},
  };
  if(upstreamBytes===undefined)
    return {...base,...observations,disposition:'REVIEW_ONLY_UNPAIRED'};
  if(!equalBytes(suffix,upstreamBytes))
    return {...base,...observations,byteEqualToUpstream:false,
      disposition:'REVIEW_ONLY_SOURCE_BYTES_DIFFER'};
  return {...base,...observations,byteEqualToUpstream:true,
    disposition:'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH'};
}
