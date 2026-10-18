import {createHash} from 'node:crypto';

/**
 * Isolated stage-to-stage byte review; never a producer identity, TLS peer,
 * original-field, complete-record, or native-target certificate.
 *
 * The optional upstream pair may be a reporter's displayed text rather than
 * a packet capture. SHA-256 pins the supplied bytes, not who sent them.
 * Byte-only comparison preserves opaque RFC5424 MSG-ANY and invalid UTF-8
 * without interpreting or replacing their octets.
 */
export interface RelayStageBytePair {
  collectorBytes:Uint8Array;
  collectorSha256:string;
  upstreamBytes?:Uint8Array;
  upstreamSha256?:string;
}
export type RelayPairByteDisposition=
  'ABSTAIN_UNSAFE_OR_UNPINNED_BYTES'|
  'REVIEW_ONLY_NO_UPSTREAM_PAIR'|
  'REVIEW_ONLY_EQUAL_BYTES'|
  'REVIEW_ONLY_COLLECTOR_STRICT_PREFIX'|
  'REVIEW_ONLY_COLLECTOR_APPEND_ONLY'|
  'REVIEW_ONLY_NON_PREFIX_CHANGE';
export interface OriginalStageByteSpan {
  startByte:number;
  endByte:number;
}
export interface RelayPairByteFidelityReview {
  disposition:RelayPairByteDisposition;
  upstreamBytes:number|null;
  collectorBytes:number;
  commonPrefixBytes:number|null;
  firstDifferenceByte:number|null;
  lostUpstreamTail:OriginalStageByteSpan|null;
  addedCollectorTail:OriginalStageByteSpan|null;
  originalDeviceIdentity:'NOT_ATTESTED';
  transportPeerAuthentication:'NOT_VERIFIED';
  eventClockOrdering:'UNSCORABLE';
  sourceComplete:false;
  nativeVerified:false;
  canAutoPromote:false;
}

const MAX_STAGE_BYTES=1024*1024;
const SHA256_HEX=/^[0-9a-f]{64}$/;
function bounded(bytes:Uint8Array|undefined):bytes is Uint8Array{
  return bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=MAX_STAGE_BYTES;
}
function sha256(bytes:Uint8Array):string{
  return createHash('sha256').update(bytes).digest('hex');
}
function pinned(bytes:Uint8Array,expected:string|undefined):boolean{
  return typeof expected==='string'&&SHA256_HEX.test(expected)&&
    sha256(bytes)===expected;
}

export function reviewPairedRelaySourceBytes(
  pair:RelayStageBytePair,
):RelayPairByteFidelityReview{
  const upstreamLength=pair.upstreamBytes instanceof Uint8Array?
    pair.upstreamBytes.length:null;
  const collectorLength=pair.collectorBytes instanceof Uint8Array?
    pair.collectorBytes.length:0;
  const base:RelayPairByteFidelityReview={
    disposition:'ABSTAIN_UNSAFE_OR_UNPINNED_BYTES',
    upstreamBytes:upstreamLength,collectorBytes:collectorLength,
    commonPrefixBytes:null,firstDifferenceByte:null,
    lostUpstreamTail:null,addedCollectorTail:null,
    originalDeviceIdentity:'NOT_ATTESTED',
    transportPeerAuthentication:'NOT_VERIFIED',
    eventClockOrdering:'UNSCORABLE',
    sourceComplete:false,nativeVerified:false,canAutoPromote:false,
  };
  // A claimed capture must always be matched to the exact pinned octets.
  if(!bounded(pair.collectorBytes)||
    !pinned(pair.collectorBytes,pair.collectorSha256))
    return base;
  if(pair.upstreamBytes===undefined&&pair.upstreamSha256===undefined)
    return {...base,disposition:'REVIEW_ONLY_NO_UPSTREAM_PAIR'};
  if(!bounded(pair.upstreamBytes)||
    !pinned(pair.upstreamBytes,pair.upstreamSha256))return base;

  // Do not call text decoders or infer framing/field ownership from contents.
  // The common prefix is the only safely replayable *stage-local* interval.
  let prefix=0;
  const minimum=Math.min(pair.upstreamBytes.length,pair.collectorBytes.length);
  while(prefix<minimum&&
    pair.upstreamBytes[prefix]===pair.collectorBytes[prefix])prefix++;
  const sameLength=pair.upstreamBytes.length===pair.collectorBytes.length;
  const same=sameLength&&prefix===minimum;
  const upstreamPrefix=prefix===pair.collectorBytes.length&&!same;
  const collectorAppend=prefix===pair.upstreamBytes.length&&!same;
  const disposition:RelayPairByteDisposition=same?'REVIEW_ONLY_EQUAL_BYTES':
    upstreamPrefix?'REVIEW_ONLY_COLLECTOR_STRICT_PREFIX':
      collectorAppend?'REVIEW_ONLY_COLLECTOR_APPEND_ONLY':
        'REVIEW_ONLY_NON_PREFIX_CHANGE';
  return {
    ...base,disposition,commonPrefixBytes:prefix,
    firstDifferenceByte:same?null:prefix,
    lostUpstreamTail:upstreamPrefix?{
      startByte:pair.collectorBytes.length,endByte:pair.upstreamBytes.length,
    }:null,
    addedCollectorTail:collectorAppend?{
      startByte:pair.upstreamBytes.length,endByte:pair.collectorBytes.length,
    }:null,
  };
}
