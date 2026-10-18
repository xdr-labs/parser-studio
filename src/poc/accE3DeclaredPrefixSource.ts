import {createHash} from 'node:crypto';
import {scanKeyValues} from './losslessLexer';
import {replayCandidate} from './grammarFunnel';

/**
 * Bounded and explicit *source* prefix annotation.
 *
 * No automatic Syslog origin/relay identification, undocumented vendor escape
 * decoding, native target confirmation, or success promotion. This observer
 * never changes the default generic or product parser's fallback selection.
 */
export interface DeclaredPrefixSourceInput {
  sourceBytes:Uint8Array;
  sourceSha256:string;
  recordFraming:string;
  declaredBodyFormat:string;
  declaredPrefixEndByte:number;
  pinnedPrefixSha256:string;
}
export type DeclaredPrefixDisposition=
  'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY_DECLARED_PREFIX';
export interface DeclaredPrefixSourceField {
  name:string;
  occurrence:number;
  sourceValueLexeme:string;
  decodedSourceValue:string;
  nameStartByte:number;
  nameEndByte:number;
  valueStartByte:number;
  valueEndByte:number;
}
export interface DeclaredPrefixSourceReview {
  disposition:DeclaredPrefixDisposition;
  sourceBytes:number;
  prefix:{startByte:0;endByte:number}|null;
  fields:DeclaredPrefixSourceField[];
  autoPromoted:false;
  independentOracleCertified:false;
  canDecodeVendorEscapes:false;
  sourceComplete:false;
  nativeTarget:'NOT_VERIFIED';
  manufacturerSemantics:'NOT_CERTIFIED';
  originalDeviceIdentity:'NOT_ATTESTED';
  transportPeerAuthentication:'NOT_VERIFIED';
}

const LIMIT=16*1024;
const MAX_PREFIX=512;
const HASH=/^[0-9a-f]{64}$/;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const checksum=(bytes:Uint8Array)=>
  createHash('sha256').update(bytes).digest('hex');
function pinned(bytes:Uint8Array,hash:string):boolean{
  return HASH.test(hash)&&checksum(bytes)===hash;
}

export function inspectDeclaredPrefixKvSource(
  input:DeclaredPrefixSourceInput,
):DeclaredPrefixSourceReview{
  const result:DeclaredPrefixSourceReview={
    disposition:'ABSTAIN_UNSAFE',
    sourceBytes:input.sourceBytes instanceof Uint8Array?input.sourceBytes.length:0,
    prefix:null,fields:[],autoPromoted:false,
    independentOracleCertified:false,canDecodeVendorEscapes:false,
    sourceComplete:false,nativeTarget:'NOT_VERIFIED',
    manufacturerSemantics:'NOT_CERTIFIED',
    originalDeviceIdentity:'NOT_ATTESTED',
    transportPeerAuthentication:'NOT_VERIFIED',
  };
  // Without an explicitly asserted one-record boundary, do not probe a
  // candidate or reinterpret an RFC6587 stream as a physical event.
  if(input.recordFraming!=='CONFIRMED_SINGLE_SOURCE_RECORD')
    return {...result,disposition:'RAW_ONLY'};
  const bytes=input.sourceBytes;
  if(!(bytes instanceof Uint8Array)||bytes.length===0||bytes.length>LIMIT||
     !pinned(bytes,input.sourceSha256)||
     input.declaredBodyFormat!=='space_kv'||
     !Number.isInteger(input.declaredPrefixEndByte)||
     input.declaredPrefixEndByte<1||
     input.declaredPrefixEndByte>MAX_PREFIX||
     input.declaredPrefixEndByte>=bytes.length)
    return result;
  const prefixBytes=bytes.subarray(0,input.declaredPrefixEndByte);
  if(!pinned(prefixBytes,input.pinnedPrefixSha256))return result;
  let raw:string,prefix:string;
  try{
    raw=decoder.decode(bytes);
    prefix=decoder.decode(prefixBytes);
  }catch{return result;}
  // Byte round trips detect BOM removal, lossy decoding, illegal UTF-8,
  // and any invalid boundary positioned in the middle of a codepoint.
  if(encoder.encode(raw).length!==bytes.length||
     encoder.encode(prefix).length!==prefixBytes.length||
     !raw.startsWith(prefix)||
     raw.startsWith('<'))return result;
  // Manual marking must not silently discard an existing named source field,
  // a quote state or an unqualified RFC5424-like PRI. It ends at a separator.
  if(!/[ \t]$/.test(prefix)||/[=\r\n\0"'\x00-\x1f\x7f]/.test(prefix.replace(/[ \t]/g,'')))
    return result;
  const bodyStart=prefix.length;
  if(encoder.encode(raw.slice(0,bodyStart)).length!==input.declaredPrefixEndByte)
    return result;
  const candidate=scanKeyValues(raw,bodyStart,'space',{preserveRepeated:true});
  const replay=candidate?replayCandidate(candidate):null;
  // A replayed duplicate is still a real source occurrence, but the base
  // funnel intentionally withholds "fullBodyCovered" for its unresolved
  // semantics. This observer reports source occurrences, never completeness.
  if(!candidate||!replay?.tokenSpansReplayed||
     candidate.naming!=='source'||candidate.fields.length>256)return result;

  const counts=new Map<string,number>();
  const fields:DeclaredPrefixSourceField[]=[];
  for(const field of candidate.fields){
    if(!field.keySpan)return result;
    const occurrence=counts.get(field.key)??0;
    counts.set(field.key,occurrence+1);
    const lexical=raw.slice(field.rawValueSpan.start,field.rawValueSpan.end);
    if(field.valueSpan.startByte>field.valueSpan.endByte||
       decoder.decode(bytes.subarray(field.rawValueSpan.startByte,
         field.rawValueSpan.endByte))!==lexical)
      return result;
    fields.push({
      name:field.key,occurrence,
      sourceValueLexeme:lexical,
      decodedSourceValue:field.value,
      nameStartByte:field.keySpan.startByte,
      nameEndByte:field.keySpan.endByte,
      valueStartByte:field.rawValueSpan.startByte,
      valueEndByte:field.rawValueSpan.endByte,
    });
  }
  return {...result,disposition:'REVIEW_ONLY_DECLARED_PREFIX',
    prefix:{startByte:0,endByte:input.declaredPrefixEndByte},fields};
}
