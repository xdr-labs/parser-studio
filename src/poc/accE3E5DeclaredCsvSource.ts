import {createHash} from 'node:crypto';
import {inspectIndependentQuotedCsv} from './independentQuotedCsvSource';

/**
 * Source-only review of a caller-marked original CSV byte excerpt with separately
 * declared ordered columns. This is NOT an observed physical CSV header.
 * It does not infer packet/record origin or apply any manufacturer decoder.
 */
export interface DeclaredCsvSourceInput {
  sourceBytes:Uint8Array;
  sourceSha256:string;
  csvStartByte:number;
  csvEndByte:number;
  csvSliceSha256:string;
  orderedNames:readonly string[];
  orderedNamesSha256:string;
  recordFraming:string;
  declaredFormat:string;
  schemaProvenance:string;
}

export interface DeclaredCsvSourceField {
  ordinal:number;
  name:string;
  nameStartByte:null;
  sourceValue:string;
  sourceValueLexeme:string;
  startByte:number;
  endByte:number;
  valueType:'UNVERIFIED_SOURCE_STRING';
}

export interface DeclaredCsvSourceReview {
  disposition:'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY_EXTERNAL_CSV_SCHEMA';
  reason:string;
  sourceBytes:number;
  sourceReviewRange:{startByte:number;endByte:number}|null;
  unreviewedPrefixBytes:number;
  unreviewedSuffixBytes:number;
  fields:DeclaredCsvSourceField[];
  schemaBasis:'EXTERNALLY_DECLARED_NOT_SOURCE_HEADER';
  declaredSchemaProvenance:'PUBLISHER_DOCUMENTED_ORDER'|'USER_DECLARED_ORDER'|'UNVERIFIED';
  autoPromoted:false;
  sourceComplete:false;
  canAutoPromote:false;
  independentOracleCertified:false;
  manufacturerSemantics:'NOT_CERTIFIED';
  transportPeerAuthentication:'NOT_VERIFIED';
  originalDeviceIdentity:'NOT_ATTESTED';
  nativeVerified:false;
}
const MAX_SOURCE_BYTES=64*1024;
const MAX_SLICE_BYTES=16*1024;
const MAX_CSV_COLUMNS=128;
const UNSAFE_NAMES=new Set(['__proto__','prototype','constructor']);
const HASH=/^[0-9a-f]{64}$/;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
// Byte views can cross isolated browser/worker/test realms. A realm-local
// instanceof Uint8Array is not proof that bytes are invalid.
function byteView(value:unknown):value is Uint8Array{
  return ArrayBuffer.isView(value)&&
    Object.prototype.toString.call(value)==='[object Uint8Array]';
}
const sha=(bytes:Uint8Array)=>
  createHash('sha256').update(bytes).digest('hex');

function hashMatches(bytes:Uint8Array,expected:string):boolean{
  return HASH.test(expected)&&sha(bytes)===expected;
}
function bytesEqual(a:Uint8Array,b:Uint8Array):boolean{
  if(a.length!==b.length)return false;
  for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;
  return true;
}
function namesQualified(names:readonly string[]):boolean{
  if(!Array.isArray(names)||names.length===0||names.length>MAX_CSV_COLUMNS)return false;
  const seen=new Set<string>();
  for(const name of names){
    if(typeof name!=='string'||!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name)||
       UNSAFE_NAMES.has(name.toLowerCase())||seen.has(name.toLowerCase()))
      return false;
    seen.add(name.toLowerCase());
  }
  return true;
}

export function inspectDeclaredCsvSource(
  input:DeclaredCsvSourceInput,
):DeclaredCsvSourceReview{
  const source=input?.sourceBytes;
  const result:DeclaredCsvSourceReview={
    disposition:'ABSTAIN_UNSAFE',reason:'UNQUALIFIED_SOURCE_OR_SCHEMA',
    sourceBytes:byteView(source)?source.length:0,
    sourceReviewRange:null,unreviewedPrefixBytes:0,unreviewedSuffixBytes:0,
    fields:[],
    schemaBasis:'EXTERNALLY_DECLARED_NOT_SOURCE_HEADER',
    declaredSchemaProvenance:'UNVERIFIED',
    autoPromoted:false,sourceComplete:false,canAutoPromote:false,
    independentOracleCertified:false,manufacturerSemantics:'NOT_CERTIFIED',
    transportPeerAuthentication:'NOT_VERIFIED',
    originalDeviceIdentity:'NOT_ATTESTED',nativeVerified:false,
  };
  // Even a perfectly decoded row cannot assert one physical event. Without
  // an explicit displayed-record assertion, do not parse the excerpt at all.
  if(input?.recordFraming!=='EXPLICIT_SINGLE_DISPLAYED_RECORD')
    return {...result,disposition:'RAW_ONLY',reason:'SINGLE_RECORD_BOUNDARY_NOT_ASSERTED'};
  const provenance=input.schemaProvenance;
  if(!byteView(source)||source.length===0||
     source.length>MAX_SOURCE_BYTES||!hashMatches(source,input.sourceSha256)||
     input.declaredFormat!=='rfc4180_comma_csv'||
     (provenance!=='PUBLISHER_DOCUMENTED_ORDER'&&
      provenance!=='USER_DECLARED_ORDER')||
     !namesQualified(input.orderedNames)||
     !hashMatches(encoder.encode(JSON.stringify(input.orderedNames)),
                  input.orderedNamesSha256))
    return result;
  const start=input.csvStartByte,end=input.csvEndByte;
  if(!Number.isInteger(start)||!Number.isInteger(end)||start<0||
     end<=start||end>source.length||end-start>MAX_SLICE_BYTES)return result;
  const bodyBytes=source.subarray(start,end);
  if(!hashMatches(bodyBytes,input.csvSliceSha256))return result;
  let fullText:string,bodyText:string;
  try{
    fullText=decoder.decode(source);
    bodyText=decoder.decode(bodyBytes);
  }catch{return result;}
  // TextDecoder strips BOM and JavaScript strings permit UTF-16 ambiguity.
  // Require entire byte-for-byte round trip BEFORE exposing original positions.
  if(!bytesEqual(encoder.encode(fullText),source)||
     !bytesEqual(encoder.encode(bodyText),bodyBytes)||
     fullText.includes('\0')||bodyText.length===0)
    return result;
  // The existing qualified RFC 4180 source lexer handles cells, quotes,
  // doubled quotes, empty values, and malformed record abstention.
  const csv=inspectIndependentQuotedCsv(bodyText,{
    recordFraming:'CONFIRMED_SINGLE_CSV_RECORD',
    treatUnquotedEmptyAsNull:false,
  });
  if(csv.disposition!=='REVIEW_ONLY_POSITIONAL'||
     csv.positionalClaims.length!==input.orderedNames.length)
    return result;
  const fields:DeclaredCsvSourceField[]=[];
  for(const [ordinal,claim] of csv.positionalClaims.entries()){
    const claimStart=start+claim.startByte;
    const claimEnd=start+claim.endByte;
    if(typeof claim.value!=='string'||claimStart<start||claimEnd>end||
       claimEnd<claimStart)return result;
    let lexical:string;
    try{lexical=decoder.decode(source.subarray(claimStart,claimEnd));}
    catch{return result;}
    if(lexical!==claim.rawValueSpan)return result;
    fields.push({
      ordinal,name:input.orderedNames[ordinal]!,nameStartByte:null,
      sourceValue:claim.value,sourceValueLexeme:lexical,
      startByte:claimStart,endByte:claimEnd,
      valueType:'UNVERIFIED_SOURCE_STRING',
    });
  }
  // Outside [start,end) remains original, unreviewed source evidence.
  // This cannot silently promote collector text to a native parsed event.
  return {...result,disposition:'REVIEW_ONLY_EXTERNAL_CSV_SCHEMA',
    reason:'PINNED_EXTERNAL_COLUMN_ORDER_SOURCE_LEXICAL_REVIEW_ONLY',
    declaredSchemaProvenance:provenance,
    sourceReviewRange:{startByte:start,endByte:end},
    unreviewedPrefixBytes:start,unreviewedSuffixBytes:source.length-end,
    fields};
}
