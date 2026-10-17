import {inspectGeneralSyslogEnvelope,type SyslogOriginalField} from './generalSyslogEnvelopeSpans';
import {inspectBoundedSourceSpans,type StructuralSourceField} from './boundedStructuralSourceSpans';
import {
  scanKeyValues,scanPrefixedKeyValues,type LexicalCandidate,type Separator,
} from './losslessLexer';
import {replayCandidate} from './grammarFunnel';

/**
 * Isolated, vendor-neutral source-only layered adjudication.
 *
 * A validated Syslog envelope is NOT a validated structured body; lexical
 * replay is NOT independent field truth and never implies native compilation.
 * Grammar and source span proof are retained separately at each layer.
 */
export type ArbitrationDisposition=
  'REVIEW_ONLY_STRUCTURED_BODY'|'REVIEW_ONLY_ENVELOPE'|'REVIEW_ONLY_UNFRAMED'|
  'REVIEW_ONLY_AMBIGUOUS'|'ABSTAIN_UNSAFE'|'RAW_ONLY';
/** Existing qualified profiles and independent source provenance may veto but
 * can NEVER approve/auto-promote an extraction via this lexical adapter. */
export interface IndependentReviewVeto {
  sourceIdentity:'MATCH'|'MISMATCH'|'UNSCORED';
  structuralProfile:'ACCEPT'|'VETO'|'UNSCORED';
  independentSourceTruth:'EXACT'|'CONFLICT'|'UNSCORED';
}
export type BodyGrammar='json'|'kv_space'|'kv_pipe'|'kv_semicolon'|'kv_tab'|
  'kv_comma'|'prefixed_kv_space'|'none';
export interface SourceFieldClaim {
  layer:'envelope'|'body';
  grammar:BodyGrammar|'rfc3164'|'rfc5424';
  path:string;
  name:string;
  value:unknown;
  valueType:'string'|'integer'|'number'|'boolean'|'null';
  startByte:number;
  endByte:number;
  rawSpanValue:string;
  evidence:'EXACT_RAW_SLICE'|'STANDARD_JSON_LITERAL'|'BOUNDED_KV_LEXER_REPLAY';
  occurrence:number;
}
export interface BodyArbitration {
  disposition:ArbitrationDisposition;
  raw:string;
  sourceBytes:number;
  envelopeMode:'rfc3164'|'rfc5424'|'unframed'|'unsafe';
  envelopeFields:SourceFieldClaim[];
  selectedBodyGrammar:BodyGrammar;
  bodyClaims:SourceFieldClaim[];
  candidateGrammars:BodyGrammar[];
  bodyReviewEvidence:'LEXICALLY_REPLAYED'|'NOT_PROVEN'|'AMBIGUOUS';
  reason:string;
  branchAttempts:number;
  maxBranchAttempts:8;
  autoPromoted:false;
  independentOracleCertified:false;
  nativeVerified:false;
}
const DELIMITERS:Separator[]=['space','pipe','semicolon','tab','comma'];
const encode=new TextEncoder();
const decode=new TextDecoder('utf-8',{fatal:true});
const bytes=(raw:string)=>encode.encode(raw);
const MAX_SOURCE=64*1024;
const MAX_SYSLOG_BYTES=8192;
const MAX_BODY_CANDIDATES=7;
const MAX_CLAIMS=2000;
const nonBody=(raw:string,reason:string):BodyArbitration=>({
  disposition:'RAW_ONLY',raw,sourceBytes:bytes(raw).length,
  envelopeMode:'unframed',envelopeFields:[],selectedBodyGrammar:'none',
  bodyClaims:[],candidateGrammars:[],bodyReviewEvidence:'NOT_PROVEN',
  reason,branchAttempts:0,maxBranchAttempts:8,
  autoPromoted:false,independentOracleCertified:false,nativeVerified:false,
});
function unicodeOkay(raw:string):boolean{
  for(let i=0;i<raw.length;i++){
    const c=raw.charCodeAt(i);
    if(c>=0xd800&&c<=0xdbff){
      i++;
      if(i===raw.length||raw.charCodeAt(i)<0xdc00||raw.charCodeAt(i)>0xdfff)return false;
    }else if(c>=0xdc00&&c<=0xdfff)return false;
  }
  return true;
}
function toRawSpan(source:Uint8Array,start:number,end:number):string|null{
  if(start<0||end<start||end>source.length)return null;
  try{return decode.decode(source.subarray(start,end));}
  catch{return null;}
}
function headers(fields:SyslogOriginalField[],raw:string,
  mode:'rfc3164'|'rfc5424'):SourceFieldClaim[]|null{
  const source=bytes(raw);
  const seen=new Set<string>();
  const output:SourceFieldClaim[]=[];
  for(const f of fields){
    if(seen.has(f.name))return null;
    seen.add(f.name);
    const original=toRawSpan(source,f.startByte,f.endByte);
    if(original===null||original!==f.value)return null;
    output.push({layer:'envelope',grammar:mode,path:'/syslog/'+f.name,
      name:f.name,value:f.value,valueType:'string',
      startByte:f.startByte,endByte:f.endByte,rawSpanValue:original,
      evidence:'EXACT_RAW_SLICE',occurrence:0});
  }
  return output;
}
function jsonClaim(value:StructuralSourceField,full:Uint8Array,offset:number):
  SourceFieldClaim|null {
  const start=offset+value.startByte,end=offset+value.endByte;
  const text=toRawSpan(full,start,end);
  if(text===null)return null;
  let parsed:unknown;
  try{parsed=JSON.parse(text);}catch{return null;}
  if(!Object.is(parsed,value.value))return null;
  return {layer:'body',grammar:'json',path:'/body'+value.path,
    name:value.path,value:value.value,valueType:value.type,
    startByte:start,endByte:end,rawSpanValue:text,
    evidence:'STANDARD_JSON_LITERAL',occurrence:0};
}
function jsonBody(raw:string,body:string,bodyByteStart:number):SourceFieldClaim[]|null{
  const scanned=inspectBoundedSourceSpans(body);
  if(scanned.disposition!=='REVIEW_ONLY'||scanned.syntax!=='json_object')return null;
  if(scanned.bodyStartByte!==0||scanned.fields.length>MAX_CLAIMS)return null;
  const full=bytes(raw);
  const claims=scanned.fields.map(field=>jsonClaim(field,full,bodyByteStart));
  return claims.every(c=>c!==null)?claims as SourceFieldClaim[]:null;
}
function lexicalClaims(candidate:LexicalCandidate):SourceFieldClaim[]|null{
  if(candidate.naming!=='source'||!replayCandidate(candidate))return null;
  if(candidate.fields.length>256)return null;
  const buffer=bytes(candidate.sourceRaw);
  const counts=new Map<string,number>();
  const claims:SourceFieldClaim[]=[];
  for(const field of candidate.fields){
    const original=toRawSpan(buffer,field.rawValueSpan.startByte,
      field.rawValueSpan.endByte);
    if(original===null)return null;
    const occurrence=counts.get(field.key)??0;
    counts.set(field.key,occurrence+1);
    claims.push({layer:'body',grammar:candidate.grammar as BodyGrammar,
      path:'/body/kv/'+field.key.replaceAll('~','~0').replaceAll('/','~1')+'#'+occurrence,
      name:field.key,value:field.value,valueType:'string',
      startByte:field.rawValueSpan.startByte,endByte:field.rawValueSpan.endByte,
      rawSpanValue:original,evidence:'BOUNDED_KV_LEXER_REPLAY',occurrence});
  }
  return claims;
}
function canonical(claims:SourceFieldClaim[]):string{
  return JSON.stringify(claims.map(c=>[
    c.path,c.name,c.value,c.valueType,c.startByte,c.endByte,
  ]));
}
export function arbitrateSourceBody(raw:string, review?:IndependentReviewVeto):BodyArbitration{
  const fallback=nonBody(raw,'NO_VERIFIED_SOURCE_STRUCTURE');
  const full=bytes(raw);
  // Only negative external evidence changes this stage's eligibility.
  // Claimed ACCEPT/EXACT alone never grants source/native certification.
  if(review?.sourceIdentity==='MISMATCH'||
     review?.structuralProfile==='VETO'||
     review?.independentSourceTruth==='CONFLICT'){
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'INDEPENDENT_SOURCE_OR_PROFILE_VETO'};
  }
  if(!raw||full.length>MAX_SOURCE||!unicodeOkay(raw)||raw.includes('\0')){
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'OUTSIDE_BOUNDED_ORIGINAL_BYTE_CONTRACT'};
  }
  const envelope=inspectGeneralSyslogEnvelope(raw);
  const possibleSyslog=/^<[0-9]{1,3}>/.test(raw);
  if(possibleSyslog&&envelope.disposition!=='REVIEW_ONLY'){
    return {...fallback,disposition:'ABSTAIN_UNSAFE',envelopeMode:'unsafe',
      reason:'INDETERMINATE_SYSLOG_ENVELOPE'};
  }
  const framed=envelope.disposition==='REVIEW_ONLY';
  if(framed&&envelope.format!=='rfc3164'&&envelope.format!=='rfc5424'){
    return {...fallback,disposition:'ABSTAIN_UNSAFE',envelopeMode:'unsafe',
      reason:'UNRECOGNIZED_VALIDATED_ENVELOPE_KIND'};
  }
  if(framed&&full.length>MAX_SYSLOG_BYTES){
    return {...fallback,disposition:'ABSTAIN_UNSAFE',envelopeMode:'unsafe',
      reason:'BOUNDED_SYSLOG_SIZE_EXCEEDED'};
  }
  const frameMode:BodyArbitration['envelopeMode']=framed?
    (envelope.format==='rfc3164'?'rfc3164':'rfc5424'):'unframed';
  const headerFields=framed?headers(envelope.fields,raw,envelope.format as
    'rfc3164'|'rfc5424'):[];
  if(headerFields===null)
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'UNCERTIFIED_ENVELOPE_BYTE_SPANS'};
  const messageField=framed?envelope.fields.find(f=>f.name==='message'):null;
  if(framed&&!messageField){
    return {...fallback,disposition:'REVIEW_ONLY_ENVELOPE',
      envelopeMode:frameMode,envelopeFields:headerFields,
      reason:'EMPTY_OR_UNNAMED_SYSLOG_BODY'};
  }
  const byteStart=messageField?.startByte??0;
  // Recover exactly the original UTF-8 byte boundary; no prefix rewrite.
  const message=toRawSpan(full,byteStart,full.length);
  if(message===null)return {...fallback,disposition:'ABSTAIN_UNSAFE',
    envelopeMode:framed?frameMode:'unsafe',reason:'MESSAGE_SOURCE_BYTES_NOT_REPLAYABLE'};
  // Use end-anchored substring only after byte-exact replay; no UTF-8 length guessing.
  const bodyCodeUnitStart=framed?raw.length-message.length:0;
  if(raw.slice(bodyCodeUnitStart)!==message||
     bytes(raw.slice(0,bodyCodeUnitStart)).length!==byteStart){
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'SOURCE_BODY_BOUNDARY_CONFLICT'};
  }
  let attempts=1;
  const candidates:Array<{name:BodyGrammar;fields:SourceFieldClaim[]}>=[];

  attempts++;
  const jsonFields=jsonBody(raw,message,byteStart);
  if(jsonFields?.length)candidates.push({name:'json',fields:jsonFields});

  for(const separator of DELIMITERS){
    attempts++;
    const lexer=scanKeyValues(raw,bodyCodeUnitStart,separator,
      {preserveRepeated:true});
    if(!lexer)continue;
    const claims=lexicalClaims(lexer);
    if(claims?.length)candidates.push({name:lexer.grammar as BodyGrammar,fields:claims});
  }
  attempts++;
  if(attempts>8||candidates.length>MAX_BODY_CANDIDATES)
    return {...fallback,disposition:'ABSTAIN_UNSAFE',reason:'BRANCH_BOUND_EXCEEDED'};
  const prefixed=scanPrefixedKeyValues(raw,bodyCodeUnitStart);
  if(prefixed){
    const claims=lexicalClaims(prefixed);
    if(claims?.length)candidates.push({name:'prefixed_kv_space',fields:claims});
  }
  if(candidates.length===0){
    return {...fallback,disposition:framed?'REVIEW_ONLY_ENVELOPE':'RAW_ONLY',
      envelopeMode:frameMode,envelopeFields:headerFields,
      bodyReviewEvidence:'NOT_PROVEN',branchAttempts:attempts,
      reason:'STRUCTURED_BODY_UNSCORABLE_WITHOUT_CONFIRMED_GRAMMAR'};
  }
  const interpretations=new Set(candidates.map(c=>canonical(c.fields)));
  if(interpretations.size>1){
    return {...fallback,disposition:'REVIEW_ONLY_AMBIGUOUS',
      envelopeMode:frameMode,envelopeFields:headerFields,
      candidateGrammars:candidates.map(c=>c.name),
      bodyReviewEvidence:'AMBIGUOUS',branchAttempts:attempts,
      reason:'COMPETING_BODY_INTERPRETATIONS_DISAGREE'};
  }
  const selected=candidates[0]!;
  if(selected.fields.length>MAX_CLAIMS)
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'BODY_FIELD_COUNT_EXCEEDED'};
  return {...fallback,disposition:framed?'REVIEW_ONLY_STRUCTURED_BODY':'REVIEW_ONLY_UNFRAMED',
    envelopeMode:frameMode,envelopeFields:headerFields,
    selectedBodyGrammar:selected.name,bodyClaims:selected.fields,
    candidateGrammars:candidates.map(c=>c.name),
    bodyReviewEvidence:'LEXICALLY_REPLAYED',branchAttempts:attempts,
    reason:'LEXICALLY_CONSISTENT_NOT_INDEPENDENTLY_CERTIFIED'};
}
