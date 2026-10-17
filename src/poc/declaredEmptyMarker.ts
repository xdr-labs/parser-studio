/** Source-only manufacturer-documentation-bound empty-marker review.
 *
 * A configured custom Syslog empty symbol is not a universal KV grammar rule.
 * The original lexical value and UTF-8 span always survive, and no empty
 * marker is interpreted unless the exact original and profile are pinned.
 */
import {createHash} from 'node:crypto';
import {conservativeKvLocatedFields} from './conservativeKvUtf8Span';

export type DocumentedValueState=
  'PRESENT_EMPTY_DOCUMENTED'|'PRESENT_NONEMPTY_LEXICAL'|'PRESENT_VALUE_UNSCORABLE';
export interface EmptyMarkerProfile {
  framing:'INDEPENDENTLY_DOCUMENTED_RFC3164_KV_CUSTOM_FORMAT';
  valueContract:'EXPLICIT_UNQUOTED_EMPTY_MARKER';
  sourceSha256:string;
  manufacturerDocSha256:string;
  emptyMarker:string;
  declaredKeys:readonly string[];
}
export interface DeclaredSourceValue {
  name:string;
  state:DocumentedValueState;
  sourceLexeme:string;
  nameStartByte:number;nameEndByte:number;
  valueStartByte:number;valueEndByte:number;
}
export interface EmptyMarkerInspection {
  disposition:'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY';
  reason:string;
  raw:string;
  sourceBytes:number;
  fields:DeclaredSourceValue[];
  absentKeys:readonly string[];
  branchAttempts:number;
  maxDepth:1;
  emptyMarkerSemantics:'DOCUMENTED_REFERENCE_ONLY'|'NOT_CERTIFIED';
  manufacturerFirmwareWire:'NOT_VERIFIED';
  nativeStellar:'NOT_VERIFIED';
  autoPromoted:false;
}
const utf8=new TextEncoder();
const strictDecoder=new TextDecoder('utf8',{fatal:true});
const safe=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const forbidden=new Set(['__proto__','constructor','prototype']);
const validSha=/^[a-f0-9]{64}$/;
const reserved=/(?:[\u0000-\u001f\u007f])/;
const hash=(raw:string)=>createHash('sha256').update(raw,'utf8').digest('hex');

function verifyProfile(profile:EmptyMarkerProfile):boolean{
  if(profile.framing!=='INDEPENDENTLY_DOCUMENTED_RFC3164_KV_CUSTOM_FORMAT'||
     profile.valueContract!=='EXPLICIT_UNQUOTED_EMPTY_MARKER'||
     !validSha.test(profile.sourceSha256)||
     !validSha.test(profile.manufacturerDocSha256)||
     !Array.isArray(profile.declaredKeys)||!profile.declaredKeys.length||
     profile.declaredKeys.length>64)return false;
  // Only one unquoted literal symbol may stand for a configured empty value.
  // Whitespace, letters, digits, quotes, equals and backslash are unsafe here.
  const marker=profile.emptyMarker;
  if(typeof marker!=='string'||marker.length!==1)return false;
  const code=marker.charCodeAt(0);
  if(code<33||code>126||code===96||/[\w'"=\\]/.test(marker))
    return false;
  const seen=new Set<string>();
  for(const key of profile.declaredKeys){
    if(typeof key!=='string'||!safe.test(key)||forbidden.has(key)||
      seen.has(key))return false;
    seen.add(key);
  }
  return true;
}
export function inspectDeclaredEmptyMarker(raw:string,
    profile?:EmptyMarkerProfile):EmptyMarkerInspection{
  const initial:EmptyMarkerInspection={
    disposition:'RAW_ONLY',reason:'NO_INDEPENDENT_DOCUMENTED_EMPTY_MARKER_PROFILE',
    raw,sourceBytes:utf8.encode(raw).length,fields:[],absentKeys:[],
    branchAttempts:0,maxDepth:1,emptyMarkerSemantics:'NOT_CERTIFIED',
    manufacturerFirmwareWire:'NOT_VERIFIED',nativeStellar:'NOT_VERIFIED',
    autoPromoted:false,
  };
  const abort=(reason:string,attempt=0):EmptyMarkerInspection=>({
    ...initial,disposition:'ABSTAIN_UNSAFE',reason,branchAttempts:attempt,
  });
  if(!profile)return initial;
  if(!verifyProfile(profile))return abort('INVALID_DECLARED_EMPTY_MARKER_PROFILE');
  if(initial.sourceBytes>8192||!raw||reserved.test(raw)||hash(raw)!==profile.sourceSha256)
    return abort('UNQUALIFIED_OR_DRIFTED_DOCUMENTED_SOURCE');
  const candidate=conservativeKvLocatedFields(raw);
  if(!candidate||candidate.envelope!=='yearless_rfc3164_kv')
    return abort('SOURCE_ENVELOPE_OR_KV_LEXICAL_UNSCORABLE',1);
  const rawBytes=utf8.encode(raw);
  const schema=new Set(profile.declaredKeys);
  const present=new Set<string>();
  const fields:DeclaredSourceValue[]=[];
  for(const found of candidate.spans){
    if(!schema.has(found.name)||present.has(found.name))
      return abort('UNDECLARED_OR_DUPLICATED_SOURCE_FIELD',2);
    present.add(found.name);
    if(found.valueStart<0||found.valueEnd>rawBytes.length||
       found.valueEnd<=found.valueStart||found.nameEnd>found.valueStart)
      return abort('SOURCE_VALUE_OFFSET_OUTSIDE_ORIGINAL',2);
    let sourceLexeme:string,name:string;
    try{
      sourceLexeme=strictDecoder.decode(rawBytes.subarray(
        found.valueStart,found.valueEnd));
      name=strictDecoder.decode(rawBytes.subarray(
        found.nameStart,found.nameEnd));
    }catch{return abort('INVALID_ORIGINAL_UTF8_SOURCE_OFFSET',2);}
    if(name!==found.name||rawBytes[found.nameEnd]!==61)
      return abort('UNREPLAYABLE_FIELD_SOURCE_IDENTITY',2);
    // The lexer supports some lexical backslash forms but no certified
    // producer escaping in this proof; do not decode or claim those forms.
    if(sourceLexeme.includes('\\'))
      return abort('VENDOR_ESCAPE_MEANING_NOT_INDEPENDENTLY_DOCUMENTED',2);
    const state:DocumentedValueState=sourceLexeme===profile.emptyMarker?
      'PRESENT_EMPTY_DOCUMENTED':
      sourceLexeme==='""'||sourceLexeme==='"'+profile.emptyMarker+'"'?
       'PRESENT_VALUE_UNSCORABLE':'PRESENT_NONEMPTY_LEXICAL';
    fields.push({name:found.name,state,sourceLexeme,
      nameStartByte:found.nameStart,nameEndByte:found.nameEnd,
      valueStartByte:found.valueStart,valueEndByte:found.valueEnd});
  }
  const absentKeys=profile.declaredKeys.filter(key=>!present.has(key));
  // Absence is not an empty value and never induces a fabricated claim.
  return {...initial,disposition:'REVIEW_ONLY',
    reason:'DOCUMENTED_CUSTOM_SOURCE_EMPTY_MARKER_REFERENCE_ONLY',
    fields,absentKeys,branchAttempts:2,
    emptyMarkerSemantics:'DOCUMENTED_REFERENCE_ONLY'};
}
