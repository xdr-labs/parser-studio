/** Generic, source-only CEF extension escape observer.
 *
 * Requires independently pinned source identity and a declared author escape
 * contract. The original raw value span is never rewritten or discarded.
 * This is not a complete CEF parser, producer firmware proof or native output.
 */
import {createHash} from 'node:crypto';

export interface DeclaredCefEscapeProfile {
  framing:'INDEPENDENTLY_DOCUMENTED_SINGLE_CEF_RECORD';
  valueGrammar:'BACKSLASH_ESCAPES_EQUALS';
  sourceSha256:string;
  manufacturerDocumentSha256:string;
  sourceFieldName:string;
}
export interface CefEscapedSourceField {
  sourceFieldName:string;
  decodedValue:string;
  rawLexeme:string;
  keyStartByte:number;keyEndByte:number;
  valueStartByte:number;valueEndByte:number;
  escapeCount:number;
}
export interface CefEscapeInspection {
  disposition:'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY';
  raw:string;sourceBytes:number;
  fields:CefEscapedSourceField[];
  reason:string;
  branchAttempts:number;maxDepth:1;
  decodedValueMeaning:'AUTHOR_DECLARED_REFERENCE_ONLY'|'NOT_CERTIFIED';
  firmwareWire:'NOT_VERIFIED';
  nativeStellar:'NOT_VERIFIED';
  autoPromoted:false;
}
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf8',{fatal:true});
const validSha=/^[a-f0-9]{64}$/;
const safeKey=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const badKey=new Set(['__proto__','prototype','constructor']);
const HEADER=/^(?:(?:<([0-9]{1,3})>)?([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}):([0-9]{2}):([0-9]{2}) +([A-Za-z0-9][A-Za-z0-9_.-]{0,254}) +)?CEF: ?([0-9]{1,3})\|([^|\r\n]{1,128})\|([^|\r\n]{1,128})\|([^|\r\n]{1,128})\|([^|\r\n]{1,128})\|([^|\r\n]{1,256})\|([0-9]{1,2})\|/;
const DIGEST=(raw:string)=>createHash('sha256').update(raw,'utf8').digest('hex');
function unicodeOkay(raw:string):boolean {
  for(let i=0;i<raw.length;i++){
    const c=raw.charCodeAt(i);
    if(c>=0xd800&&c<=0xdbff){
      i++;if(i>=raw.length||raw.charCodeAt(i)<0xdc00||raw.charCodeAt(i)>0xdfff)
        return false;
    }else if(c>=0xdc00&&c<=0xdfff)return false;
  }
  return true;
}
function validHeader(m:RegExpExecArray):boolean{
  const pri=m[1];
  if(pri!==undefined&&Number(pri)>191)return false;
  if(m[2]!==undefined){
    const day=Number(m[3]),h=Number(m[4]),min=Number(m[5]),s=Number(m[6]);
    if(day<1||day>31||h>23||min>59||s>59)return false;
  }
  return Number(m[8])<=255&&Number(m[14])<=10;
}
export function inspectDeclaredCefEscape(raw:string,
   profile?:DeclaredCefEscapeProfile):CefEscapeInspection{
  const size=encoder.encode(raw).length;
  const initial:CefEscapeInspection={
    disposition:'RAW_ONLY',raw,sourceBytes:size,fields:[],
    reason:'NO_INDEPENDENT_CEF_ESCAPE_PROFILE',branchAttempts:0,maxDepth:1,
    decodedValueMeaning:'NOT_CERTIFIED',firmwareWire:'NOT_VERIFIED',
    nativeStellar:'NOT_VERIFIED',autoPromoted:false,
  };
  const fail=(reason:string,attempt=0):CefEscapeInspection=>({
    ...initial,disposition:'ABSTAIN_UNSAFE',reason,branchAttempts:attempt,
  });
  if(!profile)return initial;
  if(profile.framing!=='INDEPENDENTLY_DOCUMENTED_SINGLE_CEF_RECORD'||
     profile.valueGrammar!=='BACKSLASH_ESCAPES_EQUALS'||
     !validSha.test(profile.sourceSha256)||
     !validSha.test(profile.manufacturerDocumentSha256)||
     typeof profile.sourceFieldName!=='string'||
     !safeKey.test(profile.sourceFieldName)||
     badKey.has(profile.sourceFieldName))
    return fail('UNQUALIFIED_OR_UNSAFE_CEF_ESCAPE_DECLARATION');
  if(!raw||size>8192||!unicodeOkay(raw)||/[\r\n\0]/.test(raw)||
      DIGEST(raw)!==profile.sourceSha256)
    return fail('ORIGINAL_SOURCE_IDENTITY_OR_BOUNDS_INVALID');
  const head=HEADER.exec(raw);
  if(!head||!validHeader(head)||head[0].includes('\\'))
    return fail('AMBIGUOUS_CEF_ENVELOPE',1);
  const extension=raw.slice(head[0].length);
  if(!extension||extension.length>8192)
    return fail('CEF_EXTENSION_OUTSIDE_BOUNDS',1);
  const key=profile.sourceFieldName;
  const safeKeyLiteral=key.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const matcher=new RegExp('(?:^|[ \\t])('+safeKeyLiteral+')=([^ \\t\\r\\n]{1,2048})(?=$|[ \\t])','g');
  const matches=[...extension.matchAll(matcher)];
  if(matches.length!==1)return fail('DECLARED_CEF_FIELD_ABSENT_OR_AMBIGUOUS',2);
  const match=matches[0]!;
  const leading=match[0].startsWith(' ' )||match[0].startsWith('\t')?1:0;
  const keyStart=head[0].length+match.index!+leading;
  const valueStart=keyStart+key.length+1;
  const lexeme=match[2]!;
  if(!lexeme||lexeme.includes('"')||lexeme.includes("'"))
    return fail('QUOTED_OR_EMPTY_CEF_EXTENSION_UNSUPPORTED',2);
  let decoded='',escapes=0;
  for(let i=0;i<lexeme.length;i++){
    const c=lexeme[i]!;
    if(c==='\\'){
      // A manufacturer-authoritative escape is necessary. This profile
      // covers only \=, not blanket unescaping of unknown wire values.
      if(lexeme[i+1]!=='=')return fail('UNKNOWN_MANUFACTURER_CEF_ESCAPE',2);
      decoded+='=';i++;escapes++;
    }else if(c==='='){
      return fail('UNESCAPED_EQUALS_HAS_AMBIGUOUS_CEF_VALUE_BOUNDARY',2);
    }else{
      if(c.charCodeAt(0)<33||c.charCodeAt(0)===127)
        return fail('CONTROL_CHARACTER_IN_DECLARED_CEF_VALUE',2);
      decoded+=c;
    }
  }
  if((escapes<1||escapes>16)||!decoded||encoder.encode(decoded).length>2048)
    return fail('DOCUMENTED_CEF_ESCAPE_OCCURRENCE_NOT_QUALIFIED',2);
  const bytes=encoder.encode(raw);
  const keyStartByte=encoder.encode(raw.slice(0,keyStart)).length;
  const keyEndByte=encoder.encode(raw.slice(0,keyStart+key.length)).length;
  const valueStartByte=encoder.encode(raw.slice(0,valueStart)).length;
  const valueEndByte=encoder.encode(raw.slice(0,valueStart+lexeme.length)).length;
  try{
    if(decoder.decode(bytes.subarray(keyStartByte,keyEndByte))!==key||
       bytes[keyEndByte]!==61||
       decoder.decode(bytes.subarray(valueStartByte,valueEndByte))!==lexeme)
      return fail('EXACT_RAW_CEF_UTF8_VALUE_REPLAY_FAILED',2);
  }catch{return fail('INVALID_UTF8_CEF_INTERVAL',2);}
  return {...initial,disposition:'REVIEW_ONLY',branchAttempts:2,
    reason:'EXPLICIT_DOCUMENTED_CEF_ESCAPE_SOURCE_REVIEW',
    fields:[{sourceFieldName:key,decodedValue:decoded,rawLexeme:lexeme,
      keyStartByte,keyEndByte,valueStartByte,valueEndByte,escapeCount:escapes}],
    decodedValueMeaning:'AUTHOR_DECLARED_REFERENCE_ONLY'};
}
