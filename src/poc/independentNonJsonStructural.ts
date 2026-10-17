import {arbitrateSourceBody,type BodyArbitration,type SourceFieldClaim,
  type IndependentReviewVeto} from './boundedSourceBodyArbiter';

/** Independent standard-format source observer; never a native/product parser. */
type CefField=Omit<SourceFieldClaim,'grammar'> & {grammar:'cef'};
export type IndependentNonJsonResult=
  BodyArbitration |
  (Omit<BodyArbitration,'selectedBodyGrammar'|'candidateGrammars'|'bodyClaims'> & {
    selectedBodyGrammar:'cef'|'none';
    candidateGrammars:('cef'|'none')[];
    bodyClaims:CefField[];
  });
const byteLength=(raw:string)=>new TextEncoder().encode(raw).length;
const MAX_CEF_BYTES=8192;
const HEADER=['version','deviceVendor','deviceProduct','deviceVersion',
  'deviceEventClassId','name','severity'] as const;
/**
 * An unqualified RFC3164-shaped preamble is not treated as a certified
 * envelope. It only allows an explicitly delimited CEF token to be inspected.
 */
const CEF_BOUNDARY=/^(?:[A-Z][a-z]{2} +(?:[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [A-Za-z0-9_.-]{1,255} )?CEF:/;
const EXTENSION_KEY=/(?:^|[ \t])([A-Za-z_][A-Za-z0-9_.-]{0,127})=/g;
const UNSAFE=new Set(['__proto__','prototype','constructor']);
function hasOnlyValidUnicode(raw:string):boolean {
  for(let i=0;i<raw.length;i++){
    const unit=raw.charCodeAt(i);
    if(unit>=0xd800&&unit<=0xdbff){
      if(++i>=raw.length||raw.charCodeAt(i)<0xdc00||raw.charCodeAt(i)>0xdfff)return false;
    }else if(unit>=0xdc00&&unit<=0xdfff)return false;
  }
  return true;
}
function claim(raw:string,name:string,value:string,start:number,end:number,
  section:'header'|'extension',occurrence=0):CefField|null {
  if(raw.slice(start,end)!==value||!value&&name!=='extension_empty')return null;
  const startByte=byteLength(raw.slice(0,start));
  const endByte=byteLength(raw.slice(0,end));
  if(new TextDecoder('utf-8',{fatal:true}).decode(
    new TextEncoder().encode(raw).slice(startByte,endByte))!==value)return null;
  return {layer:'body',grammar:'cef',path:'/body/cef/'+
    section+'/'+
    name.replaceAll('~','~0').replaceAll('/','~1')+'#'+occurrence,
    name,value,valueType:'string',startByte,endByte,rawSpanValue:value,
    evidence:'EXACT_RAW_SLICE',occurrence};
}
function readHeaders(raw:string,start:number):{claims:CefField[];ext:number}|null {
  let cursor=start+4;
  const claims:CefField[]=[];
  for(let index=0;index<HEADER.length;index++){
    const begin=cursor;
    while(cursor<raw.length&&raw[cursor]!=='|'){
      if(raw[cursor]==='\\'){
        // Unknown CEF header escape semantics must not be guessed.
        return null;
      }
      const code=raw.charCodeAt(cursor);
      if(code<32||code===127||cursor-begin>1024)return null;
      cursor++;
    }
    if(cursor===raw.length||cursor===begin)return null;
    const value=raw.slice(begin,cursor),name=HEADER[index]!;
    if(index===0&&(!/^(0|[1-9][0-9]{0,2})$/.test(value)||+value>255))
      return null;
    const field=claim(raw,name,value,begin,cursor,'header');
    if(field===null)return null;
    claims.push(field);
    cursor++;
  }
  return {claims,ext:cursor};
}
function readExtensions(raw:string,start:number):CefField[]|null {
  if(start===raw.length)return [];
  const body=raw.slice(start);
  if(/[\r\n\0]/.test(body))return null;
  const names=[...body.matchAll(EXTENSION_KEY)];
  if(!names.length||names[0]!.index!==0||names.length>256)return null;
  const seen=new Map<string,number>();
  const claims:CefField[]=[];
  for(let i=0;i<names.length;i++){
    const match=names[i]!;
    const name=match[1]!;
    if(UNSAFE.has(name)||UNSAFE.has(name.replaceAll('-','_')))return null;
    const valueStart=start+match.index!+match[0].length;
    const next=names[i+1];
    const rawEnd=next?start+next.index!:raw.length;
    let valueEnd=rawEnd;
    if(next)while(valueEnd>valueStart&&/[ \t]/.test(raw[valueEnd-1]!))valueEnd--;
    const value=raw.slice(valueStart,valueEnd);
    // A value containing unquoted whitespace, quotes or unspecified escapes
    // is not a trustworthy source token. Preserve the complete raw input.
    if(value.length>8192||/\s/u.test(value)||value.includes(String.fromCharCode(92))||value.includes(String.fromCharCode(34))||value.includes(String.fromCharCode(39)))return null;
    const occurrence=seen.get(name)??0;
    seen.set(name,occurrence+1);
    if(value.length===0)continue; // Empty CEF extension may mean null.
    const field=claim(raw,name,value,valueStart,valueEnd,'extension',occurrence);
    if(field===null)return null;
    claims.push(field);
  }
  return claims;
}
/**
 * Compose a bounded CEF header/extension grammar beside unchanged PR #46.
 * CEF is an open structural wire grammar, not an individual vendor profile.
 * Any unsupported lexical escape leaves the original source in review only.
 */
export function arbitrateIndependentNonJson(raw:string,
  review?:IndependentReviewVeto):IndependentNonJsonResult {
  // Preserve the preceding layer's independent negative-evidence veto.
  if(review?.sourceIdentity==='MISMATCH'||review?.structuralProfile==='VETO'||
     review?.independentSourceTruth==='CONFLICT')
    return arbitrateSourceBody(raw,review);
  const prefix=CEF_BOUNDARY.exec(raw);
  if(!prefix)return arbitrateSourceBody(raw,review);
  const fallback:BodyArbitration={
    disposition:'ABSTAIN_UNSAFE',raw,sourceBytes:byteLength(raw),
    envelopeMode:'unframed',envelopeFields:[],
    selectedBodyGrammar:'none',bodyClaims:[],candidateGrammars:[],
    bodyReviewEvidence:'NOT_PROVEN',reason:'UNQUALIFIED_CEF_SOURCE',
    branchAttempts:1,maxBranchAttempts:8,
    autoPromoted:false,independentOracleCertified:false,nativeVerified:false,
  };
  if(!hasOnlyValidUnicode(raw)||raw.includes('\0')||
     byteLength(raw)>MAX_CEF_BYTES||/[\r\n]/.test(raw))
    return {...fallback,reason:'CEF_OUTSIDE_BOUNDED_SOURCE_CONTRACT'};
  const marker=prefix[0].length-4;
  const headers=readHeaders(raw,marker);
  if(!headers)return {...fallback,reason:'CEF_HEADER_UNSAFE_OR_INCOMPLETE'};
  const extensions=readExtensions(raw,headers.ext);
  const bodyClaims=[...headers.claims,...(extensions??[])];
  const completeExtensions=extensions!==null&&extensions.length>0;
  return {...fallback,disposition:completeExtensions?
      'REVIEW_ONLY_STRUCTURED_BODY':'REVIEW_ONLY_UNFRAMED',
    bodyClaims,selectedBodyGrammar:completeExtensions?'cef':'none',
    candidateGrammars:['cef'],
    bodyReviewEvidence:completeExtensions?'LEXICALLY_REPLAYED':'NOT_PROVEN',
    reason:completeExtensions?'CEF_SOURCE_LEXICAL_REVIEW_NOT_INDEPENDENT_TRUTH':
      'CEF_HEADER_ONLY_EXTENSION_UNSCORABLE',
    branchAttempts:3};
}
