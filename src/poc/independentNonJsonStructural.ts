import {arbitrateSourceBody,type BodyArbitration,type SourceFieldClaim,
  type IndependentReviewVeto} from './boundedSourceBodyArbiter';
import {scanCefStandardHeaderGrammar} from '../cefStandardHeaderGrammar';
import {scanCefStandardExtensions} from '../cefStandardExtensionGrammar';

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
/**
 * An unqualified RFC3164-shaped preamble is not treated as a certified
 * envelope. It only allows an explicitly delimited CEF token to be inspected.
 */
const CEF_BOUNDARY=/^(?:[A-Z][a-z]{2} +(?:[1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [A-Za-z0-9_.-]{1,255} )?CEF:/;
function hasOnlyValidUnicode(raw:string):boolean {
  for(let i=0;i<raw.length;i++){
    const unit=raw.charCodeAt(i);
    if(unit>=0xd800&&unit<=0xdbff){
      if(++i>=raw.length||raw.charCodeAt(i)<0xdc00||raw.charCodeAt(i)>0xdfff)return false;
    }else if(unit>=0xdc00&&unit<=0xdfff)return false;
  }
  return true;
}
function claimFromOriginal(
  raw:string,name:string,decoded:string,rawLexeme:string,
  startByte:number,endByte:number,
  section:'header'|'extension',occurrence=0,
):CefField|null{
  const bytes=new TextEncoder().encode(raw);
  if(startByte<0||endByte<startByte||endByte>bytes.length)return null;
  if(new TextDecoder('utf8',{fatal:true}).decode(
    bytes.subarray(startByte,endByte))!==rawLexeme)return null;
  return {layer:'body',grammar:'cef',path:'/body/cef/'+
    section+'/'+name.replaceAll('~','~0').replaceAll('/','~1')+
    '#'+String(occurrence),
    name,value:decoded,valueType:'string',startByte,endByte,
    rawSpanValue:rawLexeme,evidence:'EXACT_RAW_SLICE',occurrence};
}
function readHeaders(raw:string,start:number):{claims:CefField[];ext:number}|null{
  const parsed=scanCefStandardHeaderGrammar(raw,start);
  if(!parsed.ok)return null;
  const claims:CefField[]=[];
  for(const entry of parsed.fields){
    const key=entry.name==='cefVersion'?'version':entry.name;
    const claim=claimFromOriginal(raw,key,entry.decoded,entry.sourceLexeme,
      entry.startByte,entry.endByte,'header');
    if(claim===null)return null;
    claims.push(claim);
  }
  return {claims,ext:parsed.extensionStart};
}
function readExtensions(raw:string,start:number):CefField[]|null{
  if(start===raw.length)return [];
  const parsed=scanCefStandardExtensions(raw,start,
    {preserveRepeatedForReview:true});
  if(!parsed.ok)return null;
  const claims:CefField[]=[];
  for(const entry of parsed.fields){
    // Without a producer contract, empty CEF may mean absent or null.
    // Preserve original record but do not invent a typed field claim.
    if(!entry.rawValueLexeme)continue;
    const claim=claimFromOriginal(
      raw,entry.name,entry.decodedValue,entry.rawValueLexeme,
      entry.valueStartByte,entry.valueEndByte,'extension',entry.occurrence,
    );
    if(claim===null)return null;
    claims.push(claim);
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
