import {arbitrateIndependentNonJson,type IndependentNonJsonResult} from './independentNonJsonStructural';
import {type BodyArbitration,type IndependentReviewVeto,type SourceFieldClaim} from './boundedSourceBodyArbiter';

/**
 * Isolated LEEF source-byte observer beside the unchanged qualified product.
 * This proves only bounded lexical source literals, NEVER publisher semantics,
 * native Fluentd/Stellar execution or an automatically certified source parse.
 */
type LeefClaim=Omit<SourceFieldClaim,'grammar'> & {grammar:'leef'};
export type IndependentLeefResult=IndependentNonJsonResult | (
  Omit<BodyArbitration,'selectedBodyGrammar'|'candidateGrammars'|'bodyClaims'> & {
    selectedBodyGrammar:'leef'|'none';
    candidateGrammars:('leef'|'none')[];
    bodyClaims:LeefClaim[];
  }
);

const MAX_BYTES=8192;
const MAX_BODY_KEYS=256;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const RESERVED=new Set(['__proto__','prototype','constructor']);
const HEADER_KEYS=['version','vendor','product','product_version','event_id'] as const;
type WireState={headers:LeefClaim[];extensionsStart:number;delimiter:string};
function sourceBytes(raw:string):Uint8Array{return encoder.encode(raw);}
function wellFormedUnicode(raw:string):boolean{
  for(let p=0;p<raw.length;p++){
    const c=raw.charCodeAt(p);
    if(c>=0xd800&&c<=0xdbff){
      p++;
      if(p===raw.length||raw.charCodeAt(p)<0xdc00||raw.charCodeAt(p)>0xdfff)
        return false;
    }else if(c>=0xdc00&&c<=0xdfff)return false;
  }
  return true;
}
function field(raw:string,name:string,start:number,end:number,
  group:'header'|'extension',occurrence=0):LeefClaim|null {
  const fragment=raw.slice(start,end);
  if(!fragment||/\0/.test(fragment))return null;
  const startByte=encoder.encode(raw.slice(0,start)).length;
  const endByte=encoder.encode(raw.slice(0,end)).length;
  if(decoder.decode(sourceBytes(raw).slice(startByte,endByte))!==fragment)return null;
  return {layer:'body',grammar:'leef',
    path:'/body/leef/'+group+'/'+name.replaceAll('~','~0').replaceAll('/','~1')+'#'+occurrence,
    name,value:fragment,valueType:'string',startByte,endByte,
    rawSpanValue:fragment,evidence:'EXACT_RAW_SLICE',occurrence};
}
function parseHeader(raw:string):WireState|null {
  const found=/^LEEF:(1\.0|2\.0)\|/.exec(raw);
  if(!found)return null;
  const headers:LeefClaim[]=[];
  const version=field(raw,'version',5,5+found[1]!.length,'header');
  if(!version)return null;
  headers.push(version);
  let cursor=found[0].length;
  for(const key of HEADER_KEYS.slice(1)){
    const end=raw.indexOf('|',cursor);
    if(end<0||end===cursor||end-cursor>1024)return null;
    const fragment=raw.slice(cursor,end);
    // LEEF header escaping is not inferred from unqualified transport.
    if(/[\x00-\x1f\x7f\\]/.test(fragment))return null;
    const claim=field(raw,key,cursor,end,'header');
    if(!claim)return null;
    headers.push(claim);
    cursor=end+1;
  }
  if(found[1]==='1.0')return {headers,extensionsStart:cursor,delimiter:'\t'};
  const stop=raw.indexOf('|',cursor);
  if(stop<cursor||stop<0)return null;
  const delimiterToken=raw.slice(cursor,stop);
  // Only distinct, explicitly delimited LEEF 2.0 source formats.
  const delimiter=delimiterToken==='0x09'?'\t':
    /^[\^,:;~]$/.test(delimiterToken)?delimiterToken:'';
  if(!delimiter)return null;
  const type=field(raw,'delimiter',cursor,stop,'header');
  if(!type)return null;
  headers.push(type);
  return {headers,extensionsStart:stop+1,delimiter};
}
function parseExtensions(raw:string,start:number,delimiter:string):
  {claims:LeefClaim[];complete:boolean}|null {
  if(start===raw.length)return {claims:[],complete:false};
  const counts=new Map<string,number>();
  const claims:LeefClaim[]=[];
  let cursor=start,remaining=MAX_BODY_KEYS;
  while(cursor<raw.length){
    if(--remaining<0)return null;
    const next=raw.indexOf(delimiter,cursor);
    const end=next<0?raw.length:next;
    const part=raw.slice(cursor,end);
    const split=part.indexOf('=');
    if(split<=0||split===part.length-1)return null;
    const key=part.slice(0,split);
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(key)||RESERVED.has(key)||
       RESERVED.has(key.replaceAll('-','_')))return null;
    const startValue=cursor+split+1;
    const value=raw.slice(startValue,end);
    if(/[\x00-\x1f\x7f\\]/.test(value)||value.includes('"')||value.includes("'"))return null;
    const occurrence=counts.get(key)??0;
    counts.set(key,occurrence+1);
    const claim=field(raw,key,startValue,end,'extension',occurrence);
    if(!claim)return null;
    claims.push(claim);
    if(next<0)break;
    cursor=next+delimiter.length;
    if(cursor===raw.length)return null;
  }
  return {claims,complete:claims.length>0};
}

/**
 * Rejects unknown LEEF syntax conservatively; delegates every non-LEEF input to
 * the exact previously qualified source observer without changing its result.
 */
export function arbitrateIndependentLeef(raw:string,
  review?:IndependentReviewVeto):IndependentLeefResult {
  const base=()=>arbitrateIndependentNonJson(raw,review);
  if(!raw.startsWith('LEEF:'))return base();
  if(review?.sourceIdentity==='MISMATCH'||review?.structuralProfile==='VETO'||
     review?.independentSourceTruth==='CONFLICT')return base();
  const fallback:BodyArbitration={
    disposition:'ABSTAIN_UNSAFE',raw,sourceBytes:sourceBytes(raw).length,
    envelopeMode:'unframed',envelopeFields:[],
    selectedBodyGrammar:'none',bodyClaims:[],candidateGrammars:[],
    bodyReviewEvidence:'NOT_PROVEN',reason:'UNQUALIFIED_LEEF_ORIGINAL',
    branchAttempts:1,maxBranchAttempts:8,
    autoPromoted:false,independentOracleCertified:false,nativeVerified:false,
  };
  if(!wellFormedUnicode(raw)||raw.includes('\0')||/[\r\n]/.test(raw)||
     fallback.sourceBytes>MAX_BYTES)
    return {...fallback,reason:'LEEF_OUTSIDE_BOUNDED_ORIGINAL_BYTES'};
  const header=parseHeader(raw);
  if(!header)return {...fallback,reason:'LEEF_UNSUPPORTED_OR_INCOMPLETE_HEADER'};
  const body=parseExtensions(raw,header.extensionsStart,header.delimiter);
  const complete=body!==null&&body.complete;
  return {...fallback,disposition:complete?
       'REVIEW_ONLY_STRUCTURED_BODY':'REVIEW_ONLY_UNFRAMED',
    bodyClaims:[...header.headers,...(body?.claims??[])],
    selectedBodyGrammar:complete?'leef':'none',
    candidateGrammars:['leef'],bodyReviewEvidence:complete?'LEXICALLY_REPLAYED':'NOT_PROVEN',
    reason:complete?'LEEF_SYNTAX_ONLY_NOT_SOURCE_CERTIFIED':'LEEF_BODY_UNSCORABLE_HEADER_ONLY',
    branchAttempts:3};
}
