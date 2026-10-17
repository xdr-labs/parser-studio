import {arbitrateOptionalIndependentCsv} from './independentQuotedCsvSource';
import {type IndependentReviewVeto} from './boundedSourceBodyArbiter';

/** Vendor-neutral logfmt only after explicit publisher/transport grammar evidence. */
export interface LogfmtContext {
  recordFraming:'CONFIRMED_LOGFMT_SINGLE_RECORD'|'CONFIRMED_LOGFMT_BATCH_RECORDS';
}
export interface LogfmtSourceClaim {
  recordIndex:number;
  name:string;
  occurrence:number;
  path:string;
  value:string;
  rawValueSpan:string;
  startByte:number;
  endByte:number;
  evidence:'BOUNDED_LOGFMT_UTF8_SOURCE_REPLAY';
}
export interface LogfmtSourceResult {
  raw:string;sourceBytes:number;
  disposition:'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY_LOGFMT_LEXICAL'|'REVIEW_ONLY_PARTIAL';
  claims:LogfmtSourceClaim[];
  unsourcedBareKeys:number;
  recordsSeen:number;
  branchAttempts:number;maxBranchAttempts:8;
  reason:string;
  autoPromoted:false;independentOracleCertified:false;nativeVerified:false;
}
const utf8=new TextEncoder(),utf8Decoder=new TextDecoder('utf8',{fatal:true});
const LIMIT=16*1024,MAX_FIELDS=256,MAX_RECORDS=64;
const UNSAFE=new Set(['__proto__','prototype','constructor']);
const byteLength=(text:string)=>utf8.encode(text).length;
const whitespace=(c:string|undefined)=>c===' '||c==='\t';
const isRecordBoundary=(c:string|undefined)=>c==='\r'||c==='\n'||c==='\x1e';
function unicodeOkay(text:string):boolean{
  for(let i=0;i<text.length;i++){
    const c=text.charCodeAt(i);
    if(c>=0xd800&&c<=0xdbff){
      i++;if(i>=text.length||text.charCodeAt(i)<0xdc00||
        text.charCodeAt(i)>0xdfff)return false;
    }else if(c>=0xdc00&&c<=0xdfff)return false;
  }
  return true;
}
function safeKey(k:string):boolean{
  return byteLength(k)<=128&&/^[\p{L}_][\p{L}\p{N}_.-]*$/u.test(k)&&
    !UNSAFE.has(k)&&!UNSAFE.has(k.replaceAll('-','_'));
}
type Token={key:string;value:string|null;start:number;end:number;recordIndex:number};
function lex(raw:string,context:LogfmtContext):{
  fields:Token[];bare:number;adjacent:boolean;records:number
}|null{
  const batch=context.recordFraming==='CONFIRMED_LOGFMT_BATCH_RECORDS';
  const fields:Token[]=[];
  let pos=0,recordIndex=0,bare=0,adjacent=false,recordHadData=false;
  while(pos<raw.length){
    while(whitespace(raw[pos]))pos++;
    if(pos>=raw.length)break;
    if(isRecordBoundary(raw[pos])){
      if(!batch)return null;
      const first=raw[pos]!;
      pos++;
      if(first==='\r'&&raw[pos]==='\n')pos++;
      // RS is an explicit external record framing control, not a source value.
      while(raw[pos]==='\x1e')pos++;
      if(recordHadData){recordIndex++;recordHadData=false;}
      if(recordIndex>MAX_RECORDS)return null;
      continue;
    }
    const keyStart=pos;
    while(pos<raw.length&&!whitespace(raw[pos])&&!isRecordBoundary(raw[pos])&&raw[pos]!=='='){
      if(raw[pos]==='"'||raw[pos]==='\\'||raw[pos]==='\0')return null;
      pos++;
    }
    if(pos===keyStart)return null;
    const key=raw.slice(keyStart,pos);
    if(!safeKey(key))return null;
    recordHadData=true;
    if(raw[pos]!=='='){
      // No source value literal exists for bare keys. Never invent one.
      bare++;
      continue;
    }
    pos++;
    const sourceStart=pos;
    // Empty unquoted assignments mean nil in some original logfmt grammars
    // and an empty string in others. Without a pinned producer profile they
    // cannot support a universal field/value source-truth claim.
    if(pos===raw.length||whitespace(raw[pos])||isRecordBoundary(raw[pos])){
      bare++;continue;
    }
    let value='',closed=false;
    if(raw[pos]==='"'){
      pos++;
      while(pos<raw.length){
        const c=raw[pos]!;
        if(c==='"'){pos++;closed=true;break;}
        if(c==='\\'){
          const next=raw[pos+1];
          if(next===undefined)return null;
          const supported:{[key:string]:string}={
            t:'\t',n:'\n',r:'\r','"':'"', '\\':'\\'
          };
          if(!(next in supported))return null;
          value+=supported[next]!;
          pos+=2;continue;
        }
        const code=c.charCodeAt(0);
        if(code===0||code===127||code<32)return null;
        value+=c;pos++;
      }
      if(!closed)return null;
      if(pos<raw.length&&!whitespace(raw[pos])&&!isRecordBoundary(raw[pos])){
        // Adjacent assignments are permitted in a few original logfmt tests;
        // require a complete next key= token, not an arbitrary suffix.
        if(!/^[\p{L}_][\p{L}\p{N}_.-]*=/u.test(raw.slice(pos)))return null;
        adjacent=true;
      }
    }else{
      while(pos<raw.length&&!whitespace(raw[pos])&&!isRecordBoundary(raw[pos])){
        if(raw[pos]==='"'||raw[pos]==='\\'||raw[pos]==='\0')return null;
        pos++;
      }
      value=raw.slice(sourceStart,pos);
    }
    fields.push({key,value,start:sourceStart,end:pos,recordIndex});
    if(fields.length>MAX_FIELDS)return null;
  }
  const records=recordIndex+Number(recordHadData);
  // A final unterminated record is still a record. A 64-record stream with a
  // trailing separator is allowed, but a 65th record must always abstain.
  if(records>MAX_RECORDS)return null;
  return {fields,bare,adjacent,records};
}
function replay(raw:string,fields:Token[]):LogfmtSourceClaim[]|null{
  const source=utf8.encode(raw),seen=new Map<string,number>();
  const claims:LogfmtSourceClaim[]=[];
  for(const field of fields){
    const startByte=byteLength(raw.slice(0,field.start));
    const endByte=byteLength(raw.slice(0,field.end));
    if(startByte>endByte||endByte>source.length)return null;
    const lexical=utf8Decoder.decode(source.subarray(startByte,endByte));
    if(lexical!==raw.slice(field.start,field.end)||field.value===null)return null;
    // Replay the exact original lexical literal independently of the scanner.
    // No transport-dependent or vendor-specific unescape is allowed.
    if(lexical.startsWith('"')){
      let decoded:unknown;
      try{decoded=JSON.parse(lexical);}catch{return null;}
      if(decoded!==field.value)return null;
    }else if(lexical!==field.value)return null;
    const key=field.recordIndex+':'+field.key;
    const occurrence=seen.get(key)??0;
    seen.set(key,occurrence+1);
    claims.push({recordIndex:field.recordIndex,name:field.key,occurrence,
      path:'/body/logfmt/record'+field.recordIndex+'/'+
        field.key.replaceAll('~','~0').replaceAll('/','~1')+'#'+occurrence,
      value:field.value,rawValueSpan:lexical,startByte,endByte,
      evidence:'BOUNDED_LOGFMT_UTF8_SOURCE_REPLAY'});
  }
  return claims;
}
export function inspectIndependentLogfmt(
  raw:string,context?:LogfmtContext,review?:IndependentReviewVeto,
):LogfmtSourceResult{
  const fallback:LogfmtSourceResult={
    disposition:'RAW_ONLY',raw,sourceBytes:byteLength(raw),
    claims:[],unsourcedBareKeys:0,recordsSeen:0,branchAttempts:0,maxBranchAttempts:8,
    reason:'LOGFMT_SOURCE_GRAMMAR_NOT_INDEPENDENTLY_QUALIFIED',
    autoPromoted:false,independentOracleCertified:false,nativeVerified:false,
  };
  if(!context)return fallback;
  if(review?.sourceIdentity==='MISMATCH'||review?.structuralProfile==='VETO'||
     review?.independentSourceTruth==='CONFLICT')
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'INDEPENDENT_SOURCE_OR_PROFILE_VETO'};
  if(!raw||fallback.sourceBytes>LIMIT||!unicodeOkay(raw)||raw.includes('\0'))
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'LOGFMT_OUTSIDE_BOUNDED_ORIGINAL_BYTES'};
  const parsed=lex(raw,context);
  if(!parsed)return {...fallback,disposition:'ABSTAIN_UNSAFE',branchAttempts:1,
    reason:'AMBIGUOUS_LOGFMT_GRAMMAR_NO_SOURCE_CLAIMS'};
  const claims=replay(raw,parsed.fields);
  if(!claims||claims.length===0)
    return {...fallback,disposition:'RAW_ONLY',branchAttempts:2,
      unsourcedBareKeys:parsed.bare,recordsSeen:parsed.records,
      reason:'LOGFMT_NO_REPLAYABLE_NAMED_VALUE_LITERAL'};
  const partial=parsed.bare>0||parsed.adjacent||parsed.records>1;
  return {...fallback,disposition:partial?'REVIEW_ONLY_PARTIAL':'REVIEW_ONLY_LOGFMT_LEXICAL',
    claims,branchAttempts:2,unsourcedBareKeys:parsed.bare,recordsSeen:parsed.records,
    reason:partial?'LOGFMT_PARTIAL_OR_MULTIRECORD_LEXICAL_REVIEW_ONLY':
      'LOGFMT_LEXICAL_SOURCE_REVIEW_NOT_CERTIFIED'};
}
/** Unknown logs are NEVER implicitly treated as logfmt. */
export function arbitrateOptionalIndependentLogfmt(
  raw:string,context?:LogfmtContext,review?:IndependentReviewVeto,
){
  if(!context)return arbitrateOptionalIndependentCsv(raw,undefined,review);
  return inspectIndependentLogfmt(raw,context,review);
}
