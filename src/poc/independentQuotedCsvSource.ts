import {arbitrateIndependentLeef} from './independentLeefSource';
import {type IndependentReviewVeto} from './boundedSourceBodyArbiter';
import {readCsvSourceCells} from '../csvSourceCells';

/** Source byte extraction is allowed only when single-record CSV framing is independently established. */
export interface CsvRecordContext {
  recordFraming:'CONFIRMED_SINGLE_CSV_RECORD';
  headerRaw?:string;
  treatUnquotedEmptyAsNull?:boolean;
  /** Explicitly user/publisher-declared brace-field ordinals; NOT RFC4180. */
  declaredBracedGroupColumns?:readonly number[];
}
export interface CsvPositionalClaim {
  ordinal:number;
  value:string|null;
  valueType:'string'|'null';
  rawValueSpan:string;
  startByte:number;
  endByte:number;
  evidence:'BOUNDED_SOURCE_BYTE_AND_RFC4180_DECODE'|
    'BOUNDED_SOURCE_BYTE_AND_DECLARED_BRACED_GROUP';
}
export interface CsvNamedClaim extends CsvPositionalClaim {
  name:string;
  path:string;
  originalHeaderSpan:{startByte:number;endByte:number;rawValueSpan:string};
}
export interface CsvSourceResult {
  disposition:'RAW_ONLY'|'ABSTAIN_UNSAFE'|'REVIEW_ONLY_POSITIONAL'|'REVIEW_ONLY_NAMED';
  raw:string;
  sourceBytes:number;
  originalHeaderRaw:string|null;
  positionalClaims:CsvPositionalClaim[];
  namedClaims:CsvNamedClaim[];
  branchAttempts:number;
  maxBranchAttempts:8;
  reviewEvidence:'EXPLICIT_FRAMING_LEXICAL_ONLY'|
    'EXPLICIT_FRAMING_DECLARED_BRACED_GROUP_DIALECT'|'NOT_PROVEN';
  reason:string;
  autoPromoted:false;
  independentOracleCertified:false;
  nativeVerified:false;
}
import type {CsvSourceCell as Cell} from '../csvSourceCells';
const encoder=new TextEncoder();
const MAX_INPUT_BYTES=16*1024;
const UNSAFE_NAMES=new Set(['__proto__','prototype','constructor']);
const length=(raw:string)=>encoder.encode(raw).length;
function wellFormed(raw:string):boolean{
  for(let i=0;i<raw.length;i++){
    const c=raw.charCodeAt(i);
    if(c>=0xd800&&c<=0xdbff){
      i++;
      if(i>=raw.length||raw.charCodeAt(i)<0xdc00||raw.charCodeAt(i)>0xdfff)
        return false;
    }else if(c>=0xdc00&&c<=0xdfff)return false;
  }
  return true;
}
function replay(raw:string,cells:Cell[]):CsvPositionalClaim[]|null{
  const bytes=encoder.encode(raw);
  const out:CsvPositionalClaim[]=[];
  const decoder=new TextDecoder('utf-8',{fatal:true});
  for(let i=0;i<cells.length;i++){
    const c=cells[i]!;
    const startByte=length(raw.slice(0,c.start));
    const endByte=length(raw.slice(0,c.end));
    const lexical=decoder.decode(bytes.subarray(startByte,endByte));
    if(lexical!==raw.slice(c.start,c.end))return null;
    if(c.quoted&&
       (lexical.length<2||lexical[0]!=='"'||lexical[lexical.length-1]!=='"'||
        lexical.slice(1,-1).replaceAll('""','"')!==c.value))return null;
    if(!c.quoted&&c.value!==null&&lexical!==c.value)return null;
    if(!c.quoted&&c.value===null&&lexical!=='')return null;
    out.push({ordinal:i,value:c.value,valueType:c.value===null?'null':'string',
      rawValueSpan:lexical,startByte,endByte,
      evidence:c.bracedGroup?
        'BOUNDED_SOURCE_BYTE_AND_DECLARED_BRACED_GROUP':
        'BOUNDED_SOURCE_BYTE_AND_RFC4180_DECODE'});
  }
  return out;
}
export function inspectIndependentQuotedCsv(
  raw:string,context?:CsvRecordContext,review?:IndependentReviewVeto,
):CsvSourceResult{
  const fallback:CsvSourceResult={
    disposition:'RAW_ONLY',raw,sourceBytes:length(raw),
    originalHeaderRaw:context?.headerRaw??null,
    positionalClaims:[],namedClaims:[],branchAttempts:0,maxBranchAttempts:8,
    reviewEvidence:'NOT_PROVEN',reason:'CSV_FRAMING_NOT_INDEPENDENTLY_ESTABLISHED',
    autoPromoted:false,independentOracleCertified:false,nativeVerified:false,
  };
  if(!context)return fallback;
  if(review?.sourceIdentity==='MISMATCH'||review?.structuralProfile==='VETO'||
     review?.independentSourceTruth==='CONFLICT')
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'INDEPENDENT_SOURCE_OR_PROFILE_VETO'};
  const header=context.headerRaw;
  const declared=context.declaredBracedGroupColumns;
  // A non-RFC dialect must be externally declared with an ordered schema;
  // a filename, guessed vendor or delimiter-like prose is not qualification.
  if(declared!==undefined&&header===undefined)
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'DECLARED_GROUP_REQUIRES_EXPLICIT_SOURCE_COLUMN_SCHEMA'};
  if(!wellFormed(raw)||!raw||fallback.sourceBytes>MAX_INPUT_BYTES||
     (header!==undefined&&(!wellFormed(header)||!header||length(header)>MAX_INPUT_BYTES)))
    return {...fallback,disposition:'ABSTAIN_UNSAFE',
      reason:'CSV_OUTSIDE_BOUNDED_UTF8_SOURCE'};
  const row=readCsvSourceCells(raw,',',context.treatUnquotedEmptyAsNull===true,
    {declaredBracedGroupColumns:declared});
  if(!row)return {...fallback,disposition:'ABSTAIN_UNSAFE',branchAttempts:1,
    reason:'UNSAFE_OR_INDETERMINATE_CSV_RECORD'};
  const positional=replay(raw,row);
  if(!positional)return {...fallback,disposition:'ABSTAIN_UNSAFE',branchAttempts:1,
    reason:'CSV_SOURCE_BYTE_REPLAY_FAILED'};
  if(header===undefined)return {...fallback,disposition:'REVIEW_ONLY_POSITIONAL',
    positionalClaims:positional,branchAttempts:1,
    reviewEvidence:'EXPLICIT_FRAMING_LEXICAL_ONLY',
    reason:'CSV_POSITIONAL_ONLY_NO_SOURCE_COLUMN_NAMES'};
  const h=readCsvSourceCells(header,',',false);
  if(!h||h.length!==positional.length)
    return {...fallback,disposition:'ABSTAIN_UNSAFE',branchAttempts:2,
      reason:'CSV_HEADER_DATA_COLUMN_COUNT_MISMATCH'};
  if(declared?.some(column=>column>=h.length))
    return {...fallback,disposition:'ABSTAIN_UNSAFE',branchAttempts:2,
      reason:'DECLARED_GROUP_COLUMN_OUTSIDE_SOURCE_SCHEMA'};
  const headerSpans=replay(header,h);
  if(!headerSpans)return {...fallback,disposition:'ABSTAIN_UNSAFE',
    branchAttempts:2,reason:'CSV_HEADER_SOURCE_BYTE_REPLAY_FAILED'};
  const names=new Set<string>(),named:CsvNamedClaim[]=[];
  for(let i=0;i<headerSpans.length;i++){
    const original=headerSpans[i]!,value=positional[i]!;
    const name=original.value;
    if(typeof name!=='string'||!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(name)||
       UNSAFE_NAMES.has(name)||names.has(name.toLowerCase()))
      return {...fallback,disposition:'ABSTAIN_UNSAFE',branchAttempts:2,
        reason:'CSV_SOURCE_HEADER_DUPLICATE_OR_UNQUALIFIED'};
    names.add(name.toLowerCase());
    named.push({...value,name,
      path:'/body/csv/'+name.replaceAll('~','~0').replaceAll('/','~1'),
      originalHeaderSpan:{startByte:original.startByte,endByte:original.endByte,
        rawValueSpan:original.rawValueSpan}});
  }
  return {...fallback,disposition:'REVIEW_ONLY_NAMED',branchAttempts:2,
    positionalClaims:positional,namedClaims:named,
    reviewEvidence:declared?.length?
      'EXPLICIT_FRAMING_DECLARED_BRACED_GROUP_DIALECT':
      'EXPLICIT_FRAMING_LEXICAL_ONLY',
    reason:declared?.length?
      'CSV_DECLARED_BRACED_FIELD_LEXICAL_ONLY_NOT_NATIVE':
      'CSV_SOURCE_NAMED_FIELDS_REVIEW_NOT_CERTIFIED'};
}
/** Without verified CSV framing this composition is identical to the previous observer. */
export function arbitrateOptionalIndependentCsv(
  raw:string,context?:CsvRecordContext,review?:IndependentReviewVeto,
){
  if(!context)return arbitrateIndependentLeef(raw,review);
  return inspectIndependentQuotedCsv(raw,context,review);
}
