/**
 * Metadata-only before/after regression comparison for the fixed
 * reviewer-authored PUBLIC SYNTHETIC golden suite.
 *
 * Reports must originate from the separately qualified pinned native runner;
 * accepting report-shaped JSON is NOT independent evidence of that provenance.
 * Never accepts or returns event bodies, normalized values, credentials,
 * private customer fixtures, or real-target success assertions.
 */
const SHA=/^[0-9a-f]{64}$/;
const GIT_HEAD=/^[0-9a-f]{40}$/;
const CASE=/^[a-z][a-z0-9-]{1,63}$/;
const SLUG=/^sample_[a-z][a-z0-9_]{1,47}$/;
const KIND="parser-studio.synthetic-native-case-evidence.v0.1";
const ORIGIN="independently-authored-public-synthetic";
const STATUSES=new Set(["PASS","TIME_MISMATCH","RECORD_MISMATCH",
  "CALLBACK_COUNT","PARSER_EXCEPTION"]);
type NativeCaseStatus="PASS"|"TIME_MISMATCH"|"RECORD_MISMATCH"|
  "CALLBACK_COUNT"|"PARSER_EXCEPTION";
export type NativeCaseRecord={
  id:string;slug:string;status:NativeCaseStatus;outputSha256:string|null;
};
export type NativeCaseEvidence={
  kind:typeof KIND;
  origin:typeof ORIGIN;
  backendHead:string;
  fixtureSha256:string;
  ruby:"3.2";
  fluentd:"1.17.1";
  cases:NativeCaseRecord[];
  sensorTrafficSent:false;
  actualTdAgentOrStellarImport:false;
  targetImportVerified:false;
};
export type NativeCaseChange={
  id:string;slug:string;from:NativeCaseStatus;to:NativeCaseStatus;
};
export type NativeOutputChange={
  id:string;slug:string;fromSha256:string;toSha256:string;
};
export type NativeRegressionDiff={
  contract:"parser-studio.synthetic-native-regression.v0.1";
  status:"SYNTHETIC_IDENTICAL"|"SYNTHETIC_DIFFERENCE_DETECTED";
  origin:typeof ORIGIN;
  baselineHead:string;candidateHead:string;
  fixtureSha256:string;
  runtime:"ruby-3.2/fluentd-1.17.1";
  caseCount:number;unchanged:number;
  regressed:NativeCaseChange[];
  improved:NativeCaseChange[];
  changedOutputs:NativeOutputChange[];
  changedFailures:NativeCaseChange[];
  sensorTrafficSent:false;
  actualTdAgentOrStellarImport:false;
  targetImportVerified:false;
};
export class NativeRegressionError extends Error{
  constructor(readonly code:string){
    super(code);this.name="NativeRegressionError";
  }
}
const deny=(code:string):never=>{throw new NativeRegressionError(code);};
function isPlain(v:unknown):v is Record<string,unknown>{
  if(v===null||typeof v!=="object"||Array.isArray(v))return false;
  return Object.getPrototypeOf(v)===Object.prototype||
    Object.getPrototypeOf(v)===null;
}
function exact(v:unknown,keys:readonly string[]):v is Record<string,unknown>{
  return isPlain(v)&&Object.keys(v).length===keys.length&&
    Object.keys(v).every(key=>keys.includes(key));
}
const ROOT=["kind","origin","backendHead","fixtureSha256","ruby","fluentd",
  "cases","sensorTrafficSent","actualTdAgentOrStellarImport",
  "targetImportVerified"] as const;
const FIELDS=["id","slug","status","outputSha256"] as const;
export function validateSyntheticNativeCaseReport(raw:unknown):NativeCaseEvidence{
  if(!exact(raw,ROOT)||raw.kind!==KIND||raw.origin!==ORIGIN||
     typeof raw.backendHead!=="string"||!GIT_HEAD.test(raw.backendHead)||
     typeof raw.fixtureSha256!=="string"||!SHA.test(raw.fixtureSha256)||
     raw.ruby!=="3.2"||raw.fluentd!=="1.17.1"||
     raw.sensorTrafficSent!==false||
     raw.actualTdAgentOrStellarImport!==false||
     raw.targetImportVerified!==false||
     !Array.isArray(raw.cases)||raw.cases.length<1||raw.cases.length>64)
    return deny("REGRESSION_REPORT_INVALID");
  const keys=new Set<string>();
  const reportCases:NativeCaseRecord[]=[];
  for(const item of raw.cases){
    if(!exact(item,FIELDS)||
       typeof item.id!=="string"||!CASE.test(item.id)||
       typeof item.slug!=="string"||!SLUG.test(item.slug)||
       !STATUSES.has(item.status as string)||
       !((item.status==="CALLBACK_COUNT"||item.status==="PARSER_EXCEPTION")?
         item.outputSha256===null:
         typeof item.outputSha256==="string"&&SHA.test(item.outputSha256)))
      return deny("REGRESSION_REPORT_INVALID");
    if(keys.has(item.id))return deny("REGRESSION_REPORT_INVALID");
    keys.add(item.id);
    reportCases.push({
      id:item.id,slug:item.slug,status:item.status as NativeCaseStatus,
      outputSha256:item.outputSha256 as string|null,
    });
  }
  return {
    kind:KIND,origin:ORIGIN,
    backendHead:raw.backendHead,
    fixtureSha256:raw.fixtureSha256,
    ruby:"3.2",fluentd:"1.17.1",
    cases:reportCases,
    sensorTrafficSent:false,
    actualTdAgentOrStellarImport:false,targetImportVerified:false,
  };
}
export function compareSyntheticNativeCaseReports(
  baseline:unknown,candidate:unknown
):NativeRegressionDiff{
  const a=validateSyntheticNativeCaseReport(baseline);
  const b=validateSyntheticNativeCaseReport(candidate);
  if(a.fixtureSha256!==b.fixtureSha256)
    return deny("REGRESSION_FIXTURE_MISMATCH");
  if(a.ruby!==b.ruby||a.fluentd!==b.fluentd)
    return deny("REGRESSION_RUNTIME_MISMATCH");
  const orderedA=a.cases.slice().sort((x,y)=>x.id.localeCompare(y.id));
  const orderedB=b.cases.slice().sort((x,y)=>x.id.localeCompare(y.id));
  if(orderedA.length!==orderedB.length||
     orderedA.some((v,i)=>v.id!==orderedB[i]?.id||
       v.slug!==orderedB[i]?.slug))
    return deny("REGRESSION_CASE_SET_MISMATCH");
  const regressed:NativeCaseChange[]=[];
  const improved:NativeCaseChange[]=[];
  const changedOutputs:NativeOutputChange[]=[];
  const changedFailures:NativeCaseChange[]=[];
  let unchanged=0;
  for(const [i,before] of orderedA.entries()){
    const after=orderedB[i]!;
    if(before.status===after.status&&
       before.outputSha256===after.outputSha256){
      unchanged++;continue;
    }
    const change={id:before.id,slug:before.slug,
      from:before.status,to:after.status};
    if(before.status==="PASS"&&after.status!=="PASS"){
      regressed.push(change);
    }else if(before.status!=="PASS"&&after.status==="PASS"){
      improved.push(change);
    }else if(before.status==="PASS"&&after.status==="PASS"){
      changedOutputs.push({
        id:before.id,slug:before.slug,
        fromSha256:before.outputSha256!,toSha256:after.outputSha256!,
      });
    }else{
      changedFailures.push(change);
    }
  }
  const allSame=unchanged===orderedA.length;
  return {
    contract:"parser-studio.synthetic-native-regression.v0.1",
    status:allSame?"SYNTHETIC_IDENTICAL":"SYNTHETIC_DIFFERENCE_DETECTED",
    origin:ORIGIN,
    baselineHead:a.backendHead,candidateHead:b.backendHead,
    fixtureSha256:a.fixtureSha256,
    runtime:"ruby-3.2/fluentd-1.17.1",
    caseCount:orderedA.length,unchanged,
    regressed,improved,changedOutputs,changedFailures,
    sensorTrafficSent:false,
    actualTdAgentOrStellarImport:false,
    targetImportVerified:false,
  };
}
