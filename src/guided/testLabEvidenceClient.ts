/** Explicit owner-scoped Test Lab evidence reports: offline metadata only.
 * Never send raw samples, credentials, vendor URLs, DP or sensor details.
 * A run ID is a locator, not an authorization token. Backend checks ownership.
 */
const BASE='/api/v1/test-lab/sessions/';
const RUN=/^test_run_[0-9a-f]{32}$/;
const SHA=/^[0-9a-f]{64}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const FAILURES=new Set(['SEND_FAILED','SEND_TIMEOUT','SEND_ABORTED','SEND_OUTCOME_UNCERTAIN']);
const FIELD_STATES=new Set(['MATCH','MISMATCH','MISSING']);
const COUNT_NAMES=['generated','sendAttempted','sinkAccepted','sensorObserved','dpIndexed','fieldCompared'] as const;
const MAX_BYTES=1024*1024;
export type EvidenceCounts=Record<typeof COUNT_NAMES[number],number>;
export type EvidenceSummary={
  contract:'testlab-redacted-summary.v0.1';
  mode:'OFFLINE_CONTRACT';runId:string;artifactRevisionId:string;
  expiresAt:string;comparisonStatus:'NOT_VERIFIED'|'OFFLINE_EVIDENCE_ONLY';
  counts:EvidenceCounts;
  failureGroups:Array<{errorCode:string;events:number}>;
  fieldCoverage:Array<{field:string;comparedEvents:number;matched:number;
    mismatched:number;missing:number;coveragePercent:number;matchPercent:number}>;
  realSensorVerified:false;runtimeParsingVerified:false;liveE2eVerified:false;
};
export type VerifiedEvidenceDownload={
  filename:string;content:string;sha256:string;artifactRevisionId:string;
  counts:EvidenceCounts;
};
const denied=():never=>{throw new Error('Untrusted or unsafe Test Lab evidence contract.');};
const validCount=(v:unknown)=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0&&v<=500;
const validPercent=(v:unknown)=>typeof v==='number'&&Number.isFinite(v)&&
  v>=0&&v<=100&&Math.abs(Math.round(v*100)-v*100)<1e-8;
const validTime=(v:unknown):v is string=>
  typeof v==='string'&&TIME.test(v)&&Number.isFinite(Date.parse(v))&&
  new Date(v).toISOString()===v;
const validField=(v:unknown):v is string=>typeof v==='string'&&FIELD.test(v)&&
  v.split('.').every(s=>s!==''&&s!=='__proto__'&&s!=='constructor'&&s!=='prototype');
function record(v:unknown):Record<string,unknown>{
  if(!v||typeof v!=='object'||Array.isArray(v)||
    (Object.getPrototypeOf(v)!==Object.prototype&&Object.getPrototypeOf(v)!==null))
    return denied();
  return v as Record<string,unknown>;
}
function exact(v:unknown,fields:readonly string[]):Record<string,unknown>{
  const obj=record(v);
  if(Object.keys(obj).length!==fields.length||
    Object.keys(obj).some(key=>!fields.includes(key))) return denied();
  return obj;
}
function counts(raw:unknown):EvidenceCounts{
  const values=exact(raw,COUNT_NAMES);
  if(COUNT_NAMES.some(k=>!validCount(values[k])))return denied();
  const c=values as EvidenceCounts;
  if(c.sendAttempted>c.generated||c.sinkAccepted>c.sendAttempted||
    c.sensorObserved>c.sinkAccepted||c.dpIndexed>c.sinkAccepted||
    c.fieldCompared>c.dpIndexed)return denied();
  return c;
}
function pct(part:number,total:number):number{
  return total===0?0:Math.round(part*10000/total)/100;
}
async function requestRead(action:'evidence-summary'|'evidence-export',
  runId:string,requester:typeof fetch):Promise<Response>{
  if(!RUN.test(runId))throw new Error('A valid owned Test Lab run ID is required.');
  const response=await requester(BASE+action+'?runId='+runId,{
    method:'GET',cache:'no-store',credentials:'same-origin',
    headers:{Accept:action==='evidence-export'?'application/json':'application/json'},
  });
  if(response.status!==200) {
    if(response.status===401||response.status===403)
      throw new Error('Test Lab evidence access denied or unavailable (HTTP '+response.status+').');
    throw new Error('Test Lab evidence request refused (HTTP '+response.status+').');
  }
  return response;
}
function summaryContract(data:unknown,runId:string):EvidenceSummary{
  const obj=exact(data,['contract','mode','runId','artifactRevisionId','expiresAt',
    'comparisonStatus','counts','failureGroups','fieldCoverage',
    'realSensorVerified','runtimeParsingVerified','liveE2eVerified']);
  if(obj.contract!=='testlab-redacted-summary.v0.1'||
    obj.mode!=='OFFLINE_CONTRACT'||obj.runId!==runId||
    typeof obj.artifactRevisionId!=='string'||!SHA.test(obj.artifactRevisionId)||
    !validTime(obj.expiresAt)||obj.realSensorVerified!==false||
    obj.runtimeParsingVerified!==false||obj.liveE2eVerified!==false)
    return denied();
  const c=counts(obj.counts);
  if(obj.comparisonStatus!==(c.dpIndexed===0?'NOT_VERIFIED':'OFFLINE_EVIDENCE_ONLY')||
    !Array.isArray(obj.failureGroups)||obj.failureGroups.length>4||
    !Array.isArray(obj.fieldCoverage)||obj.fieldCoverage.length>256)
    return denied();
  const failureCodes=new Set<string>();
  let failed=0;
  for(const entry of obj.failureGroups){
    const e=exact(entry,['errorCode','events']);
    if(typeof e.errorCode!=='string'||!FAILURES.has(e.errorCode)||
      failureCodes.has(e.errorCode)||!validCount(e.events)||e.events===0)return denied();
    failed+=(e.events as number);failureCodes.add(e.errorCode);
  }
  if(failed>c.sendAttempted-c.sinkAccepted)return denied();
  const fields=new Set<string>();
  for(const entry of obj.fieldCoverage){
    const e=exact(entry,['field','comparedEvents','matched','mismatched','missing',
      'coveragePercent','matchPercent']);
    if(!validField(e.field)||fields.has(e.field)||!validCount(e.comparedEvents)||
      !validCount(e.matched)||!validCount(e.mismatched)||!validCount(e.missing)||
      !validPercent(e.coveragePercent)||!validPercent(e.matchPercent)||
      e.comparedEvents===0||
      e.comparedEvents!==(e.matched as number)+(e.mismatched as number)+(e.missing as number)||
      (e.comparedEvents as number)>c.dpIndexed||
      e.coveragePercent!==pct(e.comparedEvents as number,c.dpIndexed)||
      e.matchPercent!==pct(e.matched as number,e.comparedEvents as number))
      return denied();
    fields.add(e.field);
  }
  if(c.fieldCompared===0&&fields.size>0||
    c.fieldCompared>0&&fields.size===0)return denied();
  return obj as unknown as EvidenceSummary;
}
export async function loadTestLabEvidenceSummary(runId:string,
  requester:typeof fetch=fetch):Promise<EvidenceSummary>{
  const response=await requestRead('evidence-summary',runId,requester);
  let data:unknown;
  try{data=await response.json();}catch{return denied();}
  return summaryContract(data,runId);
}
function evidenceReport(data:unknown,runId:string):{artifactRevisionId:string;counts:EvidenceCounts}{
  const obj=exact(data,['contract','mode','runId','artifactRevisionId','expiresAt',
    'counts','events','realSensorVerified','runtimeParsingVerified','liveE2eVerified']);
  if(obj.contract!=='testlab-redacted-evidence.v0.1'||obj.mode!=='OFFLINE_CONTRACT'||
    obj.runId!==runId||typeof obj.artifactRevisionId!=='string'||
    !SHA.test(obj.artifactRevisionId)||!validTime(obj.expiresAt)||
    obj.realSensorVerified!==false||obj.runtimeParsingVerified!==false||
    obj.liveE2eVerified!==false||!Array.isArray(obj.events)||
    obj.events.length>500)return denied();
  const c=counts(obj.counts);
  let previous=-1;
  const observed={generated:0,sendAttempted:0,sinkAccepted:0,
    sensorObserved:0,dpIndexed:0,fieldCompared:0};
  for(const item of obj.events){
    const e=exact(item,['sequence','generated','sendAttempted','sinkAccepted',
      'sensorObserved','dpIndexed','fieldComparison','fields','errorCode']);
    if(!validCount(e.sequence)||(e.sequence as number)>=500||
      (e.sequence as number)<=previous||e.generated!==true||
      typeof e.sendAttempted!=='boolean'||typeof e.sinkAccepted!=='boolean'||
      typeof e.sensorObserved!=='boolean'||typeof e.dpIndexed!=='boolean'||
      (e.errorCode!==null&&
        (typeof e.errorCode!=='string'||!FAILURES.has(e.errorCode)))||
      !Array.isArray(e.fields)||e.fields.length>16)return denied();
    previous=e.sequence as number;
    if(e.sinkAccepted&&!e.sendAttempted||
      (e.sensorObserved||e.dpIndexed)&&!e.sinkAccepted||
      e.errorCode!==null&&(!e.sendAttempted||e.sinkAccepted))return denied();
    const names=new Set<string>();
    let matched=0;
    for(const raw of e.fields){
      const f=exact(raw,['field','status']);
      if(!validField(f.field)||names.has(f.field)||
        typeof f.status!=='string'||!FIELD_STATES.has(f.status))return denied();
      names.add(f.field);if(f.status==='MATCH')matched++;
    }
    if(!e.dpIndexed&&e.fields.length>0)return denied();
    const expected=!e.dpIndexed?'NOT_VERIFIED':e.fields.length===0?'NO_FIELDS':
      matched===e.fields.length?'FIELDS_MATCHED':'FIELD_MISMATCH';
    if(e.fieldComparison!==expected)return denied();
    observed.generated++;
    if(e.sendAttempted)observed.sendAttempted++;
    if(e.sinkAccepted)observed.sinkAccepted++;
    if(e.sensorObserved)observed.sensorObserved++;
    if(e.dpIndexed)observed.dpIndexed++;
    if(e.dpIndexed&&e.fields.length>0)observed.fieldCompared++;
  }
  if(COUNT_NAMES.some(k=>c[k]!==observed[k]))return denied();
  return {artifactRevisionId:obj.artifactRevisionId,counts:c};
}
async function verifyHash(bytes:ArrayBuffer):Promise<string>{
  if(!globalThis.crypto?.subtle)throw new Error('Secure WebCrypto is required for evidence integrity.');
  const digest=await globalThis.crypto.subtle.digest('SHA-256',bytes);
  return [...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,'0')).join('');
}
export async function downloadTestLabEvidence(runId:string,requester:typeof fetch=fetch,
  expectedRevisionId?:string):Promise<VerifiedEvidenceDownload>{
  if(!globalThis.crypto?.subtle)throw new Error('Secure WebCrypto is required for evidence integrity.');
  if(expectedRevisionId!==undefined&&!SHA.test(expectedRevisionId))
    throw new Error('Expected artifact SHA identity is invalid.');
  const response=await requestRead('evidence-export',runId,requester);
  const length=response.headers.get('content-length');
  const sha=response.headers.get('x-parser-evidence-sha256');
  const filename='testlab-evidence-'+runId+'.json';
  if(response.headers.get('content-type')!=='application/json; charset=utf-8'||
    response.headers.get('content-disposition')!=='attachment; filename="'+filename+'"'||
    !length||!/^[1-9][0-9]*$/.test(length)||Number(length)>MAX_BYTES||
    !sha||!SHA.test(sha)||
    response.headers.get('cache-control')!=='no-store')
    throw new Error('Test Lab evidence attachment headers failed verification.');
  const bytes=await response.arrayBuffer();
  if(bytes.byteLength!==Number(length))return denied();
  const actualSha=await verifyHash(bytes);
  if(actualSha!==sha)return denied();
  let content:string,data:unknown;
  try{
    content=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    data=JSON.parse(content);
  }catch{return denied();}
  const safe=evidenceReport(data,runId);
  if(expectedRevisionId&&safe.artifactRevisionId!==expectedRevisionId)return denied();
  return {filename,content,sha256:actualSha,artifactRevisionId:safe.artifactRevisionId,
    counts:safe.counts};
}
