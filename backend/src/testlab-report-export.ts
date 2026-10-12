/**
 * Deterministic, redacted, content-addressed export of an existing owner-only
 * offline Test Lab report. No raw sample values, credentials, destinations,
 * browser-supplied field contents or target-verification assertions accepted.
 * In-memory report download is not durable run recovery or live DP proof.
 */
import {createHash} from "node:crypto";

export class TestLabReportExportError extends Error{
  constructor(readonly code:string){super(code);this.name="TestLabReportExportError";}
}
const denied=():never=>{throw new TestLabReportExportError("EVIDENCE_EXPORT_INVALID");};
const RUN=/^test_run_[0-9a-f]{32}$/;
const SHA=/^[0-9a-f]{64}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const FORBIDDEN=new Set(["__proto__","constructor","prototype"]);
const COUNT_KEYS=["generated","sendAttempted","sinkAccepted","sensorObserved","dpIndexed","fieldCompared"];
const EVENT_KEYS=["sequence","generated","sendAttempted","sinkAccepted",
  "sensorObserved","dpIndexed","fieldComparison","fields","errorCode"];
const ROOT_KEYS=["contract","mode","runId","artifactRevisionId","expiresAt",
  "counts","events","realSensorVerified","runtimeParsingVerified","liveE2eVerified"];
const STATUS=new Set(["MATCH","MISMATCH","MISSING"]);
const ERRORS=new Set(["SEND_FAILED","SEND_TIMEOUT","SEND_ABORTED","SEND_OUTCOME_UNCERTAIN"]);
const own=(v:unknown):v is Record<string,unknown>=>{
  if(v===null||typeof v!=="object"||Array.isArray(v))return false;
  const p=Object.getPrototypeOf(v);
  return p===Object.prototype||p===null;
};
const exact=(v:unknown,keys:readonly string[]):v is Record<string,unknown>=>{
  return own(v)&&Object.keys(v).length===keys.length&&
    Object.keys(v).every(k=>keys.includes(k));
};
const isCount=(x:unknown)=>Number.isSafeInteger(x)&&
  typeof x==="number"&&x>=0&&x<=500;
const safeField=(v:unknown)=>typeof v==="string"&&FIELD.test(v)&&
  v.split(".").every(part=>part.length>0&&!FORBIDDEN.has(part));
function cleanEvents(raw:unknown):Array<Record<string,unknown>>{
  if(!Array.isArray(raw)||raw.length>500)return denied();
  const events:Array<Record<string,unknown>>=[];
  let last=-1;
  for(const input of raw){
    if(!exact(input,EVENT_KEYS))return denied();
    if(!Number.isSafeInteger(input.sequence)||typeof input.sequence!=="number"||
       input.sequence<0||input.sequence>=500||input.sequence<=last||
       input.generated!==true||typeof input.sendAttempted!=="boolean"||
       typeof input.sinkAccepted!=="boolean"||
       typeof input.sensorObserved!=="boolean"||
       typeof input.dpIndexed!=="boolean"||
       !Array.isArray(input.fields)||input.fields.length>16||
       !["NOT_VERIFIED","NO_FIELDS","FIELDS_MATCHED","FIELD_MISMATCH"].includes(
         input.fieldComparison as string)||
       (input.errorCode!==null&&!ERRORS.has(input.errorCode as string)))
      return denied();
    if(input.sinkAccepted&&!input.sendAttempted||
       (input.sensorObserved||input.dpIndexed)&&!input.sinkAccepted||
       input.errorCode!==null&&(!input.sendAttempted||input.sinkAccepted))denied();
    const fields:Array<{field:string;status:string}>=[];
    for(const f of input.fields){
      if(!exact(f,["field","status"])||!safeField(f.field)||
        !STATUS.has(f.status as string))denied();
      fields.push({field:f.field as string,status:f.status as string});
    }
    if(new Set(fields.map(f=>f.field)).size!==fields.length||
       fields.some((f,i)=>i>0&&fields[i-1]!.field.localeCompare(f.field)>=0))denied();
    const comparison=!input.dpIndexed?"NOT_VERIFIED":
      fields.length===0?"NO_FIELDS":
      fields.every(f=>f.status==="MATCH")?"FIELDS_MATCHED":"FIELD_MISMATCH";
    if(input.fieldComparison!==comparison||
       !input.dpIndexed&&fields.length!==0)denied();
    events.push({
      sequence:input.sequence,generated:true,
      sendAttempted:input.sendAttempted,sinkAccepted:input.sinkAccepted,
      sensorObserved:input.sensorObserved,dpIndexed:input.dpIndexed,
      fieldComparison:comparison,fields,errorCode:input.errorCode,
    });
    last=input.sequence as number;
  }
  return events;
}
export function exportRedactedEvidenceReport(input:unknown):{
  bytes:Buffer;sha256:string;filename:string
}{
  if(!exact(input,ROOT_KEYS)||
     input.contract!=="testlab-redacted-evidence.v0.1"||
     input.mode!=="OFFLINE_CONTRACT"||
     typeof input.runId!=="string"||!RUN.test(input.runId)||
     typeof input.artifactRevisionId!=="string"||!SHA.test(input.artifactRevisionId)||
     typeof input.expiresAt!=="string"||!TIME.test(input.expiresAt)||
     !Number.isFinite(Date.parse(input.expiresAt))||
     new Date(input.expiresAt).toISOString()!==input.expiresAt||
     input.realSensorVerified!==false||input.runtimeParsingVerified!==false||
     input.liveE2eVerified!==false||
     !exact(input.counts,COUNT_KEYS)||
     !COUNT_KEYS.every(k=>isCount((input.counts as Record<string,unknown>)[k])))
    return denied();
  const events=cleanEvents(input.events);
  const count={
    generated:events.length,
    sendAttempted:events.filter(e=>e.sendAttempted).length,
    sinkAccepted:events.filter(e=>e.sinkAccepted).length,
    sensorObserved:events.filter(e=>e.sensorObserved).length,
    dpIndexed:events.filter(e=>e.dpIndexed).length,
    fieldCompared:events.filter(e=>e.dpIndexed&&(e.fields as unknown[]).length>0).length,
  };
  if(COUNT_KEYS.some(k=>count[k as keyof typeof count]!==
    (input.counts as Record<string,unknown>)[k]))return denied();
  // Build canonical payload from allowlisted fields only. Never serialize
  // untrusted objects/errors or unknown properties into the exported file.
  const clean={
    contract:"testlab-redacted-evidence.v0.1",mode:"OFFLINE_CONTRACT",
    runId:input.runId,artifactRevisionId:input.artifactRevisionId,
    expiresAt:input.expiresAt,counts:count,events,
    realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false,
  };
  const bytes=Buffer.from(JSON.stringify(clean)+"\n","utf8");
  if(bytes.length>1024*1024)denied();
  return {
    filename:"testlab-evidence-"+input.runId+".json",
    sha256:createHash("sha256").update(bytes).digest("hex"),bytes
  };
}
