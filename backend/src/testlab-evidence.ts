/**
 * Redacted, finite, offline run evidence. Never receives sample values,
 * credentials, sensor IPs, target URLs or raw Interflow records.
 * No default observer exists: mock callbacks are injected in tests only.
 * Independent sensor and DP observations MUST NOT be inferred from local sends.
 */
export class TestLabEvidenceError extends Error{
  constructor(readonly code:string){super(code);this.name="TestLabEvidenceError";}
}
const deny=(code:string):never=>{throw new TestLabEvidenceError(code);};
const RUN=/^test_run_[0-9a-f]{32}$/;
const SHA=/^[a-f0-9]{64}$/;
const ACTOR=/^[A-Za-z0-9_.:@-]{1,128}$/;
const RECEIPT=/^[A-Za-z0-9_.:-]{8,128}$/;
const FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const FORBIDDEN=new Set(["__proto__","constructor","prototype"]);
export type EvidenceFieldStatus={field:string;status:"MATCH"|"MISMATCH"|"MISSING"};
export type EvidenceWitness={
  receiptId:string;runId:string;sequence:number;artifactRevisionId:string;
};
export type EvidenceDpResponse={
  indexed:true;
  fields:EvidenceFieldStatus[];
};
export type EvidenceFailureCode="SEND_FAILED"|"SEND_TIMEOUT"|"SEND_ABORTED"|
  "SEND_OUTCOME_UNCERTAIN";
export type TestLabEvidenceOptions={
  now?:()=>number;
  maxRuns?:number;
  maxEventsPerRun?:number;
  ttlMs?:number;
  /** Independent, authenticated test-only sensor observer. */
  verifySensor?:(receipt:EvidenceWitness)=>Promise<boolean>;
  /** Independent, authenticated test-only DP query and redacted field comparison. */
  verifyDp?:(receipt:EvidenceWitness)=>Promise<EvidenceDpResponse|null>;
};
type Entry={
  sequence:number;
  sendAttempted:boolean;
  sinkAccepted:boolean;
  sensorObserved:boolean;
  dpIndexed:boolean;
  fieldComparison:"NOT_VERIFIED"|"FIELDS_MATCHED"|"FIELD_MISMATCH"|"NO_FIELDS";
  fields:EvidenceFieldStatus[];
  errorCode:EvidenceFailureCode|null;
};
type Run={
  owner:string;
  artifactRevisionId:string;
  createdAt:number;
  events:Map<number,Entry>;
};
function validateField(field:unknown):field is string{
  return typeof field==="string"&&FIELD.test(field)&&
    field.split(".").every(part=>part.length>0&&!FORBIDDEN.has(part));
}
export class TestLabEvidenceLedger{
  #runs=new Map<string,Run>();
  #now:()=>number;
  #maxRuns:number;
  #maxEvents:number;
  #ttl:number;
  #sensor?:TestLabEvidenceOptions["verifySensor"];
  #dp?:TestLabEvidenceOptions["verifyDp"];
  constructor(options:TestLabEvidenceOptions={}){
    this.#now=options.now??(()=>Date.now());
    this.#maxRuns=options.maxRuns??64;
    this.#maxEvents=options.maxEventsPerRun??500;
    this.#ttl=options.ttlMs??900000;
    this.#sensor=options.verifySensor;
    this.#dp=options.verifyDp;
    if(!Number.isInteger(this.#maxRuns)||this.#maxRuns<1||this.#maxRuns>256||
      !Number.isInteger(this.#maxEvents)||this.#maxEvents<1||this.#maxEvents>500||
      !Number.isSafeInteger(this.#ttl)||this.#ttl<250||this.#ttl>900000)
      deny("EVIDENCE_LIMITS_INVALID");
  }
  #expire():void{
    const now=this.#now();
    for(const [id,run] of this.#runs){
      if(now-run.createdAt>=this.#ttl)this.#runs.delete(id);
    }
  }
  #run(id:string,actor:string):Run{
    this.#expire();
    const run=this.#runs.get(id);
    if(!run||run.owner!==actor)return deny("EVIDENCE_RUN_NOT_FOUND");
    return run;
  }
  #event(id:string,actor:string,sequence:number):{run:Run;event:Entry}{
    const run=this.#run(id,actor);
    if(!Number.isSafeInteger(sequence)||sequence<0||sequence>=this.#maxEvents)
      deny("EVIDENCE_SEQUENCE_INVALID");
    const event=run.events.get(sequence);
    if(!event)return deny("EVIDENCE_STAGE_INVALID");
    return {run,event};
  }
  begin(id:string,actor:string,revision:string):void{
    this.#expire();
    if(typeof id!=="string"||!RUN.test(id)||
      typeof actor!=="string"||!ACTOR.test(actor)||
      typeof revision!=="string"||!SHA.test(revision))
      deny("EVIDENCE_RUN_INVALID");
    if(this.#runs.has(id))deny("EVIDENCE_RUN_EXISTS");
    if(this.#runs.size>=this.#maxRuns)deny("EVIDENCE_CAPACITY_EXCEEDED");
    this.#runs.set(id,{owner:actor,artifactRevisionId:revision,
      createdAt:this.#now(),events:new Map()});
  }
  generated(id:string,actor:string,sequence:number):void{
    const run=this.#run(id,actor);
    if(run.events.size>=this.#maxEvents)deny("EVIDENCE_CAPACITY_EXCEEDED");
    if(!Number.isSafeInteger(sequence)||sequence<0||sequence>=this.#maxEvents)
      deny("EVIDENCE_SEQUENCE_INVALID");
    if(run.events.has(sequence))deny("EVIDENCE_STAGE_DUPLICATE");
    run.events.set(sequence,{
      sequence,sendAttempted:false,sinkAccepted:false,
      sensorObserved:false,dpIndexed:false,fieldComparison:"NOT_VERIFIED",
      fields:[],errorCode:null,
    });
  }
  sendAttempted(id:string,actor:string,sequence:number):void{
    const {event}=this.#event(id,actor,sequence);
    if(event.sendAttempted)deny("EVIDENCE_STAGE_DUPLICATE");
    if(event.errorCode)deny("EVIDENCE_STAGE_INVALID");
    event.sendAttempted=true;
  }
  sinkAccepted(id:string,actor:string,sequence:number):void{
    const {event}=this.#event(id,actor,sequence);
    if(!event.sendAttempted||event.errorCode)deny("EVIDENCE_STAGE_INVALID");
    if(event.sinkAccepted)deny("EVIDENCE_STAGE_DUPLICATE");
    event.sinkAccepted=true;
  }
  failure(id:string,actor:string,sequence:number,code:EvidenceFailureCode):void{
    if(!["SEND_FAILED","SEND_TIMEOUT","SEND_ABORTED",
          "SEND_OUTCOME_UNCERTAIN"].includes(code))
      deny("EVIDENCE_FAILURE_CODE_INVALID");
    const {event}=this.#event(id,actor,sequence);
    if(!event.sendAttempted||event.sinkAccepted||event.errorCode)
      deny("EVIDENCE_STAGE_INVALID");
    event.errorCode=code;
  }
  #proof(run:Run,id:string,sequence:number,value:EvidenceWitness):void{
    if(!value||typeof value!=="object"||Array.isArray(value)||
       Object.keys(value).sort().join(",")!==
         "artifactRevisionId,receiptId,runId,sequence"||
       typeof value.receiptId!=="string"||!RECEIPT.test(value.receiptId)||
       value.runId!==id||value.sequence!==sequence||
       value.artifactRevisionId!==run.artifactRevisionId)
      deny("EVIDENCE_PROOF_INVALID");
  }
  async sensorObserved(id:string,actor:string,sequence:number,
    receipt:EvidenceWitness):Promise<void>{
    const {run,event}=this.#event(id,actor,sequence);
    if(!event.sinkAccepted)deny("EVIDENCE_STAGE_INVALID");
    if(event.sensorObserved)deny("EVIDENCE_STAGE_DUPLICATE");
    this.#proof(run,id,sequence,receipt);
    if(!this.#sensor)return deny("EVIDENCE_PROOF_UNAVAILABLE");
    let proven=false;
    try{proven=await this.#sensor(receipt)===true;}
    catch{/* Observer exception contains no usable proof. */}
    if(!proven)deny("EVIDENCE_PROOF_UNVERIFIED");
    const fresh=this.#event(id,actor,sequence).event;
    if(!fresh.sinkAccepted||fresh.sensorObserved)deny("EVIDENCE_STAGE_INVALID");
    fresh.sensorObserved=true;
  }
  async dpReadback(id:string,actor:string,sequence:number,
    receipt:EvidenceWitness):Promise<void>{
    const {run,event}=this.#event(id,actor,sequence);
    if(!event.sinkAccepted)deny("EVIDENCE_STAGE_INVALID");
    if(event.dpIndexed)deny("EVIDENCE_STAGE_DUPLICATE");
    this.#proof(run,id,sequence,receipt);
    if(!this.#dp)return deny("EVIDENCE_PROOF_UNAVAILABLE");
    let received:EvidenceDpResponse|null=null;
    try{received=await this.#dp(receipt);}
    catch{/* Never return raw DP payload/errors. */}
    if(!received||received.indexed!==true||
      !Array.isArray(received.fields)||received.fields.length>16||
      received.fields.some(x=>!x||!validateField(x.field)||
        !["MATCH","MISMATCH","MISSING"].includes(x.status))||
      new Set(received.fields.map(x=>x.field)).size!==received.fields.length)
      return deny("EVIDENCE_PROOF_UNVERIFIED");
    const fresh=this.#event(id,actor,sequence).event;
    if(!fresh.sinkAccepted||fresh.dpIndexed)deny("EVIDENCE_STAGE_INVALID");
    fresh.dpIndexed=true;
    fresh.fields=received.fields.map(x=>({field:x.field,status:x.status}))
      .sort((a,b)=>a.field.localeCompare(b.field));
    fresh.fieldComparison=fresh.fields.length===0?"NO_FIELDS":
      fresh.fields.every(x=>x.status==="MATCH")?"FIELDS_MATCHED":"FIELD_MISMATCH";
  }
  report(id:string,actor:string){
    const run=this.#run(id,actor);
    const events=[...run.events.values()].sort((a,b)=>a.sequence-b.sequence)
      .map(e=>({
        sequence:e.sequence,generated:true,sendAttempted:e.sendAttempted,
        sinkAccepted:e.sinkAccepted,sensorObserved:e.sensorObserved,
        dpIndexed:e.dpIndexed,fieldComparison:e.fieldComparison,
        fields:e.fields.map(f=>({...f})),errorCode:e.errorCode,
      }));
    return {
      contract:"testlab-redacted-evidence.v0.1",
      mode:"OFFLINE_CONTRACT",
      runId:id,
      artifactRevisionId:run.artifactRevisionId,
      expiresAt:new Date(run.createdAt+this.#ttl).toISOString(),
      counts:{
        generated:events.length,
        sendAttempted:events.filter(e=>e.sendAttempted).length,
        sinkAccepted:events.filter(e=>e.sinkAccepted).length,
        sensorObserved:events.filter(e=>e.sensorObserved).length,
        dpIndexed:events.filter(e=>e.dpIndexed).length,
        fieldCompared:events.filter(e=>e.dpIndexed&&e.fields.length>0).length,
      },
      events,
      realSensorVerified:false,
      runtimeParsingVerified:false,
      liveE2eVerified:false,
    };
  }
}
