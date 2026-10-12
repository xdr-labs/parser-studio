/**
 * P0 Live Test Lab: bounded in-memory session loop with Stop/Pause/expiry.
 *
 * This is a reusable orchestration primitive, not an actual UDP/TCP sender.
 * No default network transport exists. Only an authorized backend/in-network
 * agent may inject a delivery callback and server-side approval policy.
 */
import {randomUUID} from "node:crypto";
import {createSyntheticPreview,SyntheticPreviewError,
  type SyntheticPreviewRequest} from "./testlab-synthetic.js";

export type TestLabState="RUNNING"|"PAUSED"|"STOPPED"|"EXPIRED"|"FAILED"|"COMPLETED";
export type TestLabStartRequest={
  sample:SyntheticPreviewRequest;
  approvalId:string;
  ratePerSecond:number;
  leaseMs:number;
  maxEvents:number;
};
export type TestLabSendContext={
  runId:string;
  sequence:number;
  signal:AbortSignal;
};
export type TestLabStatus={
  runId:string;
  state:TestLabState;
  sentCount:number;
  nextSequence:number;
  ratePerSecond:number;
  leaseExpiresAt:string;
  lastSentAt:string|null;
  errorCode:string|null;
  parserLifecycleNotModified:true;
  realSensorVerified:false;
  runtimeParsingVerified:false;
  sensorIngestVerified:false;
};
export type TestLabSessionConfig={
  /** Supplied by trusted backend, never by a browser alone. */
  approveStart?:(intent:{approvalId:string;runId:string;format:string;
    ratePerSecond:number;maxEvents:number;leaseMs:number})=>Promise<boolean>;
  /** Backend-controlled trusted sink; no default network implementation. */
  deliver?:(event:string,context:TestLabSendContext)=>Promise<void>;
  now?:()=>number;
  maxConcurrent?:number;
};
export class TestLabSessionError extends Error{
  constructor(readonly code:string){super(code);this.name="TestLabSessionError";}
}
function invalid(code:string):never{throw new TestLabSessionError(code);}
type ActiveSession={
  state:TestLabState;
  runId:string;
  ownerId:string|null;
  sample:SyntheticPreviewRequest;
  ratePerSecond:number;
  intervalMs:number;
  leaseDeadline:number;
  maxEvents:number;
  sentCount:number;
  nextSequence:number;
  lastSentAt:string|null;
  errorCode:string|null;
  cancellation:AbortController;
  tickTimer:ReturnType<typeof setTimeout>|null;
  expiryTimer:ReturnType<typeof setTimeout>|null;
};

export class SyntheticSessionController{
  #sessions=new Map<string,ActiveSession>();
  #pendingStarts=0;
  #closed=false;
  #approve?:TestLabSessionConfig["approveStart"];
  #deliver?:TestLabSessionConfig["deliver"];
  #now:()=>number;
  #maxConcurrent:number;
  constructor(config:TestLabSessionConfig){
    this.#approve=config.approveStart;
    this.#deliver=config.deliver;
    this.#now=config.now??(()=>Date.now());
    this.#maxConcurrent=config.maxConcurrent??2;
    if(!Number.isInteger(this.#maxConcurrent)||this.#maxConcurrent<1||
       this.#maxConcurrent>10)invalid("TESTLAB_CAPACITY_INVALID");
  }
  #activeCount(){
    return [...this.#sessions.values()].filter(x=>x.state==="RUNNING"||x.state==="PAUSED").length;
  }
  #public(session:ActiveSession):TestLabStatus{
    return {
      runId:session.runId,
      state:session.state,
      sentCount:session.sentCount,
      nextSequence:session.nextSequence,
      ratePerSecond:session.ratePerSecond,
      leaseExpiresAt:new Date(session.leaseDeadline).toISOString(),
      lastSentAt:session.lastSentAt,
      errorCode:session.errorCode,
      parserLifecycleNotModified:true,
      realSensorVerified:false,runtimeParsingVerified:false,
      sensorIngestVerified:false,
    };
  }
  #owned(runId:string,ownerId?:string):ActiveSession{
    const item=this.#sessions.get(runId);
    // Hide whether another actor's run exists; random run IDs are not auth.
    if(!item||(item.ownerId!==null&&item.ownerId!==ownerId))
      invalid("TESTLAB_SESSION_NOT_FOUND");
    return item;
  }
  status(runId:string,ownerId?:string):TestLabStatus{
    return this.#public(this.#owned(runId,ownerId));
  }
  #end(item:ActiveSession,state:TestLabState,errorCode:string|null=null){
    if(item.state==="STOPPED"||item.state==="COMPLETED"||
       item.state==="EXPIRED"||item.state==="FAILED")return;
    item.state=state;
    item.errorCode=errorCode;
    if(item.tickTimer)clearTimeout(item.tickTimer);
    if(item.expiryTimer)clearTimeout(item.expiryTimer);
    item.tickTimer=null;item.expiryTimer=null;
    item.cancellation.abort();
    // Clear source/sample from memory on every terminal state.
    item.sample={...item.sample,source:""};
  }
  stop(runId:string,ownerId?:string):TestLabStatus{
    const item=this.#owned(runId,ownerId);
    this.#end(item,"STOPPED");
    return this.#public(item);
  }
  stopAll():void{
    // Shutdown is terminal. A late asynchronous approval must never
    // resurrect sessions after the HTTP listener closes.
    this.#closed=true;
    for(const item of this.#sessions.values())this.#end(item,"STOPPED");
    this.#sessions.clear();
  }
  pause(runId:string,ownerId?:string):TestLabStatus{
    const item=this.#owned(runId,ownerId);
    if(item.state!=="RUNNING")invalid("TESTLAB_SESSION_NOT_RUNNING");
    item.state="PAUSED";
    if(item.tickTimer)clearTimeout(item.tickTimer);
    item.tickTimer=null;
    return this.#public(item);
  }
  resume(runId:string,ownerId?:string):TestLabStatus{
    const item=this.#owned(runId,ownerId);
    if(item.state!=="PAUSED")invalid("TESTLAB_SESSION_NOT_PAUSED");
    if(this.#now()>=item.leaseDeadline){
      this.#end(item,"EXPIRED");return this.#public(item);
    }
    item.state="RUNNING";
    this.#schedule(item,0);
    return this.#public(item);
  }
  #schedule(item:ActiveSession,delayMs:number){
    if(item.state!=="RUNNING")return;
    item.tickTimer=setTimeout(()=>{
      item.tickTimer=null;
      void this.#tick(item);
    },delayMs);
    item.tickTimer.unref?.();
  }
  async #tick(item:ActiveSession):Promise<void>{
    if(item.state!=="RUNNING")return;
    const now=this.#now();
    if(now>=item.leaseDeadline){this.#end(item,"EXPIRED");return;}
    try{
      const event=createSyntheticPreview({
        ...item.sample,sequence:item.nextSequence,
        ...(item.sample.runMarkerField===undefined?{}:{runId:item.runId}),
      },now);
      await this.#deliver!(event.syntheticEvent,{
        runId:item.runId,sequence:item.nextSequence,signal:item.cancellation.signal,
      });
      if(item.state!=="RUNNING"||item.cancellation.signal.aborted)return;
      item.sentCount++;
      item.nextSequence++;
      item.lastSentAt=new Date(this.#now()).toISOString();
      if(item.sentCount>=item.maxEvents){this.#end(item,"COMPLETED");return;}
      this.#schedule(item,item.intervalMs);
    }catch{
      // Never echo transport exceptions or original event values.
      this.#end(item,"FAILED","TESTLAB_SINK_FAILED");
    }
  }
  async start(input:TestLabStartRequest,ownerId?:string):Promise<TestLabStatus>{
    if(this.#closed)invalid("TESTLAB_SENDER_SHUTDOWN");
    if(ownerId!==undefined && (typeof ownerId!=="string"||
      !/^[A-Za-z0-9_.:@-]{1,128}$/.test(ownerId)))
      invalid("TESTLAB_OWNER_INVALID");
    if(!this.#approve||!this.#deliver)invalid("TESTLAB_SENDER_DISABLED");
    if(!input||!input.sample||typeof input.approvalId!=="string"||
      !/^[A-Za-z0-9_.-]{8,96}$/.test(input.approvalId)||
      !Number.isFinite(input.ratePerSecond)||input.ratePerSecond<0.2||
      input.ratePerSecond>5||
      !Number.isInteger(input.leaseMs)||input.leaseMs<250||
      input.leaseMs>900000||
      !Number.isInteger(input.maxEvents)||input.maxEvents<1||
      input.maxEvents>3000)invalid("TESTLAB_LIMITS_INVALID");
    // Reserve capacity while awaiting the independent asynchronous approval.
    // Without this, concurrent Start calls can both pass the first check.
    if(this.#activeCount()+this.#pendingStarts>=this.#maxConcurrent)
      invalid("TESTLAB_CAPACITY_REACHED");
    if(input.sample.runId!==undefined)invalid("TESTLAB_RUN_ID_RESERVED");
    this.#pendingStarts++;
    try{
    const runId="test_run_"+randomUUID().replace(/-/g,"");
    const now=this.#now();
    let allowed=false;
    try{
      allowed=await this.#approve({
        approvalId:input.approvalId,runId,format:input.sample.format,
        ratePerSecond:input.ratePerSecond,maxEvents:input.maxEvents,
        leaseMs:input.leaseMs,
      });
    }catch{/* Trusted approval service failure means deny. */}
    if(this.#closed)invalid("TESTLAB_SENDER_SHUTDOWN");
    if(allowed!==true)invalid("TESTLAB_START_DENIED");
    // Validate the grammar/field selection before any delivery.
    const sample={...input.sample,sequence:0,
      ...(input.sample.runMarkerField===undefined?{}:{runId})};
    try{createSyntheticPreview(sample,now);}
    catch(error){
      if(error instanceof SyntheticPreviewError)invalid(error.code);
      invalid("TESTLAB_SAMPLE_INVALID");
    }
    if(this.#sessions.size>500){
      for(const [id,item] of this.#sessions){
        if(["STOPPED","COMPLETED","EXPIRED","FAILED"].includes(item.state)){
          this.#sessions.delete(id);
          if(this.#sessions.size<=400)break;
        }
      }
      if(this.#sessions.size>500)invalid("TESTLAB_HISTORY_CAPACITY");
    }
    const item:ActiveSession={
      runId,ownerId:ownerId??null,state:"RUNNING",sample,
      ratePerSecond:input.ratePerSecond,intervalMs:Math.ceil(1000/input.ratePerSecond),
      leaseDeadline:now+input.leaseMs,maxEvents:input.maxEvents,
      sentCount:0,nextSequence:0,lastSentAt:null,errorCode:null,
      cancellation:new AbortController(),tickTimer:null,expiryTimer:null,
    };
    this.#sessions.set(runId,item);
    item.expiryTimer=setTimeout(()=>this.#end(item,"EXPIRED"),input.leaseMs);
    item.expiryTimer.unref?.();
    this.#schedule(item,0);
    return this.#public(item);
    }finally{
      this.#pendingStarts--;
    }
  }
}
