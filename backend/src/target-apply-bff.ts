/** Server-injected, offline-only mock Apply gateway. Never opens network sockets. */
import type {IncomingMessage} from "node:http";
import type {ArtifactPackage} from "./artifact-package.js";
import type {PairExport} from "./types.js";
import {TargetDeploymentCoordinator,TargetDeploymentError,
  type TargetApplyResult} from "./target-deployment.js";

const SHA=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_.:@-]{1,128}$/;
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const NAME=/^customized_[a-z][a-z0-9_]{1,47}$/;
const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const APPROVAL=/^[A-Za-z0-9._-]{8,96}$/;
const denied=(code:string):never=>{throw new TargetDeploymentError(code);};

export type TargetApplyActor={id:string;tenant:string};
export type TargetApplyOwnedRevision={
  ownerId:string;tenant:string;pair:PairExport;artifact:ArtifactPackage;
};
export type TargetApplyStatus="NOT_ATTEMPTED"|"IN_PROGRESS"|
  "MOCK_READBACK_VERIFIED"|"DENIED"|"UNVERIFIED";
export type TargetApplyAuditEvent={
  phase:"BEFORE"|"AFTER";actorId:string;tenant:string;
  artifactRevisionId:string;
  status:"REQUESTED"|"MOCK_READBACK_VERIFIED"|"DENIED"|"UNVERIFIED";
};
export type TargetApplyMockGatewayOptions={
  mode:"MOCK_ONLY";
  authorize:(req:IncomingMessage)=>Promise<TargetApplyActor|null>;
  resolveRevision:(actor:TargetApplyActor,id:string)=>Promise<TargetApplyOwnedRevision|null>;
  getCoordinator:(actor:TargetApplyActor)=>Promise<TargetDeploymentCoordinator|null>;
  audit:(event:TargetApplyAuditEvent)=>Promise<void>;
};
export type TargetApplyHttpResult=TargetApplyResult & {
  mode:"MOCK_ONLY";status:"MOCK_READBACK_VERIFIED";realTargetVerified:false;
};
type ApplyInput={artifactRevisionId:string;expectedName:string;
  expectedVersion:string;approvalId:string;confirmed:true};
function validateInput(value:unknown):ApplyInput{
  if(!value||typeof value!=="object"||Array.isArray(value))
    return denied("TARGET_APPLY_REQUEST_INVALID");
  const v=value as Record<string,unknown>;
  if(Object.keys(v).sort().join(",")!==
     "approvalId,artifactRevisionId,confirmed,expectedName,expectedVersion"||
     typeof v["artifactRevisionId"]!=="string"||!SHA.test(v["artifactRevisionId"])||
     typeof v["expectedName"]!=="string"||!NAME.test(v["expectedName"])||
     typeof v["expectedVersion"]!=="string"||!VERSION.test(v["expectedVersion"])||
     typeof v["approvalId"]!=="string"||!APPROVAL.test(v["approvalId"])||
     v["confirmed"]!==true)return denied("TARGET_APPLY_REQUEST_INVALID");
  return v as ApplyInput;
}
const key=(a:TargetApplyActor,id:string)=>a.tenant+"|"+a.id+"|"+id;
export class TargetApplyMockGateway{
  #cfg:TargetApplyMockGatewayOptions;
  #statuses=new Map<string,{value:TargetApplyStatus;at:number}>();
  #busy=new Set<string>();
  constructor(cfg:TargetApplyMockGatewayOptions){
    if(!cfg||cfg.mode!=="MOCK_ONLY"||
       !["authorize","resolveRevision","getCoordinator","audit"]
         .every(k=>typeof cfg[k as keyof TargetApplyMockGatewayOptions]==="function"))
      denied("TARGET_APPLY_CONFIGURATION_INVALID");
    this.#cfg=cfg;
  }
  async authenticate(req:IncomingMessage):Promise<TargetApplyActor|null>{
    try{
      const actor=await this.#cfg.authorize(req);
      if(actor&&typeof actor.id==="string"&&ID.test(actor.id)&&
        typeof actor.tenant==="string"&&TENANT.test(actor.tenant))
        return {id:actor.id,tenant:actor.tenant};
    }catch{/* Deny on identity backend errors. */}
    return null;
  }
  #set(k:string,value:TargetApplyStatus){
    const now=Date.now();
    for(const [id,s] of this.#statuses){
      if(now-s.at>900000)this.#statuses.delete(id);
    }
    this.#statuses.delete(k);this.#statuses.set(k,{value,at:now});
    while(this.#statuses.size>128){
      const first=this.#statuses.keys().next().value;
      if(first===undefined)break;
      this.#statuses.delete(first);
    }
  }
  status(actor:TargetApplyActor,id:string){
    if(!SHA.test(id))denied("TARGET_APPLY_QUERY_INVALID");
    const state=this.#statuses.get(key(actor,id));
    return {contract:"target-apply-mock.v0.1",mode:"MOCK_ONLY",
      artifactRevisionId:id,status:state&&Date.now()-state.at<=900000
        ?state.value:"NOT_ATTEMPTED",ephemeral:true,realTargetVerified:false,
      sensorReadyVerified:false,targetImportVerified:false,
      realRuntimeParsingVerified:false};
  }
  async apply(actor:TargetApplyActor,value:unknown):Promise<TargetApplyHttpResult>{
    const input=validateInput(value);
    let owned:TargetApplyOwnedRevision|null=null;
    try{owned=await this.#cfg.resolveRevision(actor,input.artifactRevisionId);}
    catch{/* Private store errors are never returned. */}
    if(!owned||owned.ownerId!==actor.id||owned.tenant!==actor.tenant||
       owned.artifact?.manifest?.artifactRevisionId!==input.artifactRevisionId)
      return denied("TARGET_APPLY_REVISION_NOT_FOUND");
    if(owned.artifact.manifest.parserName!==input.expectedName||
       owned.artifact.manifest.version!==input.expectedVersion)
      return denied("TARGET_APPLY_VERSION_CONFLICT");
    let coordinator:TargetDeploymentCoordinator|null=null;
    try{coordinator=await this.#cfg.getCoordinator(actor);}
    catch{/* No target configuration leakage. */}
    if(!coordinator||coordinator.target.tenant!==actor.tenant)
      return denied("TARGET_APPLY_TARGET_UNAVAILABLE");
    if(!new URL(coordinator.target.origin).hostname.endsWith(".invalid"))
      return denied("TARGET_APPLY_MOCK_TARGET_REQUIRED");
    const k=key(actor,input.artifactRevisionId);
    if(this.#busy.has(k))denied("TARGET_APPLY_IN_FLIGHT");
    this.#busy.add(k);
    const event=(phase:TargetApplyAuditEvent["phase"],
      status:TargetApplyAuditEvent["status"]):TargetApplyAuditEvent=>({
        phase,status,actorId:actor.id,tenant:actor.tenant,
        artifactRevisionId:input.artifactRevisionId,
      });
    try{
      try{await this.#cfg.audit(event("BEFORE","REQUESTED"));}
      catch{this.#set(k,"DENIED");denied("TARGET_APPLY_AUDIT_UNAVAILABLE");}
      this.#set(k,"IN_PROGRESS");
      try{
        const result=await coordinator.create({
          artifact:owned.artifact,pair:owned.pair,
          expectedRevisionId:input.artifactRevisionId,
          confirmation:{approved:true,approvalId:input.approvalId,
            tenant:actor.tenant,targetOrigin:coordinator.target.origin,
            expectedName:input.expectedName},
        });
        try{await this.#cfg.audit(event("AFTER","MOCK_READBACK_VERIFIED"));}
        catch{this.#set(k,"UNVERIFIED");denied("TARGET_APPLY_AUDIT_UNAVAILABLE");}
        this.#set(k,"MOCK_READBACK_VERIFIED");
        return {...result,mode:"MOCK_ONLY",status:"MOCK_READBACK_VERIFIED",
          realTargetVerified:false};
      }catch(error){
        const code=error instanceof TargetDeploymentError?error.code:"TARGET_APPLY_FAILED";
        const state=/WRITE_UNCERTAIN|READBACK_UNVERIFIED|AUDIT_UNAVAILABLE/.test(code)
          ?"UNVERIFIED":"DENIED";
        this.#set(k,state);
        try{await this.#cfg.audit(event("AFTER",state));}
        catch{/* Preserve original redacted failure. */}
        if(error instanceof TargetDeploymentError)throw error;
        denied("TARGET_APPLY_FAILED");
      }
    }finally{this.#busy.delete(k);}
    return denied("TARGET_APPLY_FAILED");
  }
}
