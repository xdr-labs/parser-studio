/**
 * Testable general-tenant Legacy apply *coordination contract*, not an enabled
 * deployment endpoint. All target access, trust/DNS pinning, independently
 * approved write and audit are injected by the authorized backend operator.
 *
 * Product HTTP never creates this coordinator from a browser DP URL/key.
 * Real target credentials and any public API wiring remain owner-gated.
 */
import {isIP} from "node:net";
import {buildArtifactPackage,type ArtifactPackage} from "./artifact-package.js";
import type {PairExport} from "./types.js";

export class TargetDeploymentError extends Error{
  constructor(readonly code:string){super(code);this.name="TargetDeploymentError";}
}
function denied(code:string):never{throw new TargetDeploymentError(code);}
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const APPROVAL=/^[A-Za-z0-9._-]{8,96}$/;
const NAME=/^customized_[a-z][a-z0-9_]{1,47}$/;

export type TargetReference={origin:string;tenant:string};
export type TargetKnownParser={name:string;version:string;port:number};
export type TargetCatalogueEntry={name:string;port:number};
export type TargetInventoryGroup={complete:boolean;ports:number[]};
export type TargetWriteMethod="POST"|"PUT";
export type TargetOperationIntent={
  method:TargetWriteMethod;
  tenant:string;
  targetOrigin:string;
  name:string;
  version:string;
  port:number;
  artifactRevisionId:string;
  fileHashes:Record<string,string>;
  approvalId:string;
};
export type TargetDeploymentAudit={
  phase:"BEFORE"|"AFTER"|"FAILED";
  method:TargetWriteMethod;
  tenant:string;
  targetOrigin:string;
  name:string;
  artifactRevisionId:string;
  approvalId:string;
  status:"PREPARED"|"READBACK_VERIFIED"|"UNCERTAIN";
};
export type TargetWriteFile={filename:string;body:Buffer;sha256:string};
export type TargetWriteRequest={
  method:TargetWriteMethod;name:string;version:string;port:number;
  tenant:string;files:readonly TargetWriteFile[];
};
export type TargetDeploymentApi={
  listParsers:()=>Promise<TargetKnownParser[]>;
  listCatalogue:()=>Promise<TargetCatalogueEntry[]>;
  sensorBindings:()=>Promise<TargetInventoryGroup>;
  localReservations:()=>Promise<TargetInventoryGroup>;
  writePair:(intent:TargetWriteRequest)=>Promise<{httpStatus:number}>;
};
export type TargetApproval={
  approved:boolean;
  approvalId:string;
  targetOrigin:string;
  tenant:string;
  expectedName:string;
};
export type TargetCreateRequest={
  artifact:ArtifactPackage;
  pair:PairExport;
  expectedRevisionId:string;
  confirmation:TargetApproval;
};
export type TargetApplyResult={
  artifactRevisionId:string;
  fileHashes:Record<string,string>;
  name:string;
  tenant:string;
  origin:string;
  version:string;
  selectedParserPort:number;
  registration:{
    status:"API_REGISTERED_READBACK";
    apiReadbackVerified:true;
    realRuntimeParsingVerified:false;
    sensorReadyVerified:false;
    targetImportVerified:false;
  };
};
export interface TargetCoordinatorSettings{
  target:TargetReference;
  permittedOrigins:readonly string[];
  api:TargetDeploymentApi;
  approve:(intent:TargetOperationIntent)=>Promise<boolean>;
  audit:(record:TargetDeploymentAudit)=>Promise<void>;
  adminReservedPorts?:readonly number[];
}
export function validateDpTarget(value:string,allowed:readonly string[]):{origin:string}{
  if(typeof value!=="string"||!Array.isArray(allowed)||allowed.length<1)
    denied("TARGET_ORIGIN_UNAUTHORIZED");
  let parsed:URL;
  try{parsed=new URL(value);}catch{denied("TARGET_ORIGIN_INVALID");}
  if(parsed.protocol!=="https:"||parsed.username||parsed.password||
     parsed.pathname!=="/"||parsed.search||parsed.hash||
     !parsed.hostname||parsed.hostname==="localhost"||
     isIP(parsed.hostname.replace(/^\[|\]$/g,""))!==0||
     /(^|\.)localhost$/i.test(parsed.hostname)||
     parsed.origin!==value.replace(/\/$/,""))
    denied("TARGET_ORIGIN_INVALID");
  if(!allowed.includes(parsed.origin))denied("TARGET_ORIGIN_UNAUTHORIZED");
  return {origin:parsed.origin};
}
const active=new Set<string>();
function validPort(port:unknown):port is number{
  return typeof port==="number"&&Number.isInteger(port)&&port>=1&&port<=65535;
}
/** Local-only immutable pair and revision verification is always available. */
export function validateTargetArtifact(pair:PairExport,artifact:ArtifactPackage,
  expectedRevisionId:string):ArtifactPackage{
  if(!artifact||typeof artifact!=="object"||
     typeof expectedRevisionId!=="string"||
     expectedRevisionId!==artifact.manifest?.artifactRevisionId)
    denied("TARGET_ARTIFACT_REVISION_CONFLICT");
  let verified:ArtifactPackage;
  try{verified=buildArtifactPackage(pair,artifact.manifest.version);}
  catch{denied("TARGET_ARTIFACT_UNVERIFIED");}
  if(verified.manifest.artifactRevisionId!==expectedRevisionId||
     verified.zipSha256!==artifact.zipSha256||
     !verified.zip.equals(artifact.zip))
    denied("TARGET_ARTIFACT_MISMATCH");
  return verified;
}

export class TargetDeploymentCoordinator {
  readonly target:TargetReference;
  #cfg:TargetCoordinatorSettings;
  constructor(cfg:TargetCoordinatorSettings){
    if(!cfg||!cfg.target||typeof cfg.target.tenant!=="string"||
      !TENANT.test(cfg.target.tenant)||!cfg.api||
      typeof cfg.approve!=="function"||typeof cfg.audit!=="function"||
      !["listParsers","listCatalogue","sensorBindings","localReservations","writePair"]
        .every(key=>typeof cfg.api[key as keyof TargetDeploymentApi]==="function"))
      denied("TARGET_CONFIGURATION_INVALID");
    const v=validateDpTarget(cfg.target.origin,cfg.permittedOrigins);
    this.target={tenant:cfg.target.tenant,origin:v.origin};
    this.#cfg=cfg;
  }
  async #inventoryCheck(name:string,port:number):Promise<void>{
    let records:TargetKnownParser[],catalogue:TargetCatalogueEntry[],
      sensor:TargetInventoryGroup,reserved:TargetInventoryGroup;
    try{
      [records,catalogue,sensor,reserved]=await Promise.all([
        this.#cfg.api.listParsers(),this.#cfg.api.listCatalogue(),
        this.#cfg.api.sensorBindings(),this.#cfg.api.localReservations(),
      ]);
    }catch{denied("TARGET_INVENTORY_UNAVAILABLE");}
    if(!Array.isArray(records)||!Array.isArray(catalogue)||
      !sensor||!reserved||!Array.isArray(sensor.ports)||
      !Array.isArray(reserved.ports)||
      !records.every(x=>x&&NAME.test(x.name)&&
        typeof x.version==="string"&&validPort(x.port))||
      !catalogue.every(x=>x&&typeof x.name==="string"&&validPort(x.port))||
      !sensor.ports.every(validPort)||!reserved.ports.every(validPort))
      denied("TARGET_INVENTORY_INVALID");
    if(!sensor.complete||!reserved.complete)
      denied("TARGET_SENSOR_EVIDENCE_INCOMPLETE");
    if(records.some(x=>x.name===name))denied("TARGET_NAME_CONFLICT");
    const combined=[...catalogue.map(x=>x.port),...records.map(x=>x.port),
      ...sensor.ports,...reserved.ports,...(this.#cfg.adminReservedPorts??[])];
    if(combined.some(p=>!validPort(p)))
      denied("TARGET_INVENTORY_INVALID");
    if(combined.includes(port))denied("TARGET_PORT_CONFLICT");
  }
  async create(request:TargetCreateRequest):Promise<TargetApplyResult>{
    if(!request||!request.confirmation)denied("TARGET_CONFIRMATION_REQUIRED");
    const checked=validateTargetArtifact(request.pair,request.artifact,
      request.expectedRevisionId);
    const manifest=checked.manifest;
    const name=manifest.parserName;
    const confirmation=request.confirmation;
    if(confirmation.approved!==true||typeof confirmation.approvalId!=="string"||
      !APPROVAL.test(confirmation.approvalId))
      denied("TARGET_CONFIRMATION_REQUIRED");
    if(confirmation.targetOrigin!==this.target.origin||
      confirmation.tenant!==this.target.tenant||
      confirmation.expectedName!==name)
      denied("TARGET_CONFIRMATION_MISMATCH");
    if(!validPort(manifest.selectedParserPort)||!NAME.test(name))
      denied("TARGET_ARTIFACT_UNVERIFIED");
    const key=this.target.origin+"|"+this.target.tenant+"|"+name;
    if(active.has(key))denied("TARGET_APPLY_IN_FLIGHT");
    active.add(key);
    const intent:TargetOperationIntent={
      method:"POST",tenant:this.target.tenant,
      targetOrigin:this.target.origin,
      name,version:manifest.version,
      port:manifest.selectedParserPort,
      artifactRevisionId:manifest.artifactRevisionId,
      fileHashes:{...manifest.fileHashes},
      approvalId:confirmation.approvalId,
    };
    const audit=(phase:TargetDeploymentAudit["phase"],
      status:TargetDeploymentAudit["status"])=>this.#cfg.audit({
        phase,status,method:"POST",
        tenant:intent.tenant,targetOrigin:intent.targetOrigin,
        name:intent.name,artifactRevisionId:intent.artifactRevisionId,
        approvalId:intent.approvalId,
      });
    try{
      // Backend owns approval; browser approval checkbox alone cannot write.
      let approved=false;
      try{approved=await this.#cfg.approve(intent);}catch{/* deny */}
      if(!approved)denied("TARGET_APPROVAL_DENIED");
      await this.#inventoryCheck(name,manifest.selectedParserPort);
      // Approval is separate from evidence; repeat inventory just before
      // write to catch time-of-check changes (still not atomic remotely).
      await this.#inventoryCheck(name,manifest.selectedParserPort);
      try{await audit("BEFORE","PREPARED");}
      catch{denied("TARGET_AUDIT_UNAVAILABLE");}
      let response:{httpStatus:number};
      try{
        response=await this.#cfg.api.writePair({
          method:"POST",name,version:manifest.version,
          tenant:intent.tenant,port:manifest.selectedParserPort,
          files:request.pair.files.map(f=>({
            filename:f.name,body:Buffer.from(f.content,"utf8"),
            sha256:f.sha256,
          })),
        });
      }catch{
        try{await audit("FAILED","UNCERTAIN");}catch{/* avoid raw output */}
        denied("TARGET_WRITE_UNCERTAIN");
      }
      if(response.httpStatus!==200){
        try{await audit("FAILED","UNCERTAIN");}catch{/* redacted */}
        denied("TARGET_WRITE_UNCERTAIN");
      }
      let match:TargetKnownParser[]|null=null;
      try{
        const current=await this.#cfg.api.listParsers();
        match=current.filter(x=>x.name===name);
      }catch{/* readback unavailable */}
      if(match?.length!==1||
        match[0]?.version!==manifest.version||
        match[0]?.port!==manifest.selectedParserPort){
        try{await audit("FAILED","UNCERTAIN");}catch{/* redacted */}
        denied("TARGET_READBACK_UNVERIFIED");
      }
      try{await audit("AFTER","READBACK_VERIFIED");}
      catch{denied("TARGET_AUDIT_UNAVAILABLE");}
      return {
        artifactRevisionId:manifest.artifactRevisionId,
        fileHashes:{...manifest.fileHashes},name,tenant:intent.tenant,
        origin:intent.targetOrigin,version:manifest.version,
        selectedParserPort:manifest.selectedParserPort,
        registration:{
          status:"API_REGISTERED_READBACK",
          apiReadbackVerified:true,realRuntimeParsingVerified:false,
          sensorReadyVerified:false,targetImportVerified:false,
        },
      };
    }finally{active.delete(key);}
  }
}
