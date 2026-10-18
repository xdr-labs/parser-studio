/**
 * POC-only Legacy Custom Parser REST client, based on independently verified
 * PR #8/#9/#10 on owner-approved POC. Never handles modular activation.
 * No traffic occurs at construction. No write is enabled without BOTH
 * backend-only approval and audit functions and explicit per-action consent.
 */
import {LEGACY_POC_CAPABILITIES,LegacyContractError,
  LegacyUploadPlan,requireDisposablePocWrite} from "./stellar-legacy-plan.js";
import {buildInterflowQuery,compareInterflowHits,
  type InterflowSearchRequest,type InterflowFieldResult} from "./stellar-interflow.js";

const PREFIX="/connect/api/v1";
const MAX_RESPONSE_BYTES=2*1024*1024;
const JWT_REFRESH_MS=8*60*1000;
const NAME=/^[A-Za-z0-9_.-]{1,96}$/; // listings may include legacy non-customized test metadata
const TEST_NAME=/^customized_ps_api_crud_test_[0-9a-f]{6,16}$/;
const VERSION=/^[A-Za-z0-9._/-]{1,64}$/;
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const APPROVAL_ID=/^[A-Za-z0-9_.-]{3,96}$/;
const OWN_HOST=LEGACY_POC_CAPABILITIES.allowedHost;
function err(code:string):never{throw new LegacyContractError(code);}
export class LegacyApiError extends Error{
  constructor(readonly method:string, readonly httpStatus:number){
    super("POC_"+method+"_HTTP_"+httpStatus);this.name="LegacyApiError";
  }
}
export type LegacyParserMetadata={name:string;version:string;port?:number};
export type LegacyCatalogueRecord={name?:string;port?:number};
export type LegacyOperation="POST"|"PUT"|"DELETE"|"CLEANUP";
export type LegacyWriteIntent={
  method:LegacyOperation;tenant:string;name:string;version:string;
  approvalId:string;expectedVersion?:string;port?:number;
  parserSha256?:string;confSha256?:string;
};
export type LegacyAuditEvent={
  phase:"BEFORE"|"AFTER"|"FAILED"|"CLEANUP";
  method:LegacyOperation;tenant:string;name:string;
  version:string;approvalId:string;httpStatus?:number;
  apiRegistrationVerified:boolean;runtimeParsingVerified:false;targetImportVerified:false;
};
export type LegacyOperationResult={
  method:"POST"|"PUT"|"DELETE";name:string;version:string;
  httpStatus:200;apiRegistrationVerified:true;
  runtimeParsingVerified:false;targetImportVerified:false;
  modularActivationVerified:false;approvalId:string;
};

export interface LegacyPocClientConfig{
  host:string;tenant:string;apiKey:string;fetchImpl?:typeof fetch;
  clock?:()=>number;
  /** Must be injected by trusted backend service, never derived from UI flag. */
  approveWrite?:(intent:LegacyWriteIntent)=>Promise<boolean>;
  /** Must be durable/operator-owned before this client may write. */
  audit?:(event:LegacyAuditEvent)=>Promise<void>;
}

export type WriteConfirmation={
  confirmed:boolean;approvalId:string;
  expectedVersion?:string;
};

function readJsonBounded(response:Response):Promise<unknown>{
  return response.arrayBuffer().then(bytes=>{
    if(bytes.byteLength>MAX_RESPONSE_BYTES)err("POC_RESPONSE_TOO_LARGE");
    try{
      return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)) as unknown;
    }catch{err("POC_RESPONSE_INVALID");}
  });
}
function isRecord(x:unknown):x is Record<string,unknown>{
  return x!==null&&typeof x==="object"&&!Array.isArray(x);
}

export class LegacyPocClient{
  readonly host:string;
  readonly tenant:string;
  #key:string;
  #jwt:string|null=null;
  #jwtAt:number|null=null;
  #fetch:typeof fetch;
  #clock:()=>number;
  #approveWrite?:LegacyPocClientConfig["approveWrite"];
  #audit?:LegacyPocClientConfig["audit"];

  constructor(opts:LegacyPocClientConfig){
    if(!opts||opts.host!==OWN_HOST)err("POC_HOST_UNAUTHORIZED");
    if(typeof opts.tenant!=="string"||!TENANT.test(opts.tenant))err("POC_TENANT_INVALID");
    if(typeof opts.apiKey!=="string"||!opts.apiKey||
      opts.apiKey.length>8192)err("POC_KEY_UNAVAILABLE");
    this.host=OWN_HOST;this.tenant=opts.tenant;
    this.#key=opts.apiKey;
    this.#fetch=opts.fetchImpl??fetch;
    this.#clock=opts.clock??(()=>Date.now());
    this.#approveWrite=opts.approveWrite;this.#audit=opts.audit;
  }
  toJSON(){return {host:this.host,configured:true,writesEnabled:!!(this.#approveWrite&&this.#audit)};}

  async #send(path:string,method:string,token:string,body?:FormData,contentType?:string):Promise<Response>{
    const headers:Record<string,string>={Authorization:"Bearer "+token,Accept:"application/json"};
    if(contentType)headers["content-type"]=contentType;
    try{
      return await this.#fetch(this.host+PREFIX+path,{
        method,headers,body,redirect:"manual",signal:AbortSignal.timeout(25000),
      });
    }catch{
      err("POC_NETWORK_FAILURE");
    }
  }

  async #auth(force=false):Promise<string>{
    const now=this.#clock();
    if(!force&&this.#jwt!==null&&this.#jwtAt!==null&&
      now-this.#jwtAt>=0&&now-this.#jwtAt<JWT_REFRESH_MS)return this.#jwt;
    const reply=await this.#send("/access_token","POST",this.#key);
    if(reply.status!==200)throw new LegacyApiError("AUTH",reply.status);
    const data=await readJsonBounded(reply);
    if(!isRecord(data)||typeof data.access_token!=="string"||
      !data.access_token||data.access_token.length>8192)err("POC_AUTH_RESPONSE_INVALID");
    this.#jwt=data.access_token;this.#jwtAt=this.#clock();
    return this.#jwt;
  }

  async #request(path:string,method:"GET"|"POST"|"PUT"|"DELETE",body?:FormData):Promise<Response>{
    let result=await this.#send(path,method,await this.#auth(),body);
    if(method==="GET"&&result.status===401){
      // Only idempotent reads get a single token refresh + retry.
      result=await this.#send(path,method,await this.#auth(true),body);
    }
    if(result.status!==200)throw new LegacyApiError(method,result.status);
    return result;
  }

  async #rows(path:string):Promise<Record<string,unknown>[]>{
    const response=await this.#request(path+"?"+new URLSearchParams({cust_id:this.tenant}),"GET");
    const payload=await readJsonBounded(response);
    if(!isRecord(payload)||!Array.isArray(payload.data)||
      payload.data.length>10000||!payload.data.every(isRecord))err("POC_LIST_RESPONSE_INVALID");
    return payload.data as Record<string,unknown>[];
  }

  async listParsers():Promise<LegacyParserMetadata[]>{
    const data=await this.#rows("/custom_log_parsers");
    const out:LegacyParserMetadata[]=[];
    for(const item of data){
      if(item.cust_id!==undefined&&item.cust_id!==this.tenant)continue;
      if(typeof item.parser_name!=="string"||!NAME.test(item.parser_name)||
        item.version===undefined)err("POC_PARSER_METADATA_INVALID");
      const ver=String(item.version);
      if(!VERSION.test(ver))err("POC_PARSER_METADATA_INVALID");
      if(item.port!==undefined&&(!Number.isInteger(item.port)||
        (item.port as number)<1||(item.port as number)>65535))
        err("POC_PARSER_METADATA_INVALID");
      out.push({name:item.parser_name as string,version:ver,
        ...(item.port===undefined?{}:{port:item.port as number})});
    }
    return out;
  }

  /**
   * Strict User Scope GET-only Interflow query: bounded tenant, run marker,
   * timestamp range and index. Reuses the privately cached JWT.
   * POC evidence has NOT established raw search permissions for this key.
   */
  async searchInterflow(request:InterflowSearchRequest,
    expected:Record<string,string|number|boolean>):Promise<InterflowFieldResult>{
    const plan=buildInterflowQuery(this.tenant,request);
    const route=plan.path+"?"+plan.params.toString();
    // Exact generated path uses a known index; NEVER accept a raw URL.
    const get=async(token:string):Promise<Response>=>{
      try{
        return await this.#fetch(this.host+route,{
          method:"GET",redirect:"manual",
          headers:{Authorization:"Bearer "+token,Accept:"application/json"},
          signal:AbortSignal.timeout(25000),
        });
      }catch{err("POC_NETWORK_FAILURE");}
    };
    let result=await get(await this.#auth());
    if(result.status===401)result=await get(await this.#auth(true));
    if(result.status!==200)throw new LegacyApiError("INTERFLOW_GET",result.status);
    const payload=await readJsonBounded(result);
    return compareInterflowHits(payload,plan,expected);
  }

  async listCatalogue():Promise<LegacyCatalogueRecord[]>{
    const rows=await this.#rows("/custom_log_parsers/parsers");
    return rows.map(record=>{
      if(record.cust_id!==undefined&&record.cust_id!==this.tenant)
        err("POC_TENANT_MISMATCH");
      if(record.port!==undefined&&(!Number.isInteger(record.port)||
        (record.port as number)<1||(record.port as number)>65535))
        err("POC_CATALOGUE_INVALID");
      if(record.parser_name!==undefined&&
        (typeof record.parser_name!=="string"||
          !NAME.test(record.parser_name)))err("POC_CATALOGUE_INVALID");
      return { ...(record.parser_name===undefined?{}:{name:record.parser_name as string}),
        ...(record.port===undefined?{}:{port:record.port as number})};
    });
  }

  #testName(name:string){
    if(!TEST_NAME.test(name))err("POC_NAME_UNSAFE");
  }
  async #approval(intent:LegacyWriteIntent,opts:WriteConfirmation){
    if(opts.confirmed!==true||!APPROVAL_ID.test(opts.approvalId))
      err("POC_CONFIRMATION_REQUIRED");
    const gate=this.#approveWrite;
    if(!gate||!this.#audit)err("POC_WRITE_DISABLED");
    let approved=false;
    try{approved=await gate(intent);}catch{err("POC_APPROVAL_UNAVAILABLE");}
    if(approved!==true)err("POC_APPROVAL_DENIED");
  }
  async #auditEvent(intent:LegacyWriteIntent,phase:LegacyAuditEvent["phase"],
    verified=false,status?:number){
    const audit=this.#audit;
    if(!audit)err("POC_AUDIT_UNAVAILABLE");
    const event:LegacyAuditEvent={phase,method:intent.method,
      tenant:intent.tenant,name:intent.name,version:intent.version,
      approvalId:intent.approvalId, ...(status===undefined?{}:{httpStatus:status}),
      apiRegistrationVerified:verified,runtimeParsingVerified:false,targetImportVerified:false};
    try{await audit(event);}catch{err("POC_AUDIT_UNAVAILABLE");}
  }

  async #form(plan:LegacyUploadPlan,post:boolean):Promise<FormData>{
    const body=new FormData();
    body.set("cust_id",this.tenant);
    if(post)body.set("parser_name",plan.name);
    body.set("version",plan.version);
    for(const f of plan.multipartFiles())
      body.append("file",new Blob([new Uint8Array(f.body)],{type:f.type}),f.filename);
    return body;
  }
  async #find(name:string){
    const matches=(await this.listParsers()).filter(x=>x.name===name);
    if(matches.length>1)err("POC_DUPLICATE_METADATA");
    return matches[0];
  }
  async #catalogueFree(port:number,currentName?:string,currentPort?:number){
    const catalogue=await this.listCatalogue();
    // Fail closed when a reported port owner is ambiguous in mutation preflight.
    if(catalogue.some(entry=>entry.port===undefined))err("POC_CATALOGUE_INCOMPLETE");
    if(catalogue.some(entry=>entry.port===port &&
      !(currentName&&currentPort===port&&entry.name===currentName)))
      err("POC_PORT_CONFLICT");
  }
  #result(method:"POST"|"PUT"|"DELETE",name:string,version:string,
    approvalId:string):LegacyOperationResult{
    return {method,name,version,httpStatus:200,apiRegistrationVerified:true,
      runtimeParsingVerified:false,targetImportVerified:false,
      modularActivationVerified:false,approvalId};
  }
  async #mutateAudited(intent:LegacyWriteIntent,method:"POST"|"PUT"|"DELETE",body?:FormData){
    try{await this.#mutate(method,intent.name,body);}
    catch(error){
      await this.#auditEvent(intent,"FAILED");
      throw error;
    }
  }
  async #mutate(method:"POST"|"PUT"|"DELETE",name:string,body?:FormData):Promise<void>{
    const path="/custom_log_parsers"+(method==="POST"?"":"/"+encodeURIComponent(name))+
      (method==="DELETE"?"?"+new URLSearchParams({cust_id:this.tenant}):"");
    await this.#request(path,method,body);
  }

  async create(plan:LegacyUploadPlan,options:WriteConfirmation):Promise<LegacyOperationResult>{
    if(plan.tenant!==this.tenant)err("POC_TENANT_MISMATCH");
    const proof=requireDisposablePocWrite(plan);
    const intent:LegacyWriteIntent={method:"POST",tenant:this.tenant,name:plan.name,
      version:plan.version,approvalId:options.approvalId,port:proof.port,
      parserSha256:plan.parserSha256,confSha256:plan.confSha256};
    await this.#approval(intent,options);
    if(await this.#find(plan.name))err("POC_NAME_CONFLICT");
    await this.#catalogueFree(plan.port);
    await this.#auditEvent(intent,"BEFORE");
    await this.#mutateAudited(intent,"POST",await this.#form(plan,true));
    let found:LegacyParserMetadata|undefined;
    try{found=await this.#find(plan.name);}catch{/* readback failed; uncertain state */}
    if(!found||found.version!==plan.version){
      await this.#auditEvent(intent,"FAILED");
      // Only an exactly new disposable POC identity may be cleaned up. A
      // separate backend approval for CLEANUP is required; never auto-retry
      // a write that may have succeeded on the server.
      await this.#cleanupOwnCreate(intent);
      err("POC_CREATE_UNVERIFIED");
    }
    await this.#auditEvent(intent,"AFTER",true,200);
    return this.#result("POST",plan.name,plan.version,options.approvalId);
  }
  async #cleanupOwnCreate(intent:LegacyWriteIntent):Promise<void>{
    if(!TEST_NAME.test(intent.name)||!this.#approveWrite||!this.#audit)return;
    const cleanup:LegacyWriteIntent={...intent,method:"CLEANUP"};
    let approved=false;
    try{approved=await this.#approveWrite(cleanup);}catch{return;}
    if(!approved)return;
    try{
      await this.#auditEvent(cleanup,"BEFORE");
      await this.#mutate("DELETE",intent.name);
      const remains=await this.#find(intent.name);
      await this.#auditEvent(cleanup,"CLEANUP",!remains,200);
    }catch{/* keep unverified state; operator must reconcile. */}
  }
  async update(plan:LegacyUploadPlan,options:WriteConfirmation):Promise<LegacyOperationResult>{
    if(plan.tenant!==this.tenant)err("POC_TENANT_MISMATCH");
    const proof=requireDisposablePocWrite(plan);
    const expectedVersion=options.expectedVersion;
    if(typeof expectedVersion!=="string"||
      !VERSION.test(expectedVersion))err("POC_VERSION_INVALID");
    const intent:LegacyWriteIntent={method:"PUT",tenant:this.tenant,
      name:plan.name,version:plan.version,expectedVersion,
      approvalId:options.approvalId,port:proof.port,
      parserSha256:plan.parserSha256,confSha256:plan.confSha256};
    await this.#approval(intent,options);
    const found=await this.#find(plan.name);
    if(!found||found.version!==expectedVersion)err("POC_VERSION_CONFLICT");
    // Always check target port on UPDATE, even when it equals the prior port.
    // An unknown catalogue owner is not proof that the port belongs to us.
    await this.#catalogueFree(plan.port,plan.name,found.port);
    await this.#auditEvent(intent,"BEFORE");
    await this.#mutateAudited(intent,"PUT",await this.#form(plan,false));
    const latest=await this.#find(plan.name);
    if(!latest||latest.version!==plan.version){
      await this.#auditEvent(intent,"FAILED");err("POC_UPDATE_UNVERIFIED");
    }
    await this.#auditEvent(intent,"AFTER",true,200);
    return this.#result("PUT",plan.name,plan.version,options.approvalId);
  }
  async delete(name:string,options:WriteConfirmation):Promise<LegacyOperationResult>{
    this.#testName(name);
    const expectedVersion=options.expectedVersion;
    if(typeof expectedVersion!=="string"||
      !VERSION.test(expectedVersion))err("POC_VERSION_INVALID");
    const intent:LegacyWriteIntent={method:"DELETE",tenant:this.tenant,
      name,version:expectedVersion,expectedVersion,
      approvalId:options.approvalId};
    await this.#approval(intent,options);
    const found=await this.#find(name);
    if(!found||found.version!==expectedVersion)err("POC_VERSION_CONFLICT");
    await this.#auditEvent(intent,"BEFORE");
    await this.#mutateAudited(intent,"DELETE");
    const latest=await this.#find(name);
    if(latest){await this.#auditEvent(intent,"FAILED");err("POC_DELETE_UNVERIFIED");}
    await this.#auditEvent(intent,"AFTER",true,200);
    return this.#result("DELETE",name,expectedVersion,options.approvalId);
  }
}
