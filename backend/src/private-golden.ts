/**
 * Offline-only preflight for operator-supplied private golden events.
 * Never echoes raw samples/expected values and never runs uploaded Ruby.
 * The return value is a shape/size check, NOT a native or target attestation.
 */
import { TextDecoder } from "node:util";
import { hasOnlyPairedSurrogates } from "./unicode.js";

/** Decode evidence bytes without replacement characters or source-content errors. */
export function decodePrivateGoldenBytes(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", {fatal:true}).decode(bytes);
  } catch {
    throw new Error("PRIVATE_INVALID_UTF8");
  }
}

export const MAX_PRIVATE_GOLDEN_BYTES = 512 * 1024;
export const MAX_PRIVATE_EVENT_BYTES = 16 * 1024;
export const MAX_PRIVATE_GOLDEN_CASES = 32;

export interface PrivateGoldenIssue {code:string;path:string;message:string}
export type PrivateGoldenPreflight =
  | {ok:true;caseCount:number;profileCount:number;readyForNativeExecution:false;targetImportVerified:false}
  | {ok:false;issues:PrivateGoldenIssue[];readyForNativeExecution:false;targetImportVerified:false};

const ID = /^[a-z][a-z0-9_-]{1,63}$/;
const SLUG = /^[a-z][a-z0-9_]{1,47}$/;
const FIELD = /^[A-Za-z_][A-Za-z0-9_.-]*$/;
const UNSAFE = new Set(["__proto__","constructor","prototype"]);
const TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;

function isObject(value:unknown):value is Record<string,unknown> {
  return value!==null && typeof value==="object" && !Array.isArray(value) &&
    (Object.getPrototypeOf(value)===Object.prototype || Object.getPrototypeOf(value)===null);
}

export function inspectPrivateGolden(input:unknown):PrivateGoldenPreflight {
  const issues:PrivateGoldenIssue[]=[];
  const add=(code:string,path:string,message:string)=>issues.push({code,path,message});
  const reject=():PrivateGoldenPreflight=>({
    ok:false,issues,readyForNativeExecution:false,targetImportVerified:false,
  });
  let bytes=0;
  try {
    const encoded=JSON.stringify(input);
    if(typeof encoded!=="string")throw Error("Not serializable");
    bytes=Buffer.byteLength(encoded,"utf8");
  }catch{
    add("PRIVATE_INPUT_SHAPE","/","Fixture must be a finite JSON object.");
    return reject();
  }
  if(bytes>MAX_PRIVATE_GOLDEN_BYTES){
    add("PRIVATE_INPUT_SIZE","/","Fixture exceeds the bounded offline file limit.");
    return reject();
  }
  if(!isObject(input)){
    add("PRIVATE_INPUT_SHAPE","/","Fixture must be a JSON object.");
    return reject();
  }
  for(const key of Object.keys(input))
    if(key!=="kind" && key!=="cases")
      add("PRIVATE_UNKNOWN_FIELD","/","Private fixture contains an unsupported field.");
  if(input.kind!=="parser-studio.private-golden.v0.1")
    add("PRIVATE_VERSION","/kind","Private fixture revision is unsupported.");
  const cases=input.cases;
  if(!Array.isArray(cases)||cases.length<1||cases.length>MAX_PRIVATE_GOLDEN_CASES){
    add("PRIVATE_CASE_COUNT","/cases","Fixture case count must be within the allowed range.");
    return reject();
  }
  const caseIds=new Set<string>(),slugs=new Set<string>();
  const walk=(value:unknown,path:string,depth:number):void=>{
    if(depth>8){
      add("PRIVATE_EXPECTED_DEPTH",path,"Expected record nesting is too deep.");
      return;
    }
    if(Array.isArray(value)){
      add("PRIVATE_EXPECTED_TYPE",path,"Expected records may not contain arrays in this revision.");
      return;
    }
    if(isObject(value)){
      for(const [key,entry] of Object.entries(value)){
        if(UNSAFE.has(key) || !FIELD.test(key)){
          add("PRIVATE_UNSAFE_RECORD_KEY",path,"Expected record contains an unsafe or unsupported field name.");
          continue;
        }
        walk(entry,path,depth+1);
      }
    }else if(typeof value==="string"){
      if(!hasOnlyPairedSurrogates(value))
        add("PRIVATE_INVALID_UNICODE",path,"Expected text contains invalid Unicode scalar encoding.");
    }else if(value!==null && typeof value!=="boolean" &&
      !(typeof value==="number" && Number.isFinite(value))){
      add("PRIVATE_EXPECTED_TYPE",path,"Expected field value is not a supported JSON scalar.");
    }
  };
  for(const [i,item] of cases.entries()){
    const path="/cases/"+i;
    if(!isObject(item)){
      add("PRIVATE_CASE_SHAPE",path,"Each fixture case must be an object.");
      continue;
    }
    const required=["id","projectSlug","rawEvent","expectedTime","expectedRecord"];
    for(const key of Object.keys(item)){
      if(!required.includes(key))
        add("PRIVATE_UNKNOWN_FIELD",path,"Fixture case contains an unsupported field.");
    }
    for(const key of required){
      if(!Object.hasOwn(item,key))
        add("PRIVATE_REQUIRED",path+"/"+key,"Required fixture field is missing.");
    }
    if(typeof item.id!=="string"||!ID.test(item.id)){
      add("PRIVATE_CASE_ID",path+"/id","Fixture case ID is not valid.");
    }else if(caseIds.has(item.id)){
      add("PRIVATE_DUPLICATE_CASE",path+"/id","Fixture case ID must be unique.");
    }else caseIds.add(item.id);
    if(typeof item.projectSlug!=="string"||!SLUG.test(item.projectSlug)){
      add("PRIVATE_PROJECT_SLUG",path+"/projectSlug","Parser project slug is not valid.");
    }else slugs.add(item.projectSlug);
    if(typeof item.rawEvent!=="string"||!item.rawEvent.length ||
      Buffer.byteLength(item.rawEvent,"utf8")>MAX_PRIVATE_EVENT_BYTES ||
      item.rawEvent.includes("\u0000")){
      add("PRIVATE_EVENT_SIZE",path+"/rawEvent","Raw event is empty, too large or contains unsupported bytes.");
    }else if(!hasOnlyPairedSurrogates(item.rawEvent)){
      add("PRIVATE_INVALID_UNICODE",path+"/rawEvent","Raw event contains invalid Unicode scalar encoding.");
    }
    if(item.expectedTime!==null &&
      (typeof item.expectedTime!=="string"||!TIME.test(item.expectedTime)||
       !Number.isFinite(Date.parse(item.expectedTime)) ||
       new Date(item.expectedTime).toISOString().slice(0,19)+"Z"!==item.expectedTime)){
      add("PRIVATE_TIME_FORMAT",path+"/expectedTime","Expected event time must be explicit UTC seconds or null.");
    }
    if(!isObject(item.expectedRecord)){
      add("PRIVATE_EXPECTED_SHAPE",path+"/expectedRecord","Expected record must be a JSON object.");
    }else walk(item.expectedRecord,path+"/expectedRecord",0);
  }
  if(issues.length)return reject();
  return {ok:true,caseCount:cases.length,profileCount:slugs.size,
    readyForNativeExecution:false,targetImportVerified:false};
}
