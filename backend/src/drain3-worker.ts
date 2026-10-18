/** Optional, locally installed Drain3 0.9.11 in one bounded ephemeral process.
 * This is not a remote LLM, persistent template store, Ruby compiler or
 * automatic parser update. Never log or return source lines or runtime errors.
 */
import {spawn} from "node:child_process";
import {isAbsolute,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {hasValidUnicodeJson} from "./unicode.js";

export class Drain3WorkerError extends Error{
 constructor(readonly code:string){super(code);this.name="Drain3WorkerError";}
}
const deny=(code:string):never=>{throw new Drain3WorkerError(code);};
const MAX_BODY=64*1024;
const MAX_OUTPUT=48*1024;
const MAX_WALL_MS=5000;
const MAX_PENDING=2;
let active=0;
const script=fileURLToPath(new URL("../scripts/drain3_offline_worker.py",import.meta.url));

export interface Drain3Request{
 contract:"parser-studio.drain3-input.v0.1";
 training:string[];
 holdout:string[];
}
export interface Drain3Hint{
 clusterId:string;
 shape:string;
 trainingCount:number;
 trainingLineNumbers:number[];
 holdoutMatches:number;
 reviewOnly:true;
}
export interface Drain3Report{
 contract:"parser-studio.drain3-reviewed-hints.v0.1";
 engine:"Drain3 0.9.11";
 sourceCount:number;
 accounted:number;
 holdoutCount:number;
 holdoutMatched:number;
 groupCount:number;
 groups:Drain3Hint[];
 persisted:false;
 sourceValuesIncluded:false;
 nativeParserVerified:false;
 targetImportVerified:false;
}
const SAFE_TOKENS=new Set([
 "ERROR","WARN","WARNING","DEBUG","INFO","TRACE","FATAL","LOGIN",
 "LOGOUT","ALLOW","DENY","FAILED","SUCCESS","GET","POST","PUT",
 "PATCH","DELETE","HTTP","HTTPS","TCP","UDP","SRC","DST","IP",
 "PORT","USER","STATUS","TIME","ID","<VAR>","<IP>","<NUM>",
 "<UUID>","<PUNCT>","<WORD>",
]);
function exact(v:unknown,keys:readonly string[]):v is Record<string,unknown>{
 return !!v&&typeof v==="object"&&!Array.isArray(v)&&
  Object.keys(v).length===keys.length&&
  Object.keys(v).every(k=>keys.includes(k));
}
function validRecords(v:unknown,max:number):v is string[]{
 return Array.isArray(v)&&v.length<=max&&v.every(x=>
  typeof x==="string"&&x.length>0&&x.length<=2048&&
  Buffer.byteLength(x,"utf8")<=2048&&
  !/\0|\r|\n/.test(x));
}
export function validateDrain3Request(input:unknown):Drain3Request{
 if(!hasValidUnicodeJson(input)||!exact(input,["contract","training","holdout"])||
  input.contract!=="parser-studio.drain3-input.v0.1"||
  !validRecords(input.training,500)||!input.training.length||
  !validRecords(input.holdout,500)||
  Buffer.byteLength(JSON.stringify(input),"utf8")>MAX_BODY)
   return deny("DRAIN3_INPUT_UNSUPPORTED");
 return input as unknown as Drain3Request;
}
function reviewed(raw:unknown,input:Drain3Request):Drain3Report{
 if(!exact(raw,["ok","contract","engine","sourceCount","accounted",
    "holdoutCount","holdoutMatched","groupCount","groups","persisted",
    "sourceValuesIncluded","nativeParserVerified","targetImportVerified"])||
    raw.ok!==true||
    raw.contract!=="parser-studio.drain3-reviewed-hints.v0.1"||
    raw.engine!=="Drain3 0.9.11"||
    raw.sourceCount!==input.training.length||raw.accounted!==input.training.length||
    raw.holdoutCount!==input.holdout.length||
    !Number.isSafeInteger(raw.holdoutMatched)||
    Number(raw.holdoutMatched)<0||Number(raw.holdoutMatched)>input.holdout.length||
    !Array.isArray(raw.groups)||raw.groups.length>32||
    raw.groupCount!==raw.groups.length||
    raw.persisted!==false||raw.sourceValuesIncluded!==false||
    raw.nativeParserVerified!==false||raw.targetImportVerified!==false)
    return deny("DRAIN3_OUTPUT_UNTRUSTED");
 const groups=raw.groups as unknown[];
 const seen=new Set<string>(),lines=new Set<number>();
 let holdout=0;
 for(const item of groups){
  if(!exact(item,["clusterId","shape","trainingCount","trainingLineNumbers",
    "holdoutMatches","reviewOnly"])||
     typeof item.clusterId!=="string"||!/^cluster-[1-9][0-9]{0,3}$/.test(item.clusterId)||
     seen.has(item.clusterId)||typeof item.shape!=="string"||
     item.shape.length>512||item.shape.length===0||
     !item.shape.split(" ").every(x=>SAFE_TOKENS.has(x))||
     !Number.isSafeInteger(item.trainingCount)||Number(item.trainingCount)<1||
     !Array.isArray(item.trainingLineNumbers)||
     item.trainingLineNumbers.length!==item.trainingCount||
     !Number.isSafeInteger(item.holdoutMatches)||Number(item.holdoutMatches)<0||
     item.reviewOnly!==true)return deny("DRAIN3_OUTPUT_UNTRUSTED");
  seen.add(item.clusterId);
  holdout+=Number(item.holdoutMatches);
  for(const n of item.trainingLineNumbers){
   if(!Number.isSafeInteger(n)||n<1||n>input.training.length||lines.has(n))
     return deny("DRAIN3_OUTPUT_UNTRUSTED");
   lines.add(n);
  }
 }
 if(lines.size!==input.training.length||holdout!==raw.holdoutMatched)
   return deny("DRAIN3_OUTPUT_UNTRUSTED");
 const clean:Drain3Report={
  contract:"parser-studio.drain3-reviewed-hints.v0.1",
  engine:"Drain3 0.9.11",sourceCount:input.training.length,
  accounted:lines.size,holdoutCount:input.holdout.length,
  holdoutMatched:holdout,groupCount:groups.length,
  groups:structuredClone(groups) as Drain3Hint[],
  persisted:false,sourceValuesIncluded:false,nativeParserVerified:false,
  targetImportVerified:false,
 };
 return clean;
}
/** The interpreter path is trusted server configuration, never HTTP input. */
export async function mineDrain3(
 input:unknown,
 pythonExecutable:string,
):Promise<Drain3Report>{
 const safe=validateDrain3Request(input);
 if(typeof pythonExecutable!=="string"||
   !isAbsolute(pythonExecutable)||pythonExecutable.length>512)
   return deny("DRAIN3_RUNTIME_UNAVAILABLE");
 if(active>=MAX_PENDING)return deny("DRAIN3_BUSY");
 active++;
 try{
  const source=JSON.stringify(safe);
  const result=await new Promise<unknown>((resolveResult,rejectResult)=>{
   let complete=false,bytes=0,stdout="";
   const reject=()=>finish(undefined,"DRAIN3_WORKER_UNAVAILABLE");
   const child=spawn(pythonExecutable,["-I","-B",script],{
     cwd:resolve(fileURLToPath(new URL("../",import.meta.url))),
     env:{PATH:"/usr/bin:/bin",PYTHONDONTWRITEBYTECODE:"1",
       PYTHONNOUSERSITE:"1",LC_ALL:"C.UTF-8",LANG:"C.UTF-8"},
     stdio:["pipe","pipe","ignore"],shell:false,
   });
   const finish=(value?:unknown,reason?:string)=>{
     if(complete)return;
     complete=true;clearTimeout(timeout);
     if(reason){
       child.kill("SIGKILL");
       rejectResult(new Drain3WorkerError(reason));
     }else resolveResult(value);
   };
   const timeout=setTimeout(reject,MAX_WALL_MS);
   child.stdout.setEncoding("utf8");
   child.stdout.on("data",(chunk:string)=>{
     bytes+=Buffer.byteLength(chunk,"utf8");
     if(bytes>MAX_OUTPUT)return reject();
     stdout+=chunk;
   });
   child.on("error",reject);
   child.on("close",(code)=>{
     if(complete)return;
     if(code!==0)return reject();
     try{finish(JSON.parse(stdout) as unknown);}catch{return reject();}
   });
   child.stdin.on("error",()=>{});
   child.stdin.end(source);
  });
  if(!result||typeof result!=="object"||
     (result as Record<string,unknown>).ok!==true)
     return deny("DRAIN3_WORKER_UNAVAILABLE");
  return reviewed(result,safe);
 }finally{active--;}
}
