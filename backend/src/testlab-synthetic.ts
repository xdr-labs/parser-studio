/**
 * P0 Live Test Lab — offline format-aware synthetic event PREVIEW.
 * Deliberately NO sockets, sensor sends, timers, persistence or credentials.
 * User preview and explicit target authorization must precede transmission.
 * Bounded initial subset: JSON object and simple unquoted one-line KV.
 */
import {hasValidUnicodeJson} from "./unicode.js";

export type SyntheticVariableKind="ipv4"|"username"|"url";
export type SyntheticVariable={path:string;kind:SyntheticVariableKind};
export type SyntheticPreviewRequest={
  format:"json"|"kv";
  source:string;
  seed:number;
  sequence:number;
  timestampField?:string;
  variableFields:readonly SyntheticVariable[];
  runMarkerField?:string;
  runId?:string;
};
export type SyntheticPreview={
  contract:"parser-studio.synthetic-preview.v0.1";
  format:"json"|"kv";
  syntheticEvent:string;
  generatedAt:string;
  sequence:number;
  changedPaths:string[];
  safeToSendToSensor:false;
  runtimeParsingVerified:false;
  targetSensorVerified:false;
};
export class SyntheticPreviewError extends Error{
  constructor(readonly code:string){super(code);this.name="SyntheticPreviewError";}
}
function fail(code:string):never{throw new SyntheticPreviewError(code);}
const PATH=/^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*){0,7}$/;
const KV=/^([A-Za-z_][A-Za-z0-9_.-]*)=([^\s"'\\]+)$/;
const prohibited=new Set(["__proto__","prototype","constructor"]);

function pathParts(input:string):string[]{
  if(typeof input!=="string"||!PATH.test(input))fail("TESTLAB_PATH_INVALID");
  const parts=input.split(".");
  if(parts.some(x=>prohibited.has(x)))fail("TESTLAB_PATH_UNSAFE");
  return parts;
}
function safeTree(root:unknown,depth=0):boolean{
  if(depth>12)return false;
  if(Array.isArray(root))return false; // not in the reviewed preview subset
  if(root&&typeof root==="object"){
    return Object.entries(root).every(([key,value])=>
      !prohibited.has(key)&&safeTree(value,depth+1));
  }
  return root===null||typeof root==="string"||
    typeof root==="boolean"||typeof root==="number";
}
function strictSource(input:SyntheticPreviewRequest):Record<string,unknown>{
  if(input.format==="json"){
    let value:unknown;
    try{value=JSON.parse(input.source);}catch{fail("TESTLAB_JSON_UNSUPPORTED");}
    if(!value||Array.isArray(value)||typeof value!=="object"||
       !safeTree(value))fail("TESTLAB_JSON_UNSUPPORTED");
    return value as Record<string,unknown>;
  }
  if(input.format==="kv"){
    if(/[\r\n]/.test(input.source))fail("TESTLAB_KV_UNSUPPORTED");
    const parts=input.source.trim().split(/[ \t]+/);
    if(!parts.length||parts.length>80)fail("TESTLAB_KV_UNSUPPORTED");
    const map:Record<string,unknown>=Object.create(null);
    for(const part of parts){
      const m=KV.exec(part);
      if(!m||Object.hasOwn(map,m[1]!)||prohibited.has(m[1]!))
        fail("TESTLAB_KV_UNSUPPORTED");
      map[m[1]!]=m[2]!;
    }
    return map;
  }
  fail("TESTLAB_FORMAT_UNSUPPORTED");
}
function location(root:Record<string,unknown>,path:string):{host:Record<string,unknown>;key:string}{
  const parts=pathParts(path);
  let node:Record<string,unknown>=root;
  for(const part of parts.slice(0,-1)){
    if(!Object.hasOwn(node,part)||
       !node[part]||typeof node[part]!=="object"||
       Array.isArray(node[part]))fail("TESTLAB_FIELD_MISSING");
    node=node[part] as Record<string,unknown>;
  }
  const key=parts[parts.length-1]!;
  if(!Object.hasOwn(node,key)||typeof node[key]!=="string")
    fail("TESTLAB_FIELD_MISSING");
  return {host:node,key};
}
function nextValue(seed:number,sequence:number,ordinal:number):number{
  let state=(seed^(Math.imul(sequence+1,0x9e3779b1))^
    Math.imul(ordinal+1,0x85ebca6b))>>>0;
  if(!state)state=1;
  state^=state<<13;state^=state>>>17;state^=state<<5;
  return state>>>0;
}
function dynamicValue(kind:SyntheticVariableKind,
  seed:number,sequence:number,ordinal:number,old:string):string{
  const token=nextValue(seed,sequence,ordinal);
  if(kind==="ipv4"){
    const prefix=["192.0.2","198.51.100","203.0.113"][token%3]!;
    return prefix+"."+((token>>>8)%254+1);
  }
  if(kind==="username")return "synthetic_user_"+String(token%1000000).padStart(6,"0");
  if(kind==="url"){
    const part="synthetic/"+token.toString(16).padStart(8,"0");
    return old.startsWith("/")?"/"+part:"https://synthetic.invalid/"+part;
  }
  fail("TESTLAB_VARIABLE_KIND_UNSUPPORTED");
}
function currentTimestamp(reference:string,nowMs:number):string{
  const m=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?(Z|[+-]\d\d:\d\d)$/.exec(reference);
  if(!m||!Number.isFinite(Date.parse(reference)))
    fail("TESTLAB_TIMESTAMP_FORMAT_UNSUPPORTED");
  const zone=m[2]!;
  let offset=0;
  if(zone!=="Z"){
    const hour=Number(zone.slice(1,3));
    const minute=Number(zone.slice(4,6));
    if(hour>14||minute>59||(hour===14&&minute!==0))
      fail("TESTLAB_TIMESTAMP_FORMAT_UNSUPPORTED");
    offset=(hour*60+minute)*(zone[0]==="-"?-1:1);
  }
  const time=new Date(nowMs+offset*60000);
  const utc=time.toISOString();
  const digits=m[1]?m[1].length-1:0;
  return utc.slice(0,19)+(digits?"."+utc.slice(20,20+digits):"")+zone;
}
export function createSyntheticPreview(input:SyntheticPreviewRequest,
  nowMs=Date.now()):SyntheticPreview{
  if(!input||typeof input!=="object"||
    !["json","kv"].includes(input.format))fail("TESTLAB_FORMAT_UNSUPPORTED");
  if(typeof input.source!=="string"||
    Buffer.byteLength(input.source,"utf8")>16384||input.source.length<1||
    input.source.includes("\u0000")||!hasValidUnicodeJson(input.source))
    fail("TESTLAB_SOURCE_UNSAFE");
  if(!Number.isInteger(input.seed)||input.seed<0||input.seed>0xffffffff||
    !Number.isInteger(input.sequence)||input.sequence<0||input.sequence>1e9||
    !Number.isFinite(nowMs)||nowMs<0)
    fail("TESTLAB_SEQUENCE_INVALID");
  if(!Array.isArray(input.variableFields)||input.variableFields.length>12)
    fail("TESTLAB_VARIABLES_INVALID");
  if(input.runMarkerField!==undefined &&
    (typeof input.runId!=="string"||
     !/^[a-zA-Z0-9_-]{8,64}$/.test(input.runId)))
    fail("TESTLAB_RUN_MARKER_INVALID");
  if(input.runId!==undefined&&input.runMarkerField===undefined)
    fail("TESTLAB_RUN_MARKER_INVALID");
  const roots=strictSource(input);
  const changed:string[]=[];
  const selected=new Set<string>();
  const modify=(path:string,value:(previous:string,index:number)=>string)=>{
    if(selected.has(path))fail("TESTLAB_DUPLICATE_FIELD");
    selected.add(path);
    const {host,key}=location(roots,path);
    host[key]=value(host[key] as string,changed.length);
    changed.push(path);
  };
  if(input.timestampField!==undefined)
    modify(input.timestampField,previous=>currentTimestamp(previous,nowMs));
  for(const entry of input.variableFields){
    if(!entry||!["ipv4","username","url"].includes(entry.kind))
      fail("TESTLAB_VARIABLE_KIND_UNSUPPORTED");
    modify(entry.path,(previous,index)=>
      dynamicValue(entry.kind,input.seed,input.sequence,index,previous));
  }
  if(input.runMarkerField!==undefined)
    modify(input.runMarkerField,()=>input.runId!);
  const syntheticEvent=input.format==="json"?
    JSON.stringify(roots):Object.entries(roots).map(([key,value])=>key+"="+value).join(" ");
  if(Buffer.byteLength(syntheticEvent,"utf8")>16384)
    fail("TESTLAB_OUTPUT_TOO_LARGE");
  return {contract:"parser-studio.synthetic-preview.v0.1",
    format:input.format,syntheticEvent,
    generatedAt:new Date(nowMs).toISOString(),sequence:input.sequence,
    changedPaths:changed,safeToSendToSensor:false,
    runtimeParsingVerified:false,targetSensorVerified:false};
}
