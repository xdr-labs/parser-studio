/**
 * P0 Live Test Lab — offline format-aware synthetic event PREVIEW.
 * Deliberately NO sockets, sensor sends, timers, persistence or credentials.
 * User preview and explicit target authorization must precede transmission.
 * Bounded reviewed subset: JSON object, simple unquoted one-line KV,
 * and strict single-line CSV with an explicit source column contract.
 */
import {hasValidUnicodeJson} from "./unicode.js";

export type SyntheticVariableKind="ipv4"|"username"|"url";
export type SyntheticVariable={path:string;kind:SyntheticVariableKind};
export type SyntheticPreviewRequest={
  format:"json"|"kv"|"csv"|"cef"|"leef"|"syslog_rfc5424";
  source:string;
  csvColumns?:readonly string[];
  csvDelimiter?:","|";"|"\t";
  syslogBodyFormat?:"kv";
  seed:number;
  sequence:number;
  timestampField?:string;
  variableFields:readonly SyntheticVariable[];
  runMarkerField?:string;
  runId?:string;
};
export type SyntheticPreview={
  contract:"parser-studio.synthetic-preview.v0.1";
  format:"json"|"kv"|"csv"|"cef"|"leef"|"syslog_rfc5424";
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

const CSV_COLUMN=/^[A-Za-z][A-Za-z0-9_]{0,63}$/;
/** This encoder/decoder intentionally excludes CSV multiline and nonstandard
 * trailing text. The reviewed generated Ruby uses CSV.parse_line.
 */
function csvDefinition(input:SyntheticPreviewRequest):{columns:readonly string[];separator:string}{
  const columns=input.csvColumns;
  const separator=input.csvDelimiter??",";
  if(!Array.isArray(columns)||columns.length<1||columns.length>100||
    ![",",";","\t"].includes(separator)||
    new Set(columns).size!==columns.length||
    columns.some(x=>typeof x!=="string"||!CSV_COLUMN.test(x)||
      prohibited.has(x)))fail("TESTLAB_CSV_SCHEMA_INVALID");
  return {columns,separator};
}
function parseCsvLine(source:string,separator:string):string[]{
  if(/[\r\n]/.test(source))fail("TESTLAB_CSV_MULTILINE_UNSUPPORTED");
  const output:string[]=[];
  let position=0;
  while(true){
    if(output.length>=100)fail("TESTLAB_CSV_COLUMNS_INVALID");
    let value="";
    while(position<source.length&&
      (source[position]===" "||(source[position]==="\t"&&separator!=="\t")))position++;
    if(source[position]==='"'){
      position++;
      let closed=false;
      while(position<source.length){
        const character=source[position]!;
        if(character==='"'){
          if(source[position+1]==='"'){value+='"';position+=2;}
          else{position++;closed=true;break;}
        }else{value+=character;position++;}
      }
      if(!closed)fail("TESTLAB_CSV_QUOTE_INVALID");
      while(position<source.length&&
        (source[position]===" "||(source[position]==="\t"&&separator!=="\t")))position++;
      if(position<source.length&&source[position]!==separator)
        fail("TESTLAB_CSV_QUOTE_INVALID");
    }else{
      while(position<source.length&&source[position]!==separator){
        if(source[position]==='"')fail("TESTLAB_CSV_QUOTE_INVALID");
        value+=source[position++];
      }
      value=value.trim();
    }
    output.push(value);
    if(position>=source.length)break;
    position++;
  }
  return output;
}
function serializeCsvLine(columns:readonly string[],source:Record<string,unknown>,
  separator:string):string{
  return columns.map(key=>{
    const item=source[key];
    if(typeof item!=="string")fail("TESTLAB_CSV_OUTPUT_INVALID");
    if(/[\r\n]/.test(item))fail("TESTLAB_CSV_MULTILINE_UNSUPPORTED");
    return item.includes('"')||item.includes(separator)?
      '"'+item.replace(/"/g,'""')+'"':item;
  }).join(separator);
}
const prohibited=new Set(["__proto__","prototype","constructor"]);

/** Read exactly the reviewed CEF/LEEF header fields, including escaped
 * pipes/backslashes. Preserve original header bytes for replay output.
 */
function delimitedEnvelope(source:string,header:string,splits:number,
  label:"CEF"|"LEEF"):{prefix:string;body:string;fields:string[]}{
  if(!source.startsWith(header)||/[\r\n\u0000]/.test(source))
    fail("TESTLAB_"+label+"_HEADER_INVALID");
  let i=header.length,escaped=false;
  const fields:string[]=[];
  let value="";
  while(i<source.length){
    const c=source[i++]!;
    if(escaped){
      if(c!=="|"&&c!=="\\")fail("TESTLAB_"+label+"_HEADER_INVALID");
      value+=c;
      escaped=false;
    }else if(c==="\\"){
      escaped=true;
    }else if(c==="|"){
      fields.push(value);
      value="";
      if(fields.length===splits){
        if(fields.some(x=>!x||x.length>512)||i>2048)
          fail("TESTLAB_"+label+"_HEADER_INVALID");
        return {prefix:source.slice(0,i),body:source.slice(i),fields};
      }
    }else{value+=c;}
    if(i>2048)fail("TESTLAB_"+label+"_HEADER_INVALID");
  }
  fail("TESTLAB_"+label+"_HEADER_INVALID");
}
function cefEnvelope(source:string){
  return delimitedEnvelope(source,"CEF:0|",6,"CEF");
}
function leefEnvelope(source:string):{
  prefix:string;body:string;separator:string;
}{
  const v=source.startsWith("LEEF:1.0|")?"1.0":
    source.startsWith("LEEF:2.0|")?"2.0":null;
  if(v===null)fail("TESTLAB_LEEF_HEADER_INVALID");
  const p=delimitedEnvelope(source,"LEEF:"+v+"|",v==="1.0"?4:5,"LEEF");
  let separator=v==="1.0"?"\t":p.fields[4]!;
  const hex=/^0x([0-9a-fA-F]{1,2})$/.exec(separator);
  if(hex)separator=String.fromCharCode(parseInt(hex[1]!,16));
  if(separator.length!==1||
    !(separator==="\t"||(separator.charCodeAt(0)>=33&&
      separator.charCodeAt(0)<=126&&
      separator!=="="&&separator!=="\\")))
    fail("TESTLAB_LEEF_SEPARATOR_INVALID");
  return {prefix:p.prefix,body:p.body,separator};
}
function parseSimpleKv(source:string,label:"KV"):Record<string,unknown>{
  if(/[\r\n]/.test(source))fail("TESTLAB_"+label+"_UNSUPPORTED");
  const parts=source.trim().split(/[ \t]+/);
  if(!parts.length||parts.length>80)fail("TESTLAB_"+label+"_UNSUPPORTED");
  const map:Record<string,unknown>=Object.create(null);
  for(const part of parts){
    const m=KV.exec(part);
    if(!m||Object.hasOwn(map,m[1]!)||prohibited.has(m[1]!))
      fail("TESTLAB_"+label+"_UNSUPPORTED");
    map[m[1]!]=m[2]!;
  }
  return map;
}

/** CEF extension values may contain spaces. Match the same bounded structural
 * rule as the generated Ruby parser: whitespace belongs to the current value
 * until the final whitespace byte immediately preceding another safe key=.
 * CEF escapes are decoded only for the reviewed n/r/= and backslash subset.
 */
function parseCefFields(source:string):Record<string,unknown>{
  if(!source||/[\r\n\u0000]/.test(source))fail("TESTLAB_CEF_UNSUPPORTED");
  const result:Record<string,unknown>=Object.create(null);
  const key=/([A-Za-z_][A-Za-z0-9_.-]{0,127})=/y;
  let position=0,count=0;
  while(position<source.length){
    while(position<source.length&&(source[position]===" "||source[position]==="\t"))position++;
    if(position>=source.length)break;
    if(count>=80)fail("TESTLAB_CEF_UNSUPPORTED");
    key.lastIndex=position;
    const match=key.exec(source);
    if(!match||match.index!==position||prohibited.has(match[1]!)||
      Object.hasOwn(result,match[1]!))fail("TESTLAB_CEF_UNSUPPORTED");
    const field=match[1]!;
    let cursor=key.lastIndex,value="",boundary=-1;
    while(cursor<source.length){
      const character=source[cursor]!;
      if(character==="\\"){
        if(cursor+1>=source.length)fail("TESTLAB_CEF_UNSUPPORTED");
        const following=source[cursor+1]!;
        value+=following==="n"?"\n":following==="r"?"\r":
          following==="="?"=":following==="\\"?"\\":"\\"+following;
        cursor+=2;continue;
      }
      if(character===" "||character==="\t"){
        let runEnd=cursor;
        while(runEnd<source.length&&
          (source[runEnd]===" "||source[runEnd]==="\t"))runEnd++;
        key.lastIndex=runEnd;
        const next=key.exec(source);
        if(next&&next.index===runEnd){
          if(runEnd-cursor>1)value+=source.slice(cursor,runEnd-1);
          boundary=runEnd-1;break;
        }
      }
      value+=character;cursor++;
    }
    if(boundary<0)value=value.replace(/[ \t]+$/,"");
    if(/[\r\n\u0000]/.test(value))fail("TESTLAB_CEF_UNSUPPORTED");
    result[field]=value;
    count++;
    position=boundary<0?source.length:boundary+1;
  }
  if(!Object.keys(result).length)fail("TESTLAB_CEF_UNSUPPORTED");
  return result;
}
function serializeCefFields(root:Record<string,unknown>):string{
  return Object.entries(root).map(([key,value])=>{
    if(typeof value!=="string"||/[\r\n\u0000\t]/.test(value))
      fail("TESTLAB_CEF_UNSUPPORTED");
    const escaped=value.replace(/\\/g,"\\\\").replace(/=/g,"\\=");
    return key+"="+escaped;
  }).join(" ");
}
function parseLeefFields(text:string,separator:string):Record<string,unknown>{
  if(!text)fail("TESTLAB_LEEF_EXTENSION_INVALID");
  const tokens=text.split(separator);
  if(tokens.length>80)fail("TESTLAB_LEEF_EXTENSION_INVALID");
  const fields:Record<string,unknown>=Object.create(null);
  for(const token of tokens){
    const pos=token.indexOf("=");
    const key=token.slice(0,pos);
    if(pos<1||!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key)||
      prohibited.has(key)||Object.hasOwn(fields,key))
      fail("TESTLAB_LEEF_EXTENSION_INVALID");
    fields[key]=token.slice(pos+1);
  }
  return fields;
}
function serializeLeefFields(root:Record<string,unknown>,separator:string):string{
  return Object.entries(root).map(([key,value])=>{
    if(typeof value!=="string"||/[\r\n\u0000]/.test(value)||
      value.includes(separator))fail("TESTLAB_LEEF_EXTENSION_INVALID");
    return key+"="+value;
  }).join(separator);
}
/** Bounded RFC5424 v1 with NILVALUE Structured Data only. Parser
 * selection is explicit: no automatic body format inference.
 */
function syslogEnvelope(input:SyntheticPreviewRequest):{
  pri:number;timestamp:string;hostname:string;appname:string;
  procid:string;msgid:string;body:string;
}{
  if(input.syslogBodyFormat!=="kv")fail("TESTLAB_SYSLOG_BODY_UNSUPPORTED");
  const m=/^<([0-9]{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) - (.+)$/.exec(input.source);
  if(!m||Number(m[1])>191)fail("TESTLAB_SYSLOG_HEADER_UNSUPPORTED");
  for(const [index,limit] of [[3,255],[4,48],[5,128],[6,32]] as const){
    const value=m[index]!;
    if(Buffer.byteLength(value,"utf8")>limit||!/^[!-~]+$/.test(value))
      fail("TESTLAB_SYSLOG_HEADER_UNSUPPORTED");
  }
  try{currentTimestamp(m[2]!,0);}
  catch{fail("TESTLAB_SYSLOG_TIMESTAMP_UNSUPPORTED");}
  return {pri:Number(m[1]),timestamp:m[2]!,hostname:m[3]!,
    appname:m[4]!,procid:m[5]!,msgid:m[6]!,body:m[7]!};
}
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
  if(input.format==="csv"){
    const {columns,separator}=csvDefinition(input);
    const values=parseCsvLine(input.source,separator);
    if(values.length!==columns.length)fail("TESTLAB_CSV_COLUMNS_INVALID");
    const root:Record<string,unknown>=Object.create(null);
    for(let index=0;index<columns.length;index++)root[columns[index]!]=values[index]!;
    return root;
  }
  if(input.format==="kv")return parseSimpleKv(input.source,"KV");
  if(input.format==="cef")
    return parseCefFields(cefEnvelope(input.source).body);
  if(input.format==="leef"){
    const envelope=leefEnvelope(input.source);
    return parseLeefFields(envelope.body,envelope.separator);
  }
  if(input.format==="syslog_rfc5424"){
    const envelope=syslogEnvelope(input);
    let body:Record<string,unknown>;
    try{body=parseSimpleKv(envelope.body,"KV");}
    catch{fail("TESTLAB_SYSLOG_BODY_UNSUPPORTED");}
    const root:Record<string,unknown>=Object.create(null);
    root.body=body;
    return root;
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
    const octets=old.split(".");
    if(octets.length!==4||octets.some(part=>!/^(?:0|[1-9]\d{0,2})$/.test(part)||
      Number(part)>255))fail("TESTLAB_VARIABLE_SOURCE_INVALID");
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
    !["json","kv","csv","cef","leef","syslog_rfc5424"].includes(input.format))
    fail("TESTLAB_FORMAT_UNSUPPORTED");
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
  if(input.format!=="csv"&&
    (input.csvColumns!==undefined||input.csvDelimiter!==undefined))
    fail("TESTLAB_CSV_SCHEMA_INVALID");
  if(input.format!=="syslog_rfc5424"&&input.syslogBodyFormat!==undefined)
    fail("TESTLAB_SYSLOG_BODY_UNSUPPORTED");
  if(input.format==="syslog_rfc5424"&&input.timestampField!==undefined&&
    input.timestampField!=="syslog_timestamp"&&
    !input.timestampField.startsWith("body."))
    fail("TESTLAB_SYSLOG_TIMESTAMP_FIELD_INVALID");
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
  if(input.format==="syslog_rfc5424"){
    changed.push("syslog_timestamp");
    selected.add("syslog_timestamp");
  }
  if(input.timestampField!==undefined&&input.timestampField!=="syslog_timestamp")
    modify(input.timestampField,previous=>currentTimestamp(previous,nowMs));
  for(const entry of input.variableFields){
    if(!entry||!["ipv4","username","url"].includes(entry.kind))
      fail("TESTLAB_VARIABLE_KIND_UNSUPPORTED");
    modify(entry.path,(previous,index)=>
      dynamicValue(entry.kind,input.seed,input.sequence,index,previous));
  }
  if(input.runMarkerField!==undefined)
    modify(input.runMarkerField,()=>input.runId!);
  const kvLine=(record:Record<string,unknown>)=>
    Object.entries(record).map(([key,value])=>key+"="+value).join(" ");
  let syntheticEvent:string;
  if(input.format==="json")syntheticEvent=JSON.stringify(roots);
  else if(input.format==="csv")syntheticEvent=serializeCsvLine(
    csvDefinition(input).columns,roots,csvDefinition(input).separator);
  else if(input.format==="cef")
    syntheticEvent=cefEnvelope(input.source).prefix+serializeCefFields(roots);
  else if(input.format==="leef"){
    const envelope=leefEnvelope(input.source);
    syntheticEvent=envelope.prefix+serializeLeefFields(roots,envelope.separator);
  }else if(input.format==="syslog_rfc5424"){
    const header=syslogEnvelope(input);
    const newTimestamp=currentTimestamp(header.timestamp,nowMs);
    const body=roots.body as Record<string,unknown>;
    syntheticEvent="<"+header.pri+">1 "+newTimestamp+" "+header.hostname+" "+
      header.appname+" "+header.procid+" "+header.msgid+" - "+kvLine(body);
  }else syntheticEvent=kvLine(roots);
  if(Buffer.byteLength(syntheticEvent,"utf8")>16384)
    fail("TESTLAB_OUTPUT_TOO_LARGE");
  return {contract:"parser-studio.synthetic-preview.v0.1",
    format:input.format,syntheticEvent,
    generatedAt:new Date(nowMs).toISOString(),sequence:input.sequence,
    changedPaths:changed,safeToSendToSensor:false,
    runtimeParsingVerified:false,targetSensorVerified:false};
}
