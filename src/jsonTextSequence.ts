import {jsonSourcePreflightError} from './jsonSourcePreflight';
export interface JsonTextSequence{
  records:Array<Record<string,unknown>>;
  rawJsonTexts:string[];
}

export type JsonTextSequenceResult=
  |{ok:true;sequence:JsonTextSequence}
  |{ok:false;error:string};

const RS='\u001e';
const MAX_STREAM_BYTES=1024*1024;
const MAX_RECORD_BYTES=128*1024;
const MAX_RECORDS=1000;
const MAX_NODES=50000;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function safeJson(value:unknown,depth:number,state:{nodes:number}):boolean{
  if(depth>24||++state.nodes>MAX_NODES)return false;
  if(Array.isArray(value))return value.length<=4096&&value.every(item=>safeJson(item,depth+1,state));
  if(value&&typeof value==='object'){
    const entries=Object.entries(value as Record<string,unknown>);
    if(entries.length>2048)return false;
    for(const [key,item] of entries){
      if(!key||bytes(key)>256||UNSAFE_KEYS.has(key)||!safeJson(item,depth+1,state))return false;
    }
  }
  if(typeof value==='string'&&bytes(value)>128*1024)return false;
  return true;
}

export function parseJsonTextSequence(raw:string):JsonTextSequenceResult{
  if(!raw||raw[0]!==RS||raw.includes('\0')||bytes(raw)>MAX_STREAM_BYTES)
    return {ok:false,error:'Invalid or oversized JSON text sequence'};
  const chunks=raw.split(RS);
  if(chunks[0]!==''||chunks.length<2||chunks.length-1>MAX_RECORDS)
    return {ok:false,error:'Malformed JSON text sequence framing'};
  const records:Array<Record<string,unknown>>=[];
  const rawJsonTexts:string[]=[];
  for(let index=1;index<chunks.length;index++){
    const framed=chunks[index]!;
    if(!framed||!framed.endsWith('\n'))return {ok:false,error:'JSON text sequence record must end with LF'};
    const jsonText=framed.slice(0,-1);
    if(!jsonText.trim()||bytes(jsonText)>MAX_RECORD_BYTES)
      return {ok:false,error:'Empty or oversized JSON text sequence record'};
    const fidelityError=jsonSourcePreflightError(jsonText,MAX_RECORD_BYTES);
    if(fidelityError)return {ok:false,error:fidelityError};
    let parsed:unknown;
    try{parsed=JSON.parse(jsonText);}catch{return {ok:false,error:'JSON text sequence record is malformed'};}
    if(!parsed||Array.isArray(parsed)||typeof parsed!=='object')
      return {ok:false,error:'Security JSON text sequence records must be JSON objects'};
    if(!safeJson(parsed,0,{nodes:0}))return {ok:false,error:'JSON text sequence record exceeds bounded limits'};
    records.push(parsed as Record<string,unknown>);
    rawJsonTexts.push(jsonText);
  }
  return {ok:true,sequence:{records,rawJsonTexts}};
}
