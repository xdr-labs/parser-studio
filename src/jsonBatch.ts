export interface JsonObjectBatch{
  mode:'top_level_array'|'records_wrapper';
  records:Array<Record<string,unknown>>;
  container?:Record<string,unknown>;
}

export type JsonObjectBatchResult=
  |{ok:true;batch:JsonObjectBatch}
  |{ok:false;error:string};

const MAX_BYTES=1024*1024;
const MAX_RECORDS=1000;
const MAX_NODES=50000;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function safeJson(value:unknown,depth:number,state:{nodes:number}):boolean{
  if(depth>24||++state.nodes>MAX_NODES)return false;
  if(Array.isArray(value)){
    if(value.length>4096)return false;
    return value.every(item=>safeJson(item,depth+1,state));
  }
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

function objectRecords(value:unknown):Array<Record<string,unknown>>|null{
  if(!Array.isArray(value)||value.length<1||value.length>MAX_RECORDS)return null;
  const records:Array<Record<string,unknown>>=[];
  for(const item of value){
    if(!item||Array.isArray(item)||typeof item!=='object')return null;
    records.push(item as Record<string,unknown>);
  }
  return records;
}

export function parseJsonObjectBatch(raw:string):JsonObjectBatchResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_BYTES)
    return {ok:false,error:'Invalid or oversized JSON batch'};
  let parsed:unknown;
  try{parsed=JSON.parse(raw);}catch{return {ok:false,error:'JSON batch is malformed'};}
  if(!safeJson(parsed,0,{nodes:0}))return {ok:false,error:'JSON batch exceeds bounded object limits'};

  const direct=objectRecords(parsed);
  if(direct)return {ok:true,batch:{mode:'top_level_array',records:direct}};

  if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed)){
    const container=parsed as Record<string,unknown>;
    const records=objectRecords(container.Records);
    if(records){
      const metadata:Record<string,unknown>={};
      for(const [key,value] of Object.entries(container)){
        if(key==='Records')continue;
        metadata[key]=value;
      }
      return {ok:true,batch:{mode:'records_wrapper',records,...(Object.keys(metadata).length?{container:metadata}:{})}};
    }
  }
  return {ok:false,error:'JSON batch must be an object array or a Records wrapper'};
}
