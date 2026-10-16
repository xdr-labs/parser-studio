export interface NdjsonObjectStream{
  records:Array<Record<string,unknown>>;
  rawRecords:string[];
  lineEnding:'lf'|'crlf';
}

export type NdjsonStreamResult=
  |{ok:true;stream:NdjsonObjectStream}
  |{ok:false;error:string};

const MAX_STREAM_BYTES=1024*1024;
const MAX_RECORD_BYTES=64*1024;
const MAX_RECORDS=1000;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function jsonSafe(value:unknown,depth:number,state:{nodes:number}):boolean{
  if(depth>16||++state.nodes>10000)return false;
  if(Array.isArray(value))return value.length<=4096&&value.every(item=>jsonSafe(item,depth+1,state));
  if(value&&typeof value==='object'){
    const entries=Object.entries(value as Record<string,unknown>);
    if(entries.length>2048)return false;
    for(const [key,item] of entries){
      if(!key||bytes(key)>256||UNSAFE_KEYS.has(key)||!jsonSafe(item,depth+1,state))return false;
    }
  }
  if(typeof value==='string'&&bytes(value)>64*1024)return false;
  return true;
}

export function parseNdjsonObjectStream(raw:string):NdjsonStreamResult{
  if(!raw||raw.includes('\0')||bytes(raw)>MAX_STREAM_BYTES)
    return {ok:false,error:'Invalid or oversized NDJSON stream'};
  if(!raw.endsWith('\n'))return {ok:false,error:'NDJSON stream must end with a newline'};
  const hasCrlf=raw.includes('\r\n');
  const withoutCrlf=raw.replace(/\r\n/g,'');
  if(withoutCrlf.includes('\r'))return {ok:false,error:'Unsupported NDJSON line ending'};
  if(hasCrlf&&raw.replace(/\r\n/g,'').includes('\n'))
    return {ok:false,error:'Mixed NDJSON line endings are unsupported'};
  const lineEnding:NdjsonObjectStream['lineEnding']=hasCrlf?'crlf':'lf';
  const normalized=hasCrlf?raw.replace(/\r\n/g,'\n'):raw;
  const lines=normalized.slice(0,-1).split('\n');
  if(!lines.length||lines.length>MAX_RECORDS||lines.some(line=>line===''))
    return {ok:false,error:'NDJSON contains an empty record or exceeds the record limit'};
  const records:Array<Record<string,unknown>>=[];
  for(const line of lines){
    if(bytes(line)>MAX_RECORD_BYTES)return {ok:false,error:'NDJSON record exceeds parser limit'};
    let parsed:unknown;
    try{parsed=JSON.parse(line);}catch{return {ok:false,error:'NDJSON record is not valid JSON'};}
    if(!parsed||Array.isArray(parsed)||typeof parsed!=='object')
      return {ok:false,error:'NDJSON security records must be JSON objects'};
    if(!jsonSafe(parsed,0,{nodes:0}))return {ok:false,error:'NDJSON record exceeds bounded object limits'};
    records.push(parsed as Record<string,unknown>);
  }
  return {ok:true,stream:{records,rawRecords:lines,lineEnding}};
}
