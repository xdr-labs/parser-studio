export interface GelfMessage{
  raw:string;
  fields:Record<string,unknown>;
}

export type GelfTcpResult=
  |{ok:true;messages:GelfMessage[]}
  |{ok:false;error:string};

const MAX_STREAM_BYTES=1024*1024;
const MAX_MESSAGE_BYTES=128*1024;
const MAX_MESSAGES=1000;
const UNSAFE_KEYS=new Set(['__proto__','constructor','prototype']);

function bytes(value:string):number{return new TextEncoder().encode(value).byteLength;}

function safeJson(value:unknown,depth:number,state:{nodes:number}):boolean{
  if(depth>16||++state.nodes>10000)return false;
  if(Array.isArray(value))return value.length<=4096&&value.every(item=>safeJson(item,depth+1,state));
  if(value&&typeof value==='object'){
    const entries=Object.entries(value as Record<string,unknown>);
    if(entries.length>2048)return false;
    for(const [key,item] of entries){
      if(!/^[A-Za-z0-9_@.-]{1,128}$/.test(key)||UNSAFE_KEYS.has(key)||!safeJson(item,depth+1,state))return false;
    }
  }
  if(typeof value==='string'&&bytes(value)>64*1024)return false;
  return true;
}

function validGelfObject(value:unknown):value is Record<string,unknown>{
  if(!value||Array.isArray(value)||typeof value!=='object')return false;
  const fields=value as Record<string,unknown>;
  if(fields.version!=='1.1'||typeof fields.host!=='string'||!fields.host||bytes(fields.host)>255||
     typeof fields.short_message!=='string'||!fields.short_message||bytes(fields.short_message)>8192)return false;
  if(fields.full_message!==undefined&&(typeof fields.full_message!=='string'||bytes(fields.full_message)>64*1024))return false;
  if(fields.timestamp!==undefined&&(typeof fields.timestamp!=='number'||!Number.isFinite(fields.timestamp)||fields.timestamp<0))return false;
  if(fields.level!==undefined&&(typeof fields.level!=='number'||!Number.isInteger(fields.level)||fields.level<0||fields.level>7))return false;
  return safeJson(fields,0,{nodes:0});
}

export function parseGelfTcpStream(raw:string):GelfTcpResult{
  if(!raw||bytes(raw)>MAX_STREAM_BYTES||!raw.endsWith('\0'))return {ok:false,error:'Invalid GELF TCP framing'};
  const frames=raw.slice(0,-1).split('\0');
  if(!frames.length||frames.length>MAX_MESSAGES||frames.some(frame=>!frame))
    return {ok:false,error:'GELF TCP contains an empty frame or exceeds the message limit'};
  const messages:GelfMessage[]=[];
  for(const frame of frames){
    if(bytes(frame)>MAX_MESSAGE_BYTES)return {ok:false,error:'GELF message exceeds parser limit'};
    let parsed:unknown;
    try{parsed=JSON.parse(frame);}catch{return {ok:false,error:'GELF frame is not valid JSON'};}
    if(!validGelfObject(parsed))return {ok:false,error:'GELF frame failed required field validation'};
    messages.push({raw:frame,fields:parsed});
  }
  return {ok:true,messages};
}
