/** Bounded generic ordered source-header grammar, explicitly supplied by a
 * publisher/manufacturer contract. No vendor-specific parser branches.
 * Source-field review only; never auto-certifies semantics or native output.
 */
import {inspectGeneralSyslogEnvelope,type SyslogSourceInspection,
  type SyslogOriginalField} from './generalSyslogEnvelopeSpans';

export interface DeclaredSourceHeaderField {
  name:string;
  syntax:'opaque_token'|'unsigned_integer';
  minimum?:number;
  maximum?:number;
}
export interface DeclaredSourceHeaderProfile {
  framing:'INDEPENDENTLY_DECLARED_RFC3164_ORDERED_BODY_HEADER';
  fields:readonly DeclaredSourceHeaderField[];
}

const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const safeFieldName=/^[a-z][a-z0-9_]{0,47}$/;
const headerTokenMax=128;
function fail(raw:string,reason:string,qualified=false):SyslogSourceInspection{
  return {disposition:qualified?'ABSTAIN_UNSAFE':'RAW_ONLY',
    format:'none',fields:[],reason,sourceBytes:encoder.encode(raw).length,
    originalRaw:raw,branchAttempts:0,maxDepth:1,autoPromoted:false,
    manufacturerSemantics:'NOT_CERTIFIED',nativeParser:'NOT_VERIFIED'};
}
function validProfile(profile:DeclaredSourceHeaderProfile):boolean{
  if(profile.framing!=='INDEPENDENTLY_DECLARED_RFC3164_ORDERED_BODY_HEADER'||
    !Array.isArray(profile.fields)||profile.fields.length<1||profile.fields.length>8)
    return false;
  const names=new Set<string>(['pri','month','day','time','hostname','message','appname','procid']);
  for(const f of profile.fields){
    if(!f||typeof f.name!=='string'||!safeFieldName.test(f.name)||names.has(f.name)||
       !['opaque_token','unsigned_integer'].includes(f.syntax))
      return false;
    names.add(f.name);
    if(f.syntax==='opaque_token'&&(f.minimum!==undefined||f.maximum!==undefined))
      return false;
    if(f.syntax==='unsigned_integer'){
      const minimum=f.minimum??0,maximum=f.maximum??Number.MAX_SAFE_INTEGER;
      if(!Number.isSafeInteger(minimum)||!Number.isSafeInteger(maximum)||
         minimum<0||maximum<minimum||maximum>Number.MAX_SAFE_INTEGER)return false;
    }
  }
  return true;
}
export function inspectDeclaredSourceHeader(raw:string,
  profile?:DeclaredSourceHeaderProfile):SyslogSourceInspection{
  if(!profile)return fail(raw,'NO_VERIFIED_DECLARED_SOURCE_HEADER_SCHEMA');
  if(!validProfile(profile))return fail(raw,'INVALID_DECLARED_SOURCE_HEADER_SCHEMA',true);
  const parent=inspectGeneralSyslogEnvelope(raw);
  const message=parent.fields.find(x=>x.name==='message');
  if(parent.disposition!=='REVIEW_ONLY'||parent.format!=='rfc3164'||
     !message||parent.fields.some(x=>x.name==='appname')||
     parent.fields.some(x=>x.name==='procid'))
    return fail(raw,'NOT_QUALIFIED_UNTAGGED_RFC3164_BODY',true);
  const body=message.value;
  if(body.length===0||body.length>8192)return fail(raw,'BODY_OUTSIDE_SOURCE_BOUNDS',true);
  const tokens:SyslogOriginalField[]=[];
  let cursor=0;
  for(const spec of profile.fields){
    const start=cursor;
    while(cursor<body.length&&!/[\s\0]/.test(body[cursor]!)&&
      cursor-start<=headerTokenMax)cursor++;
    const token=body.slice(start,cursor);
    if(!token||token.length>headerTokenMax||token.includes('=')||
       /[\x00-\x1f\x7f]/.test(token))
      return fail(raw,'INVALID_DECLARED_HEADER_TOKEN',true);
    if(spec.syntax==='unsigned_integer'){
      if(!/^[0-9]{1,16}$/.test(token))
        return fail(raw,'INVALID_DECLARED_UNSIGNED_TOKEN',true);
      const value=Number(token),min=spec.minimum??0,
        max=spec.maximum??Number.MAX_SAFE_INTEGER;
      if(!Number.isSafeInteger(value)||value<min||value>max)
        return fail(raw,'DECLARED_UNSIGNED_OUTSIDE_RANGE',true);
    }
    const startByte=message.startByte+encoder.encode(body.slice(0,start)).length;
    const endByte=message.startByte+encoder.encode(body.slice(0,cursor)).length;
    tokens.push({name:spec.name,value:token,type:'string',startByte,endByte});
    // Do not reinterpret additional fields if this exact delimiter contract
    // is absent or ambiguous. The source body remains untouched on failure.
    if(body[cursor]!==' ')return fail(raw,'DECLARED_HEADER_SEPARATOR_MISSING',true);
    let spaces=0;
    while(body[cursor]===' '&&spaces<4){cursor++;spaces++;}
    if(spaces<1||spaces>3||body[cursor]===' ')
      return fail(raw,'DECLARED_HEADER_WHITESPACE_AMBIGUOUS',true);
  }
  if(cursor>=body.length||/[\r\n\0]/.test(body.slice(cursor)))
    return fail(raw,'DECLARED_BODY_MISSING_OR_UNSAFE',true);
  const payloadStart=message.startByte+encoder.encode(body.slice(0,cursor)).length;
  const source=encoder.encode(raw);
  const fields:SyslogOriginalField[]=[
    ...parent.fields.filter(x=>x!==message),
    ...tokens,
    {name:'message',value:body.slice(cursor),type:'string',
     startByte:payloadStart,endByte:source.length},
  ];
  let last=0;
  for(const f of [...fields].sort((a,b)=>a.startByte-b.startByte)){
    if(f.startByte<last||f.startByte<0||f.endByte>source.length||
      f.endByte<=f.startByte)return fail(raw,'DECLARED_SOURCE_SPAN_OVERLAP',true);
    try{
      if(decoder.decode(source.subarray(f.startByte,f.endByte))!==f.value)
        return fail(raw,'DECLARED_SOURCE_SPAN_MISMATCH',true);
    }catch{return fail(raw,'DECLARED_SOURCE_INVALID_UTF8',true);}
    last=f.endByte;
  }
  return {...parent,fields,branchAttempts:parent.branchAttempts+1,
    maxDepth:1,autoPromoted:false,
    reason:'EXPLICIT_DECLARED_ORDERED_SOURCE_HEADER_REVIEW_ONLY',
    manufacturerSemantics:'NOT_CERTIFIED',nativeParser:'NOT_VERIFIED'};
}
