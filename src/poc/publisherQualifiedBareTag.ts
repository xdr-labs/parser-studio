/** Opt-in, vendor-neutral source observer for a publisher-asserted bare RFC3164 APP tag.
 * Proof is partial source field identity only, not a native/semantic acceptance.
 */
import {inspectGeneralSyslogEnvelope,type SyslogSourceInspection,
  type SyslogOriginalField} from './generalSyslogEnvelopeSpans';

export interface QualifiedBareTagContext {
  sourceFraming:'PUBLISHER_ASSERTED_RFC3164_BARE_APP_TAG';
}

const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});

function abstain(raw:string,reason:string,unsafe=false):SyslogSourceInspection{
  return {disposition:unsafe?'ABSTAIN_UNSAFE':'RAW_ONLY',format:'none',
    fields:[],reason,sourceBytes:encoder.encode(raw).length,originalRaw:raw,
    branchAttempts:0,maxDepth:1,autoPromoted:false,
    manufacturerSemantics:'NOT_CERTIFIED',nativeParser:'NOT_VERIFIED'};
}
function verify(raw:Uint8Array,fields:SyslogOriginalField[]):boolean{
  let last=0;
  for(const field of [...fields].sort((a,b)=>a.startByte-b.startByte)){
    if(field.startByte<last||field.startByte<0||field.endByte>raw.length||
      field.endByte<=field.startByte)return false;
    try{if(decoder.decode(raw.subarray(field.startByte,field.endByte))!==field.value)
      return false;}
    catch{return false;}
    last=field.endByte;
  }
  return true;
}

/** Never infer a publisher framing contract from appearance alone. */
export function inspectPublisherQualifiedBareTag(raw:string,
  context?:QualifiedBareTagContext):SyslogSourceInspection{
  if(context?.sourceFraming!=='PUBLISHER_ASSERTED_RFC3164_BARE_APP_TAG')
    return abstain(raw,'NO_INDEPENDENT_BARE_TAG_FRAMING_ASSERTION');
  const base=inspectGeneralSyslogEnvelope(raw);
  if(base.disposition!=='REVIEW_ONLY'||base.format!=='rfc3164'||
    base.fields.some(f=>f.name==='appname'))
    return abstain(raw,'NO_UNAMBIGUOUS_RFC3164_BARE_TAG_BOUNDARY',true);
  const originalMessage=base.fields.find(f=>f.name==='message');
  if(!originalMessage)
    return abstain(raw,'MISSING_PUBLISHER_BARE_TAG_CANDIDATE',true);
  // The entire original envelope was already checked by the bounded generic
  // lexer. Only split the first APP token when the transport is independently
  // identified as bare-tag RFC3164; never identify the manufacturer by name.
  const m=/^([A-Za-z][A-Za-z0-9_.@/-]{0,127})( {1,3})(\S[^\r\n\0]*)$/.exec(originalMessage.value);
  if(!m||m[1]==='CEF'||m[1]==='LEEF'||m[1]==='-')
    return abstain(raw,'AMBIGUOUS_OR_UNSUPPORTED_BARE_TAG_BOUNDARY',true);
  const bytes=encoder.encode(raw);
  const appEnd=originalMessage.startByte+encoder.encode(m[1]!).length;
  const msgStart=appEnd+encoder.encode(m[2]!).length;
  const additions:SyslogOriginalField[]=[
    {name:'appname',value:m[1]!,type:'string',
     startByte:originalMessage.startByte,endByte:appEnd},
    {name:'message',value:m[3]!,type:'string',
     startByte:msgStart,endByte:bytes.length},
  ];
  const fields=[...base.fields.filter(f=>f!==originalMessage),...additions];
  if(!verify(bytes,fields))
    return abstain(raw,'SOURCE_BARE_TAG_BYTE_SPAN_REPLAY_FAILED',true);
  return {...base,fields,
    reason:'EXPLICIT_PUBLISHER_QUALIFIED_BARE_RFC3164_TAG_SOURCE_REVIEW_ONLY',
    branchAttempts:base.branchAttempts+1,maxDepth:1,
    autoPromoted:false,manufacturerSemantics:'NOT_CERTIFIED',
    nativeParser:'NOT_VERIFIED'};
}
