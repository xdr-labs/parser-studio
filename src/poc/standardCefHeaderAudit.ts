/** Format-level CEF HEADER audit — not a CEF extension or native parser.
 * ArcSight CEF defines nonempty header fields, escaped pipe/backslash and
 * severity values. Preserve raw encoded value spans and decoded strings
 * separately. No manufacturer- or firmware-specific grammar branching.
 */
import {createHash} from 'node:crypto';
export interface CefAuditedHeaderField{
  name:string;
  decoded:string;sourceLexeme:string;startByte:number;endByte:number;
}
export type CefHeaderDecision={
  raw:string;rawSha256:string;sourceBytes:number;
  disposition:'REVIEW_ONLY_HEADER'|'ABSTAIN_UNSAFE';
  reason:string;fields:CefAuditedHeaderField[];
  branchAttempts:1;maxDepth:1;
  completeEvent:false;nativeStellar:'NOT_VERIFIED';autoPromoted:false;
};
const enc=new TextEncoder();
const names=['cefVersion','deviceVendor','deviceProduct','deviceVersion',
  'deviceEventClassId','name','severity'] as const;
const bounds=[3,63,63,31,1023,512,32];
const severityNamed=new Set(['Unknown','Low','Medium','High','Very-High']);
function validUtf16(raw:string){
  for(let i=0;i<raw.length;i++){
    const a=raw.charCodeAt(i);
    if(a>=0xd800&&a<=0xdbff){
      if(i+1>=raw.length||raw.charCodeAt(++i)<0xdc00||raw.charCodeAt(i)>0xdfff)return false;
    }else if(a>=0xdc00&&a<=0xdfff)return false;
  }
  return true;
}
export function inspectCefStandardHeader(raw:string):CefHeaderDecision{
  const bytes=enc.encode(raw);
  const base:CefHeaderDecision={
    raw,rawSha256:createHash('sha256').update(bytes).digest('hex'),
    sourceBytes:bytes.length,disposition:'ABSTAIN_UNSAFE',
    fields:[],reason:'UNSUPPORTED_OR_UNQUALIFIED_CEF_HEADER',
    branchAttempts:1,maxDepth:1,completeEvent:false,
    nativeStellar:'NOT_VERIFIED',autoPromoted:false,
  };
  const fail=(reason:string)=>({...base,reason});
  if(!raw||bytes.length>8192||!validUtf16(raw)||/[\r\n\0]/.test(raw))
    return fail('OUTSIDE_CEF_SOURCE_BOUNDS');
  const start=raw.startsWith('CEF:')?0:(
    /^(?:<\d{1,3}>)?[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2} +[A-Za-z0-9_.-]{1,255} +CEF:/.test(raw)?
      raw.indexOf('CEF:'):-1
  );
  if(start<0)return fail('UNSUPPORTED_CEF_TRANSPORT_FRAMING');
  let cursor=start+4;
  const fields:CefAuditedHeaderField[]=[];
  for(let index=0;index<names.length;index++){
    const begin=cursor;
    let decoded='',terminated=false;
    while(cursor<raw.length){
      const c=raw[cursor]!;
      if(c==='|'){terminated=true;break;}
      if(c==='\\'){
        const next=raw[cursor+1];
        if(next!=='|'&&next!=='\\')
          return fail('UNKNOWN_CEF_HEADER_ESCAPE');
        decoded+=next;cursor+=2;continue;
      }
      if(c.charCodeAt(0)<32||c.charCodeAt(0)===127)
        return fail('CEF_HEADER_CONTROL_CHARACTER');
      decoded+=c;cursor++;
    }
    if(!terminated)return fail('CEF_HEADER_FIELD_OR_SEPARATOR_MISSING');
    const lexical=raw.slice(begin,cursor);
    if(!lexical||!decoded||enc.encode(decoded).length>bounds[index]!)
      return fail('CEF_MISSING_OR_OVERSIZED_REQUIRED_HEADER');
    if(index===0&&!(decoded==='0'||decoded==='1'))
      return fail('UNSUPPORTED_CEF_VERSION');
    if(index===6&&!(severityNamed.has(decoded)||
      (/^(?:0|[1-9]|10)$/.test(decoded))))
      return fail('CEF_SEVERITY_OUT_OF_STANDARD_RANGE');
    const startByte=enc.encode(raw.slice(0,begin)).length;
    const endByte=enc.encode(raw.slice(0,cursor)).length;
    if(Buffer.from(bytes.subarray(startByte,endByte)).toString('utf8')!==lexical)
      return fail('CEF_ORIGINAL_SOURCE_BYTES_NOT_REPLAYABLE');
    fields.push({name:names[index]!,decoded,sourceLexeme:lexical,
      startByte,endByte});
    cursor++;
  }
  return {...base,fields,disposition:'REVIEW_ONLY_HEADER',
    reason:'STANDARD_CEF_HEADER_ONLY_REVIEW_EXTENSION_UNSCORED'};
}
