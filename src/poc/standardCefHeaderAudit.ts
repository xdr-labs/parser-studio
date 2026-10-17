/** Format-level CEF HEADER audit — not a CEF extension or native parser.
 * ArcSight CEF defines nonempty header fields, escaped pipe/backslash and
 * severity values. Preserve raw encoded value spans and decoded strings
 * separately. No manufacturer- or firmware-specific grammar branching.
 */
import {createHash} from 'node:crypto';
import {scanCefStandardHeaderGrammar} from '../cefStandardHeaderGrammar';
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
  if(!raw||bytes.length>8192)return fail('OUTSIDE_CEF_SOURCE_BOUNDS');
  const start=raw.startsWith('CEF:')?0:(
    /^(?:<\d{1,3}>)?[A-Z][a-z]{2} +[0-9]{1,2} +[0-9]{2}:[0-9]{2}:[0-9]{2} +[A-Za-z0-9_.-]{1,255} +CEF:/.test(raw)?
      raw.indexOf('CEF:'):-1
  );
  if(start<0)return fail('UNSUPPORTED_CEF_TRANSPORT_FRAMING');
  const scanned=scanCefStandardHeaderGrammar(raw,start);
  if(!scanned.ok)return fail(scanned.reason);
  const fields:CefAuditedHeaderField[]=scanned.fields;
  return {...base,fields,disposition:'REVIEW_ONLY_HEADER',
    reason:'STANDARD_CEF_HEADER_ONLY_REVIEW_EXTENSION_UNSCORED'};
}
