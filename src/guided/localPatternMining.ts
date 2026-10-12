/** P1-AP5 local-only bounded unknown-text structural grouping.
 * This is not Drain3, a Regex generator, or native parser verification.
 * All unpredictable text is replaced by fixed classes before output.
 */
import {MAX_DATASET_BYTES,MAX_EVENTS,splitEvents} from '../parser';
import {analyzeLogEnvelopes} from './autoParserEnvelope';

const SAFE_TOKENS=new Set(['INFO','WARN','WARNING','ERROR','DEBUG','TRACE',
 'GET','POST','PUT','PATCH','DELETE','HEAD','HTTP','HTTPS','ALLOW','DENY',
 'LOGIN','LOGOUT','START','STOP','SUCCESS','FAILED','FAILURE']);
const MAX_TOKENS=48,MAX_GROUPS=12;
export interface StructuralHint{
 fingerprint:string;
 count:number;
 tokenCount:number;
 sourceLines:number[];
 status:'REVIEW_ONLY';
}
export interface StructuralMiningReport{
 contract:'auto-parser.local-structural-hints.v0.1';
 sourceCount:number;
 unknownCount:number;
 groupedCount:number;
 groups:StructuralHint[];
 status:'CANDIDATES'|'NO_UNKNOWN'|'UNSUPPORTED_OR_LIMIT';
 algorithm:'BOUNDED_BROWSER_TOKEN_CLASSES';
 nativeVerified:false;targetVerified:false;customerValuesIncluded:false;
}
function classOf(token:string):string{
 if(/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(token))return '<IP>';
 if(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token))return '<UUID>';
 if(/^https?:\/\//i.test(token))return '<URL>';
 if(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(token))return '<EMAIL>';
 if(/^\d{4}-\d\d-\d\d[T ]\d\d:\d\d/.test(token))return '<TIME>';
 if(/^\d+(?:\.\d+)?$/.test(token))return '<NUMBER>';
 if(/^[^=\s]{1,64}=/.test(token))return '<KEY_VALUE>';
 if(SAFE_TOKENS.has(token.toUpperCase()))return token.toUpperCase();
 if(/^[\[\]{}()|,;:]+$/.test(token))return '<PUNCT>';
 return '<WORD>';
}
export function mineLocalStructuralHints(source:string):StructuralMiningReport{
 const empty=(status:StructuralMiningReport['status'],count=0,unknown=0):StructuralMiningReport=>({
  contract:'auto-parser.local-structural-hints.v0.1',sourceCount:count,unknownCount:unknown,
  groupedCount:0,groups:[],status,algorithm:'BOUNDED_BROWSER_TOKEN_CLASSES',
  nativeVerified:false,targetVerified:false,customerValuesIncluded:false,
 });
 if(typeof source!=='string'||!source.trim()||
   new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES)
   return empty('UNSUPPORTED_OR_LIMIT');
 const records=splitEvents(source,'single-line',MAX_EVENTS+1);
 if(!records.length||records.length>MAX_EVENTS)return empty('UNSUPPORTED_OR_LIMIT');
 const ledger=analyzeLogEnvelopes(source,'single-line');
 if(ledger.status!=='READY'||ledger.accounted!==records.length||!ledger.complete)
   return empty('UNSUPPORTED_OR_LIMIT',records.length);
 const unknown=ledger.events.filter(e=>e.status==='UNKNOWN'&&e.body==='unknown');
 if(!unknown.length)return empty('NO_UNKNOWN',records.length);
 const groups=new Map<string,StructuralHint>();
 let grouped=0;
 for(const event of unknown){
   const record=records[event.sequence-1];
   if(!record||record.line!==event.line)continue;
   const tokens=record.raw.trim().split(/\s+/);
   if(tokens.length===0||tokens.length>MAX_TOKENS)continue;
   const shape=tokens.map(classOf).join(' ');
   if(shape.length>1024)continue;
   let entry=groups.get(shape);
   if(!entry){
     if(groups.size>=MAX_GROUPS)continue;
     entry={fingerprint:shape,count:0,tokenCount:tokens.length,sourceLines:[],status:'REVIEW_ONLY'};
     groups.set(shape,entry);
   }
   entry.count++;entry.sourceLines.push(event.line);grouped++;
 }
 return {contract:'auto-parser.local-structural-hints.v0.1',sourceCount:records.length,
   unknownCount:unknown.length,groupedCount:grouped,
   groups:[...groups.values()].sort((a,b)=>b.count-a.count||a.fingerprint.localeCompare(b.fingerprint)),
   status:grouped?'CANDIDATES':'UNSUPPORTED_OR_LIMIT',algorithm:'BOUNDED_BROWSER_TOKEN_CLASSES',
   nativeVerified:false,targetVerified:false,customerValuesIncluded:false};
}
