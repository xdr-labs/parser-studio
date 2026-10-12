/** P1-AP5: strictly offline structural hints from reviewed PUBLIC SYNTHETIC templates.
 * No Drain3 execution, automatic parser reuse, customer log storage or native claim.
 */
import type {SuiteResult} from '../model';
import {listSafeLeafPaths} from '../fieldPaths';
import {compareBrowserSuites} from './autoParserRegression';
import {analyzeLogEnvelopes,type EnvelopeLedger} from './autoParserEnvelope';
import {loadStarterTemplate,starterTemplateIds,type StarterTemplateId} from './sampleTemplates';

export interface KnownParserHint{
 id:StarterTemplateId;
 label:string;
 coveragePercent:number;
 matchedFieldCount:number;
 expectedFieldCount:number;
 decision:'REVIEW_TEMPLATE_ONLY';
 nativeVerified:false;
}
export interface FingerprintMatchReport{
 contract:'auto-parser.known-fingerprints.v0.1';
 sourceCount:number;
 familyCount:number;
 hints:KnownParserHint[];
 status:'CANDIDATES'|'NO_MATCH'|'MIXED_OR_UNKNOWN';
 privateSampleIncluded:false;
 persisted:false;
 nativeVerified:false;
}
function signature(id:StarterTemplateId){
 if(id==='rfc5424_cef')return 'rfc5424/cef';
 if(id==='rfc5424_leef')return 'rfc5424/leef';
 if(id==='syslog_rfc5424')return 'rfc5424/unknown';
 return 'none/'+id;
}
export function matchKnownParserFingerprints(source:string,suite:SuiteResult):FingerprintMatchReport{
 // Reuse strict exact-source count, event order, flag and forged aggregate guards.
 compareBrowserSuites(source,suite,suite);
 const ledger:EnvelopeLedger=analyzeLogEnvelopes(source,'single-line');
 const base={contract:'auto-parser.known-fingerprints.v0.1' as const,
   sourceCount:ledger.sourceCount,familyCount:ledger.families.length,
   privateSampleIncluded:false as const,persisted:false as const,nativeVerified:false as const};
 if(ledger.status!=='READY'||ledger.accounted!==ledger.sourceCount||
    ledger.unsupported>0||ledger.families.length!==1)
   return {...base,status:'MIXED_OR_UNKNOWN',hints:[]};
 const family=ledger.families[0]!;
 const current=family.envelope+'/'+family.body;
 let sharedFields=new Set<string>(listSafeLeafPaths(suite.events[0]!.fields));
 for(const e of suite.events){
   if(!e.extracted||!e.fields||typeof e.fields!=='object')
     return {...base,status:'NO_MATCH',hints:[]};
   const eventFields=new Set(listSafeLeafPaths(e.fields));
   sharedFields=new Set([...sharedFields].filter((key:string)=>eventFields.has(key)));
 }
 const hints:KnownParserHint[]=[];
 for(const id of starterTemplateIds){
   if(signature(id)!==current)continue;
   const preset=loadStarterTemplate(id);
   const fields=[...new Set(preset.draft.mappings.map(x=>x.source))];
   const count=fields.filter(x=>sharedFields.has(x)).length;
   const score=fields.length?Math.round(count/fields.length*100):0;
   if(score<50||count===0)continue;
   hints.push({id,label:preset.label,coveragePercent:score,
     matchedFieldCount:count,expectedFieldCount:fields.length,
     decision:'REVIEW_TEMPLATE_ONLY',nativeVerified:false});
 }
 hints.sort((a,b)=>b.coveragePercent-a.coveragePercent||a.id.localeCompare(b.id));
 return {...base,status:hints.length?'CANDIDATES':'NO_MATCH',hints:hints.slice(0,3)};
}
