/** Offline per-event field-rule trace, no source or normalized values.
 * A browser-approximation explanation only; not Fluentd or Stellar execution.
 */
import type {MappingRule,SuiteResult} from '../model';
import {lookupFieldValue,safeLocalFieldPath} from '../fieldPaths';

export type RuleTraceStatus=
  'MAPPED'|'SOURCE_MISSING'|'TYPE_FAILED'|'RULE_INVALID'|
  'TARGET_AMBIGUOUS'|'NO_EXTRACTION'|'NOT_EMITTED';
export interface MappingTrace{
  ruleIndex:number;
  status:RuleTraceStatus;
}
export interface BrowserRuleTrace{
  eventId:string;
  line:number;
  totalRules:number;
  mappedCount:number;
  needsReviewCount:number;
  mappings:MappingTrace[];
  nativeVerified:false;
}
const EVENT=/^event-[1-9][0-9]{0,2}$/;
const safeLine=(value:unknown):value is number=>
  typeof value==='number'&&Number.isSafeInteger(value)&&value>=1&&value<=65536;

/** Reviews one explicit current Web Worker event; emits only fixed statuses
 * and numeric identifiers. Never copies worker diagnostic strings/codes,
 * parsed customer values or arbitrary field names to the returned trace.
 * This is descriptive: it does not reproduce native Ruby mapping behavior.
 */
export function traceBrowserMappingRules(
  suite:SuiteResult|undefined,
  mappings:readonly MappingRule[],
  eventId:string,
):BrowserRuleTrace|null{
  if(!suite||suite.engine!=='browser-preview'||
    suite.nativeFluentdVerified!==false||suite.stellarExportVerified!==false||
    !Array.isArray(suite.events)||suite.events.length>500||
    !Array.isArray(mappings)||mappings.length>100||
    typeof eventId!=='string'||!EVENT.test(eventId))return null;
  const event=suite.events.find(x=>x&&x.id===eventId);
  if(!event||!safeLine(event.line)||!['pass','warning','fail'].includes(event.status)||
    !event.fields||typeof event.fields!=='object'||Array.isArray(event.fields)||
    !event.normalized||typeof event.normalized!=='object'||Array.isArray(event.normalized)||
    !Array.isArray(event.diagnostics)||!Array.isArray(event.trace))return null;

  const counts=new Map<string,number>();
  for(const mapping of mappings){
    if(!mapping||typeof mapping.source!=='string'||typeof mapping.target!=='string')return null;
    const target=mapping.target.trim();
    counts.set(target,(counts.get(target)??0)+1);
  }
  const trace:MappingTrace[]=mappings.map((mapping,index)=>{
    const source=mapping.source.trim(),target=mapping.target.trim();
    let status:RuleTraceStatus='NOT_EMITTED';
    if(!safeLocalFieldPath(source)||!safeLocalFieldPath(target)){
      status='RULE_INVALID';
    }else if((counts.get(target)??0)>1){
      status='TARGET_AMBIGUOUS';
    }else if(event.matched!==true||event.extracted!==true){
      status='NO_EXTRACTION';
    }else{
      const present=lookupFieldValue(event.fields,source).found;
      if(!present){
        status='SOURCE_MISSING';
      }else if(Object.prototype.hasOwnProperty.call(event.normalized,target)){
        status='MAPPED';
      }else if(event.diagnostics.some(diag=>diag?.code==='TYPE_ERROR'&&
          diag.field===source&&diag.stage==='normalize')){
        status='TYPE_FAILED';
      }
    }
    return {ruleIndex:index+1,status};
  });
  const mappedCount=trace.filter(x=>x.status==='MAPPED').length;
  return {eventId,line:event.line,totalRules:trace.length,mappedCount,
    needsReviewCount:trace.length-mappedCount,mappings:trace,nativeVerified:false};
}
