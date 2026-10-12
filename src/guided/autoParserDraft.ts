/** AP2 review action: conservative browser-derived suggestions only.
 * This function never contacts backend or stores raw samples/field values.
 */
import {createDraft,type ParserDraft,type MappingRule,type SuiteResult} from '../model';
import {splitEvents,MAX_DATASET_BYTES,MAX_EVENTS} from '../parser';
import {listSafeLeafPaths} from '../fieldPaths';
import {suggestUnmappedFields} from './fieldMappingSuggestions';
import {suggestMappingType} from './typeSuggestions';
import {defaultGuidedOptions} from './contract';
import {toBackendProject} from './backendAdapter';
import {analyzeLogEnvelopes,type EnvelopeLedger,type CompilerAssessment}
  from './autoParserEnvelope';

export type AutoParserDraftResult=
  | {ok:true;draft:ParserDraft;sourceFieldCount:number;requiresApproval:boolean;automaticMappingCount:number}
  | {ok:false;reason:'UNTRUSTED_PREVIEW'|'SOURCE_CHANGED'|'MIXED_OR_UNKNOWN'|
      'BOUNDARY_REVIEW'|'COMPILER_UNSUPPORTED'|'COLUMNS_REQUIRED'|'BACKEND_UNAVAILABLE'|
      'BACKEND_UNTRUSTED'|'SOURCE_LIMIT'|'MODEL_REVIEW_REQUIRED'};
const same=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b);
export function prepareAutoParserDraft(
  source:string,draft:ParserDraft,suite:SuiteResult|undefined,
  ledger:EnvelopeLedger,compiler:CompilerAssessment,
):AutoParserDraftResult{
  const failed=(reason:Extract<AutoParserDraftResult,{ok:false}>['reason']):AutoParserDraftResult=>
    ({ok:false,reason});
  if(!suite||suite.engine!=='browser-preview'||
    suite.nativeFluentdVerified!==false||suite.stellarExportVerified!==false||
    !Array.isArray(suite.events))return failed('UNTRUSTED_PREVIEW');
  if(typeof source!=='string'||new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES||
    ledger.boundary!=='single-line'||ledger.sourceCount>MAX_EVENTS)return failed('SOURCE_LIMIT');
  const records=splitEvents(source,'single-line',MAX_EVENTS+1);
  if(!ledger.complete||ledger.accounted!==records.length||
    records.length!==ledger.sourceCount||
    suite.events.length!==records.length||
    suite.counts.total!==records.length||
    records.some((record,i)=>record.raw!==suite.events[i]?.raw||
      record.line!==suite.events[i]?.line)){
    return failed('SOURCE_CHANGED');
  }
  // Recompute *only the value-free census* to block stale/forged summaries.
  if(!same(analyzeLogEnvelopes(source,'single-line'),ledger))return failed('SOURCE_CHANGED');
  if(compiler.status!=='DRAFT_COMPILABLE'||!compiler.format){
    return failed(compiler.status==='DRAFT_COMPILABLE'?'COMPILER_UNSUPPORTED':compiler.status);
  }
  if(ledger.unsupported!==0||ledger.families.length!==1)
    return failed('MIXED_OR_UNKNOWN');
  const relevant=ledger.events.every(entry=>entry.status==='RECOGNIZED');
  if(!relevant)return failed('MIXED_OR_UNKNOWN');

  const opts=draft.guided??defaultGuidedOptions();
  const next:ParserDraft={
    ...draft,format:compiler.format,
    ...(compiler.format==='syslog_rfc5424'&&compiler.bodyFormat
      ?{syslogBodyFormat:compiler.bodyFormat}:{}),
  };
  const allFields=new Set<string>();
  for(const event of suite.events){
    if(event.fields&&typeof event.fields==='object'&&!Array.isArray(event.fields)){
      for(const field of listSafeLeafPaths(event.fields))allFields.add(field);
    }
  }
  const base=createDraft();
  const unchangedDefaults=
    same(draft.mappings,base.mappings)&&
    same(opts.groups,defaultGuidedOptions().groups)&&
    same(opts.classification,defaultGuidedOptions().classification);
  const mappingsCoverSource=next.mappings.every(m=>allFields.has(m.source));
  // Do not override any modified or user-accepted rules.
  const replaceDefaults=unchangedDefaults&&!mappingsCoverSource;
  if(replaceDefaults){
    const blank:ParserDraft={
      ...next,mappings:[],
      guided:{...opts,classification:{defaultIndex:'Syslog',rules:[]},groups:{}},
    };
    const suggestions=suggestUnmappedFields(
      suite.events.map(event=>event.fields),blank);
    if(suggestions.length===0)return failed('MODEL_REVIEW_REQUIRED');
    const mappings:MappingRule[]=suggestions.map((suggestion,i)=>{
      const rule:MappingRule={id:'auto-'+String(i+1),source:suggestion.source,
        target:suggestion.target,type:suggestion.type};
      const supported=suggestMappingType(suite,rule);
      // Strong, bounded conversion evidence only; never guess timezone or
      // official schema meaning from an ambiguous field label.
      if(supported&&supported.evidence===suite.events.length&&
        ['ip','port','boolean','integer'].includes(supported.type))
        rule.type=supported.type;
      return rule;
    });
    next.mappings=mappings;
    next.guided={...opts,groups:Object.fromEntries(suggestions.map((s,i)=>['auto-'+String(i+1),s.group])),
      classification:{defaultIndex:'Syslog',rules:[]}};
  }
  // All paths must be safe for the actual R1.5 backend translator. A browser
  // preview alone must NEVER upgrade an unsupported parser into DRAFT-ready.
  const mapped=toBackendProject(next);
  if(!mapped.ok)return failed('MODEL_REVIEW_REQUIRED');
  return {ok:true,draft:next,sourceFieldCount:allFields.size,
    automaticMappingCount:replaceDefaults?next.mappings.length:0,
    requiresApproval:!unchangedDefaults};
}
