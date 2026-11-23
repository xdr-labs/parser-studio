/** AP2 review action: conservative browser-derived suggestions only.
 * This function never contacts backend or stores raw samples/field values.
 */
import {createDraft,type ParserDraft,type MappingRule,type SuiteResult} from '../model';
import {splitEvents,MAX_DATASET_BYTES,MAX_EVENTS} from '../parser';
import {listSafeLeafPaths,lookupFieldValue} from '../fieldPaths';
import {suggestUnmappedFieldPlan} from './fieldMappingSuggestions';
import {suggestMappingType,suggestNativeJsonType} from './typeSuggestions';
import {createCanonicalMappingPlan} from './canonicalMappingPlan';
import {defaultGuidedOptions} from './contract';
import {toBackendProject} from './backendAdapter';
import {validManufacturerNamespace} from '../../backend/src/vendor-namespace';
import {canonicalIgnoreSourceValue} from '../../backend/src/canonical-operator-contract';
import {selectDraftFormat} from './draftFormatTransition';
import {preview} from '../parser';
import {familyRoutedDraft} from './genericStructuralAutoDraft';
import {READING_FAMILY_DISCRIMINATOR} from './multiEventRouting';
import {analyzeLogEnvelopes,type EnvelopeLedger,type CompilerAssessment}
  from './autoParserEnvelope';

export type AutoParserDraftResult=
  | {ok:true;draft:ParserDraft;sourceFieldCount:number;requiresApproval:boolean;automaticMappingCount:number}
  | {ok:false;reason:'UNTRUSTED_PREVIEW'|'SOURCE_CHANGED'|'MIXED_OR_UNKNOWN'|
      'BOUNDARY_REVIEW'|'COMPILER_UNSUPPORTED'|'COLUMNS_REQUIRED'|'BACKEND_UNAVAILABLE'|
      'BACKEND_UNTRUSTED'|'SOURCE_LIMIT'|'MODEL_REVIEW_REQUIRED'|'MANUFACTURER_UNSUPPORTED'};
const same=(a:unknown,b:unknown)=>JSON.stringify(a)===JSON.stringify(b);
export function prepareAutoParserDraft(
  source:string,draft:ParserDraft,suite:SuiteResult|undefined,
  ledger:EnvelopeLedger,compiler:CompilerAssessment,
  /** eventFamilyRouting false keeps one shared mapping set (Recipe v0.2 cannot represent per-event routing). */
  options:{eventFamilyRouting?:boolean}={},
):AutoParserDraftResult{
  const failed=(reason:Extract<AutoParserDraftResult,{ok:false}>['reason']):AutoParserDraftResult=>
    ({ok:false,reason});
  if(!suite||suite.engine!=='browser-preview'||
    suite.nativeFluentdVerified!==false||suite.stellarExportVerified!==false||
    !Array.isArray(suite.events))return failed('UNTRUSTED_PREVIEW');
  if(typeof source!=='string'||new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES||
    (ledger.boundary!=='single-line'&&
      !(ledger.boundary==='blank-line'&&
        (compiler.format==='java_stacktrace'&&draft.guided?.receiver.framing==='blank_line_java'||
         compiler.format==='json'&&draft.guided?.receiver.framing==='blank_line_json'&&
         draft.guided.receiver.protocols.length===1&&draft.guided.receiver.protocols[0]==='tcp')))||
    ledger.sourceCount>MAX_EVENTS)return failed('SOURCE_LIMIT');
  const records=splitEvents(source,ledger.boundary,MAX_EVENTS+1);
  if(!ledger.complete||ledger.accounted!==records.length||
    records.length!==ledger.sourceCount||
    suite.events.length!==records.length||
    suite.counts.total!==records.length||
    records.some((record,i)=>record.raw!==suite.events[i]?.raw||
      record.line!==suite.events[i]?.line)){
    return failed('SOURCE_CHANGED');
  }
  // Recompute *only the value-free census* to block stale/forged summaries.
  if(!same(analyzeLogEnvelopes(source,ledger.boundary,draft.forwarder,
    draft.guided?.receiver.messageLimit,draft.guided?.receiver.framing),ledger))
    return failed('SOURCE_CHANGED');
  if(compiler.status!=='DRAFT_COMPILABLE'||!compiler.format){
    return failed(compiler.status==='DRAFT_COMPILABLE'?'COMPILER_UNSUPPORTED':compiler.status);
  }
  if(ledger.unsupported!==0||(!compiler.mixedFormats&&ledger.families.length!==1))
    return failed('MIXED_OR_UNKNOWN');
  if(compiler.format==='mixed'){
    const approved=compiler.mixedFormats??[];
    // The server's exact-prefix family dispatcher never trims leading blanks.
    if(approved.length<2||approved.length>4||
       records.some(rec=>!(
         /^(?:\{|CEF:|LEEF:|<\d{1,3}>1 |<\d{1,3}>[A-Z][a-z]{2} |[A-Za-z_][A-Za-z0-9_.-]*=)/.test(rec.raw)||
         (approved.includes('csv')&&rec.raw.includes(draft.csvDelimiter??',')))))
      return failed('MIXED_OR_UNKNOWN');
    const census=[...new Set(ledger.families.map(x=>
      x.envelope==='rfc5424'&&['cef','leef','json','kv'].includes(x.body)?
        'rfc5424_'+x.body:
      x.envelope==='rfc3164'&&['kv','cef','leef'].includes(x.body)?
        'rfc3164_'+x.body:x.envelope==='none'?x.body:'UNSUPPORTED'))].sort();
    if(!same(census,approved))return failed('MIXED_OR_UNKNOWN');
  }
  const relevant=ledger.events.every(entry=>entry.status==='RECOGNIZED');
  if(!relevant)return failed('MIXED_OR_UNKNOWN');

  const opts=draft.guided??defaultGuidedOptions();
  const next:ParserDraft={
    ...selectDraftFormat(draft,compiler.format),
    ...(compiler.format==='mixed'?{mixedFormats:[...(compiler.mixedFormats??[])]}:{}),
    ...(['syslog_rfc3164','syslog_rfc5424'].includes(compiler.format)&&compiler.bodyFormat
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
  // Do not override any modified or user-accepted rules.
  const replaceDefaults=unchangedDefaults;
  if(replaceDefaults){
    const blank:ParserDraft={
      ...next,mappings:[],
      guided:{...opts,classification:{defaultIndex:'Syslog',rules:[]},groups:{}},
    };
    const fieldPlan=suggestUnmappedFieldPlan(
      suite.events.map(event=>event.fields),blank);
    // A field is left out of the automatic mapping only when no event of the sample carries a value for it. One
    // empty occurrence used to remove the field for every event: `user_name=""` on a denied connection dropped
    // `user_name="jkim"` of the allowed one from the generated parser, and nothing else in the output kept it.
    const suggestions=fieldPlan.suggestions.filter(suggestion=>
        suite.events.some(event=>{
          const found=lookupFieldValue(event.fields,suggestion.source);
          if(!found.found)return false;
          const value=found.value;
          return !canonicalIgnoreSourceValue(value,['']);
        }));
    // Source values outside the normalized field-path grammar (for example,
    // nested arrays and intentionally empty CSV cells) remain explicitly
    // accounted for in the original source and review UI. They MUST NOT
    // silently become mapped fields, but they need not block authoring a
    // DRAFT for the independently addressable subset. Only an unresolved
    // *safe* source-path assignment fails this stage closed.
    if(fieldPlan.unresolved.length>0)return failed('MODEL_REVIEW_REQUIRED');
    if(suggestions.length===0)return failed('MODEL_REVIEW_REQUIRED');
    const mappings:MappingRule[]=suggestions.map((suggestion,i)=>{
      const rule:MappingRule={id:'auto-'+String(i+1),authoring:{version:1,origin:'AUTO'},source:suggestion.source,
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
    // Apply only whole-sample, dictionary-backed matches to generated mappings.
    // The user still reviews them in Map Fields; ambiguous candidates stay vendor-only.
    const official=createCanonicalMappingPlan(suite,next).officialCandidates
      .filter(candidate=>candidate.confidence==='HIGH'&&candidate.safeForBulk);
    if(official.length){
      const bySource=new Map(official.map(candidate=>[candidate.source,candidate]));
      const groups={...next.guided.groups};
      next.mappings=next.mappings.map(mapping=>{
        const candidate=bySource.get(mapping.source);
        if(!candidate||candidate.when)return mapping;
        groups[mapping.id]=candidate.group;
        return {...mapping,target:candidate.target,type:candidate.type};
      });
      // Keep the original vendor field for every event. The additional
      // official field exists only for approved, observed transport events.
      for(const candidate of official.filter(item=>item.when)){
        const id='auto-semantic-'+candidate.target;
        if(next.mappings.some(m=>m.id===id))continue;
        next.mappings.push({id,source:candidate.source,target:candidate.target,
          type:candidate.type,when:candidate.when});
        groups[id]=candidate.group;
      }
      next.guided={...next.guided,groups};
    }
    // Vendor-only fields keep the type the JSON itself declares: when every
    // observed value is a JSON boolean or an exact integer, do not fall back to
    // text. Dictionary-matched and top-level mappings are left as decided above.
    next.mappings=next.mappings.map(mapping=>{
      if(mapping.type!=='string'||next.guided?.groups[mapping.id]!=='vendor_fields')return mapping;
      const native=suggestNativeJsonType(suite,mapping);
      return native?{...mapping,type:native.type}:mapping;
    });
    // A mixed sample holds several record families, each read by its own grammar: the same Stellar meaning sits
    // under another source in each (CEF body.src, key=value body.srcip), and a field one family always carries
    // is missing from the others. Deciding the official mappings over the whole sample leaves both to review
    // (golden mixed_envelope_cef_kv: neither family got srcip, dstip, srcport, dstport). The mappings are
    // decided inside each reading family instead and routed by it (@reading_family), as Generic Structural
    // routes by generic.mode; the routed draft is used only when it maps strictly more official values.
    if(next.format==='mixed'&&options.eventFamilyRouting!==false){
      const shared=preview(source,next);
      const routed=familyRoutedDraft(source,next,shared,{discriminator:READING_FAMILY_DISCRIMINATOR,
        carryOtherFamilySources:true,familyOf:event=>event.readingFamily});
      if(routed){
        next.mappings=routed.draft.mappings;next.eventProfiles=routed.draft.eventProfiles;
        next.guided=routed.draft.guided;
      }
    }
  }
  // All paths must be safe for the actual R1.5 backend translator. A browser
  // preview alone must NEVER upgrade an unsupported parser into DRAFT-ready.
  // The generated manufacturer namespace has a fixed printable-ASCII policy. Say
  // so directly: reporting it as a mapping problem sends the user to unrelated
  // field review while the real fix is one character in the manufacturer box.
  if(!validManufacturerNamespace(next.vendor.trim()))return failed('MANUFACTURER_UNSUPPORTED');
  const mapped=toBackendProject(next);
  if(!mapped.ok)return failed('MODEL_REVIEW_REQUIRED');
  // Owner decision Q3-1: a parser made by the Auto Parser keeps every field it reads, also one the sample never
  // showed, in the vendor namespace.
  return {ok:true,draft:{...next,preserveUnmapped:true},sourceFieldCount:allFields.size,
    automaticMappingCount:replaceDefaults?next.mappings.length:0,
    requiresApproval:!unchangedDefaults};
}
