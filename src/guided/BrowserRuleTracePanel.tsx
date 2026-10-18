import {ChevronRight,ClipboardCheck} from 'lucide-react';
import type {MappingRule,SuiteResult} from '../model';
import {traceBrowserMappingRules,type RuleTraceStatus} from './browserRuleTrace';

interface Props{
  suite:SuiteResult|undefined;
  pending:boolean;
  mappings:readonly MappingRule[];
  selectedEventId:string;
  onSelectEvent:(eventId:string)=>void;
  onEditMapping:(index:number)=>void;
}
const LABELS:Record<RuleTraceStatus,string>={
  MAPPED:'Output written in browser preview',
  SOURCE_MISSING:'Source field absent in this event',
  TYPE_FAILED:'Source value failed reviewed type conversion',
  RULE_INVALID:'Unsupported or unsafe rule path',
  TARGET_AMBIGUOUS:'Multiple rules share this destination',
  NO_EXTRACTION:'Extraction did not produce a matching event',
  NOT_EMITTED:'Output not emitted; cause not established',
};

export default function BrowserRuleTracePanel({
  suite,pending,mappings,selectedEventId,onSelectEvent,onEditMapping,
}:Props){
  const ready=!pending&&suite?.engine==='browser-preview'&&
    suite.nativeFluentdVerified===false&&suite.stellarExportVerified===false;
  const id=ready&&(suite?.events.some(e=>e.id===selectedEventId)?selectedEventId:
    suite.events[0]?.id)||'';
  const trace=ready?traceBrowserMappingRules(suite,mappings,id):null;
  return <details className="guided-rule-trace" aria-label="Browser-only per-rule event trace">
    <summary><ClipboardCheck size={16}/> Inspect Rule-by-Rule Outcome (Local Only)</summary>
    <p>For a single selected browser-preview event, inspect each mapping's
      reviewed outcome without displaying extracted, normalized or raw values.
      This is not native Ruby/Fluentd execution, multi-family routing or DP
      ingestion verification.</p>
    {ready&&suite?.events.length
      ? <label className="guided-field"><span>Event to Trace</span>
        <select aria-label="Trace event number" value={id}
          onChange={e=>onSelectEvent(e.target.value)}>
          {suite.events.map(event=><option key={event.id} value={event.id}>
            Event #{event.line} · {event.status.toUpperCase()}
          </option>)}
        </select>
      </label>
      : <small>Run a current local browser preview to inspect field rules.</small>}
    {trace&&<div className="guided-rule-trace-results" aria-label="Value-free per-rule results">
      <strong>Event #{trace.line}: {trace.mappedCount}/{trace.totalRules}
        {' '}rules emitted · {trace.needsReviewCount} need review</strong>
      <div className="guided-rule-trace-list">
        {trace.mappings.map(rule=><div key={rule.ruleIndex} className="guided-rule-trace-row">
          <div><strong>Mapping Rule #{rule.ruleIndex}</strong>
            <span>{LABELS[rule.status]}</span>
            <small>{rule.status}</small>
          </div>
          <button className="guided-cta-secondary" type="button"
            aria-label={'Review mapping rule '+rule.ruleIndex}
            onClick={()=>onEditMapping(rule.ruleIndex-1)}>
            Review Mapping <ChevronRight size={14}/>
          </button>
        </div>)}
      </div>
      {trace.totalRules===0&&<small>No mapping rules exist in this draft.</small>}
      <small>Only fixed reason codes and numeric rule/event identifiers are
        shown. Unreviewed diagnostics cannot inject arbitrary source text.
        Browser results do not prove vendor parser compatibility.</small>
    </div>}
  </details>;
}
