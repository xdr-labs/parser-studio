import {useMemo,useState} from 'react';
import type {SuiteResult} from '../model';
import {buildSampleUnionSchema} from './sampleUnionSchema';
import {HelpTip} from './BeginnerHelp';

/**
 * Read-only structural coverage of representative browser-parsed events.
 * No source bytes or field values are sent to the server, stored or used to
 * generate unqualified conditional parser rules.
 */
export default function SampleUnionReview({suite}:{suite?:SuiteResult}){
  const [selector,setSelector]=useState('event_type');
  const summary=useMemo(()=>buildSampleUnionSchema(suite,selector.trim()),[suite,selector]);
  if(!suite||suite.counts.total<2)return null;

  return <details className="auto-parser-recipe sample-union-review"
    aria-label="Compare fields across log types">
    <summary>Optional: compare fields from different log types <HelpTip
      label="Compare fields across log types"
      text="When the same product creates several alert, user, or asset logs, compare field names and missing values before deciding whether one parser can handle them. This does not invent a parser rule."/></summary>
    <p>Parser Studio reviews up to 10 representative events from the current browser sample.
      It keeps event types separate and shows which source fields are present, blank, or missing.</p>
    <label>Field that identifies the event type (optional)
      <input aria-label="Event type source field" value={selector} maxLength={128}
        placeholder="event_type"
        onChange={event=>setSelector(event.target.value)}/>
    </label>
    <div className="sample-union-stats" role="status" aria-label="Structural source coverage">
      <span>Sample events <strong>{summary.totalEvents}</strong></span>
      <span>Examples compared <strong>{summary.reviewed} / 10 maximum</strong></span>
      <span>Groups <strong>{summary.groups.length}</strong></span>
      <span>Not parsed <strong>{summary.unscorable}</strong></span>
    </div>
    {summary.moreSamplesNotUsed>0&&<p role="note">
      {summary.moreSamplesNotUsed} additional parsed event{summary.moreSamplesNotUsed===1?' was':'s were'}
      {' '}not used to infer these field lists. The full sample is still checked separately before file creation.
    </p>}
    {summary.groups.length===0?<p>No extracted fields are ready for comparison yet.</p>:
      <div className="sample-union-groups">
        {summary.groups.map((group,index)=><section
          className="sample-union-group" aria-label={'Log type comparison '+(index+1)} key={group.id}>
          <h3>{group.eventType?'Event type: '+group.eventType:'Event type not identified'}</h3>
          <p>{group.format} · {group.sampleNumbers.length} compared event
            {group.sampleNumbers.length===1?'':'s'} · Source event numbers: {group.sampleNumbers.join(', ')}</p>
          <div className="sample-union-fields" aria-label={'Source field coverage '+(index+1)}>
            {group.fields.length===0?<p>No safely named source fields were found.</p>:
              group.fields.map(field=><div className="sample-union-field" key={field.source}>
                <code>{field.source}</code>
                <span>Present {field.populated}/{group.sampleNumbers.length}</span>
                <span>Blank {field.blank} · Missing {field.missing}</span>
                <strong>{field.semanticStatus==='POSITIONAL_UNVERIFIED'?'Unnamed position — verify definition':
                  field.optional?'Optional in these examples':'Found in every example'}</strong>
              </div>)}
          </div>
        </section>)}
      </div>}
    <p role="note" className="sample-union-scope">
      <strong>Source review only:</strong> field presence does not prove field meaning, conditional routing,
      native Ruby execution, or one-parser compatibility. Map Fields remains the next step.
      Unsupported types are not automatically added to generated parser files.
    </p>
  </details>;
}
