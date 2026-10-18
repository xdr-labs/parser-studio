import {useEffect,useMemo,useRef,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import type {ParserDraft,SuiteResult,FieldType} from '../model';
import type {BackendCapabilities} from './backendCapabilities';
import {assertBackendProjectSupported} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {HelpTip} from './BeginnerHelp';

export default function ReviewedEventProfilesPanel({
  suite,draft,setDraft,backendCapabilities,source,pending,
}:{
  suite?:SuiteResult;
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  backendCapabilities?:BackendCapabilities;
  source:string;
  pending:boolean;
}){
  const [field,setField]=useState('event_type');
  const [notice,setNotice]=useState('');
  const [approval,setApproval]=useState(false);
  const [edits,setEdits]=useState<Record<string,{target:string;type:FieldType}>>({});
  useEffect(()=>{setEdits({});setApproval(false);},[source,field]);
  const previous=useRef<{source:string;draft:ParserDraft}|null>(null);
  const plan=useMemo(()=>planReviewedEventFamilyDraft(suite,draft,field.trim()),
    [suite,draft,field]);
  const candidate=useMemo(()=>{
    if(!plan.ok)return null;
    const next=structuredClone(plan.candidate);
    for(const variant of next.eventProfiles?.variants??[])
      variant.mappings=variant.mappings.map(rule=>{
        const replacement=edits[rule.id];
        return replacement?{...rule,...replacement}:rule;
      });
    return next;
  },[plan,edits]);
  const available=backendCapabilities?.authoring.conditionalEventProfiles===true&&
    backendCapabilities.authoring.conditionalEventProfilesUnknownPolicy==='reject';
  const apply=()=>{
    if(pending||!available||!candidate||!approval){
      setNotice('Complete the explicit field review and compiler capability check first.');
      return;
    }
    const adapted=toBackendProject(candidate);
    if(!adapted.ok){
      setNotice('The proposed mappings need further review before DRAFT generation.');
      return;
    }
    try{assertBackendProjectSupported(adapted.project,backendCapabilities);}
    catch{setNotice('The connected backend cannot compile this conditional parser.');return;}
    previous.current={source,draft:structuredClone(draft)};
    setDraft(candidate);
    setApproval(false);
    setNotice('Event-family rules applied to this local draft. Check Map Fields and the full sample again.');
  };
  if(!suite||suite.counts.total<2)return null;

  return <details className="auto-parser-recipe" aria-label="Configure one parser for event types">
    <summary>Optional: one parser for several event types
      <HelpTip label="One reviewed multi-type parser"
        text="Use this only when all events contain an explicit discriminator. Review all shared and type-specific mappings. Unknown types must be rejected, never mapped by guessing."/></summary>
    <p>Choose the field that identifies each event type. The preview uses every
      extracted source event and does not infer field meanings from a manufacturer name.</p>
    <label>Event-type field
      <input aria-label="One-parser event discriminator" value={field} maxLength={128}
        placeholder="event_type" onChange={event=>{setField(event.target.value);setApproval(false);}}/>
    </label>
    {plan.ok?<div aria-label="Proposed event type rules">
      <p>{plan.types.length} reviewed types in {suite.counts.total} source events.
        {' '}{plan.commonCount} common field mapping(s) remain shared.</p>
      {plan.types.map(group=><div className="reviewed-event-family" key={group.name}><p>
        <strong>{group.name}</strong> · explicit source value: <code>{group.sourceValue}</code>
        {' '}· {group.fieldCount} type-specific field(s)</p>
        {group.fieldCount>0&&<details className="family-mapping-details"
          aria-label={'Type-specific mappings for '+group.name}>
          <summary>Review {group.fieldCount} field mapping(s)</summary>
          {plan.candidate.eventProfiles?.variants.find(v=>v.name===group.name)?.mappings.map(rule=>
            <div className="family-mapping-row" key={rule.id}>
              <code>{rule.source}</code>
              <label>Output field
                <input aria-label={group.name+' output for '+rule.source}
                  value={edits[rule.id]?.target??rule.target} maxLength={128}
                  onChange={event=>{
                    const target=event.target.value;
                    setEdits(old=>({...old,[rule.id]:{
                      target,type:old[rule.id]?.type??rule.type,
                    }}));setApproval(false);
                  }}/>
              </label>
              <label>Value type
                <select aria-label={group.name+' type for '+rule.source}
                  value={edits[rule.id]?.type??rule.type}
                  onChange={event=>{
                    const type=event.target.value as FieldType;
                    setEdits(old=>({...old,[rule.id]:{
                      target:old[rule.id]?.target??rule.target,type,
                    }}));setApproval(false);
                  }}>
                  {(['string','integer','boolean','ip','port','timestamp'] as const).map(type=>
                    <option key={type} value={type}>{type}</option>)}
                </select>
              </label>
            </div>)}
        </details>}
      </div>)}
      <p>{plan.removedCommonCount} previous all-type mapping(s) become conditional.
        {' '}{plan.removedClassifiers} incompatible classification rule(s) are removed
        from the proposed DRAFT. Save a Local Version before accepting this change.</p>
      <p>An unknown type always fails closed. A single parser DRAFT is permitted
        only if the backend advertises the exact conditional compiler capability.</p>
    </div>:<p role="note">{plan.reason}</p>}
    {!available&&<p role="note">The connected local compiler has not advertised
      this conditional parser feature. Source comparison remains available,
      but no conditional DRAFT will be applied.</p>}
    <label><input type="checkbox" aria-label="Approve explicit family routing changes"
      checked={approval} onChange={event=>setApproval(event.target.checked)}/>
      I reviewed the event types, changed mappings and classification rules.</label>
    <div className="manual-boundary-buttons">
      <button type="button" onClick={apply}
        disabled={!plan.ok||!available||pending||!approval}>
        Apply reviewed event types to this parser
      </button>
      {previous.current?.source===source&&<button type="button" onClick={()=>{
        const saved=previous.current;
        if(!saved||saved.source!==source)return;
        setDraft(saved.draft);previous.current=null;
        setNotice('Previous mappings restored. Source logs were never changed.');
      }}>Undo event-family routing</button>}
    </div>
    {draft.eventProfiles&&<p role="status" aria-label="Configured event profiles">
      Current local draft: {draft.eventProfiles.variants.length} explicit event types.
      Generated files remain DRAFT / target NOT VERIFIED.</p>}
    {notice&&<p role="status">{notice}</p>}
  </details>;
}
