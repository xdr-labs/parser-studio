import {useMemo,useRef,useState} from 'react';
import type {ComponentProps,Dispatch,SetStateAction} from 'react';
import type {ParserDraft} from '../model';
import {preview} from '../parser';
import NormalizationMappingReview from './NormalizationMappingReview';
import {UNRECOGNIZED_SCOPE,applyFamilyMappingEdit,familyScopes,familySource,projectFamilyDraft} from './familyScopedAssist';
import {isCarriedFamilyMapping} from './multiEventRouting';

type Props=ComponentProps<typeof NormalizationMappingReview>;

const REFUSAL:Record<string,string>={
  DESTINATION_COLLISION:'Two field matches would write the same Stellar Cyber field or vendor field name in one event; a name another event type of this parser carries counts too. This change is not applied until the name is free.',
  SOURCE_FORMAT_CHANGED:'A field match cannot change how the log is read. This change is not applied.',
  INVALID_FAMILY:'A field match needs a destination name. This change is not applied until it has one.',
};

/**
 * Map Fields for a parser with event profiles (several event types): one event type at a time, with the same
 * screen as a single-type parser (owner decision of 2026-11-25: automatic, ChatGPT Assisted and manual mapping for
 * every parser). The selected type is shown as an ordinary single-type draft (projectFamilyDraft) on its own
 * records; what the user adds, changes or removes is put back into that type only (applyFamilyMappingEdit), so the
 * other types keep their matches and no destination is written twice in one event.
 */
function EventTypeScopedMappingReview(props:Props){
  const {draft,setDraft,suite}=props;
  const scopes=useMemo(()=>(familyScopes(draft,suite)??[]).filter(scope=>scope.name!==UNRECOGNIZED_SCOPE),[draft,suite]);
  const [chosen,setChosen]=useState('');
  const [picked,setPicked]=useState(0);
  const [notice,setNotice]=useState('');
  // A change that cannot be applied yet (a name typed half-way that is taken, an empty name) stays on the screen as
  // the user typed it, beside the reason; it is applied with the next change that can be (final audit F-3: refusing
  // each such keystroke dropped characters of the name). It belongs to the draft it was made on.
  const [held,setHeld]=useState<{base:ParserDraft;type:string;edited:ParserDraft}|null>(null);
  const active=scopes.find(scope=>scope.name===chosen)??scopes[0];
  const scoped=useMemo(()=>{
    if(!active||!suite)return null;
    const projected=held&&held.base===draft&&held.type===active.name?held.edited:projectFamilyDraft(draft,active.name);
    if(!projected)return null;
    const source=familySource(suite,active);
    return {draft:projected,source,suite:preview(source,projected)};
  },[draft,suite,active,held]);
  if(!active||!scoped)return <NormalizationMappingReview {...props}/>;
  const pendingChange=Boolean(held&&held.base===draft&&held.type===active.name);
  const scopedSetDraft:Dispatch<SetStateAction<ParserDraft>>=next=>{
    const edited=typeof next==='function'?next(scoped.draft):next;
    if(edited===scoped.draft)return;
    const result=applyFamilyMappingEdit(draft,active.name,edited);
    if(!result.ok){
      setHeld({base:draft,type:active.name,edited});
      setNotice(REFUSAL[result.reason]??'The change cannot be applied to this event type ('+result.reason+').');
      return;
    }
    setHeld(null);setNotice('');
    setDraft(result.draft);
  };
  // The unparsed-text evidence of the whole sample, for the records of this type in their order.
  const exact=props.multipassSourceSample!==undefined&&props.multipassSourceSample===props.originalRawSample&&
    props.multipassResiduals?.length===suite?.events.length&&props.multipassRawEvents?.length===suite?.events.length;
  const shared=draft.mappings.length;
  const own=(name:string)=>draft.eventProfiles?.variants.find(variant=>variant.name===name)?.mappings
    .filter(rule=>!isCarriedFamilyMapping(rule)).length??0;
  return <>
    <section className="normalization-runtime-note" role="note" aria-label="Mapping by event type">
      <strong>This parser has {scopes.length} event types with their own field matches</strong>
      <span>Choose an event type to see, add, change or remove its field matches. The other event types keep theirs.
        {shared>0?' '+shared+' field match'+(shared===1?' is':'es are')+' shared by every event type; changing a shared match changes it for all of them.':''}</span>
      <label>Event type to map
        <select aria-label="Mapping event type" value={active.name} disabled={props.pending}
          onChange={event=>{setChosen(event.target.value);setPicked(0);setNotice('');setHeld(null);}}>
          {scopes.map(scope=><option key={scope.name} value={scope.name}>
            {scope.name+' - '+scope.records.length+(scope.records.length===1?' record':' records')+', '+own(scope.name)+' own field match'+(own(scope.name)===1?'':'es')}
          </option>)}
        </select>
      </label>
      {notice&&<p role="alert" aria-label="Event type mapping refusal">{notice}</p>}
    </section>
    <NormalizationMappingReview {...props} key={active.name} draft={scoped.draft} setDraft={scopedSetDraft}
      suite={scoped.suite} selected={picked} setSelected={setPicked}
      onContinue={pendingChange?()=>setNotice('A change on this screen is not applied yet: '+notice+' Finish or undo it before continuing.'):props.onContinue}
      originalRawSample={props.originalRawSample===undefined?undefined:scoped.source}
      multipassSourceSample={exact?scoped.source:undefined}
      multipassResiduals={exact?active.records.map(index=>props.multipassResiduals![index]!):undefined}
      multipassRawEvents={exact?active.records.map(index=>props.multipassRawEvents![index]!):undefined}
      skipGeneratedReconcile jsonataScope={{draft,setDraft,suite}}/>
  </>;
}

export default function EventTypeMappingReview(props:Props){
  // The preview of the sample is computed again after every edit. The last one is shown meanwhile, so the screen
  // and the chosen event type stay while the user edits.
  const last=useRef(props.suite);
  if(props.suite)last.current=props.suite;
  const suite=props.suite??last.current;
  return props.draft.eventProfiles&&suite?<EventTypeScopedMappingReview {...props} suite={suite}/>:<NormalizationMappingReview {...props}/>;
}
