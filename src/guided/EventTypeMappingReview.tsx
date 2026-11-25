import {useMemo,useRef,useState} from 'react';
import type {ComponentProps,Dispatch,SetStateAction} from 'react';
import type {ParserDraft} from '../model';
import {preview} from '../parser';
import NormalizationMappingReview from './NormalizationMappingReview';
import {UNRECOGNIZED_SCOPE,applyFamilyMappingEdit,familyScopes,familySource,projectFamilyDraft} from './familyScopedAssist';

type Props=ComponentProps<typeof NormalizationMappingReview>;

const REFUSAL:Record<string,string>={
  DESTINATION_COLLISION:'Two field matches would write the same Stellar Cyber field in one event. Nothing was changed.',
  SOURCE_FORMAT_CHANGED:'A field match cannot change how the log is read. Nothing was changed.',
  INVALID_FAMILY:'The event types of this parser would no longer be valid. Nothing was changed.',
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
  const active=scopes.find(scope=>scope.name===chosen)??scopes[0];
  const scoped=useMemo(()=>{
    if(!active||!suite)return null;
    const projected=projectFamilyDraft(draft,active.name);
    if(!projected)return null;
    const source=familySource(suite,active);
    return {draft:projected,source,suite:preview(source,projected)};
  },[draft,suite,active]);
  if(!active||!scoped)return <NormalizationMappingReview {...props}/>;
  const scopedSetDraft:Dispatch<SetStateAction<ParserDraft>>=next=>{
    const edited=typeof next==='function'?next(scoped.draft):next;
    if(edited===scoped.draft)return;
    const result=applyFamilyMappingEdit(draft,active.name,edited);
    if(!result.ok){setNotice(REFUSAL[result.reason]??'The change could not be applied to this event type ('+result.reason+'). Nothing was changed.');return;}
    setNotice('');
    setDraft(result.draft);
  };
  // The unparsed-text evidence of the whole sample, for the records of this type in their order.
  const exact=props.multipassSourceSample!==undefined&&props.multipassSourceSample===props.originalRawSample&&
    props.multipassResiduals?.length===suite?.events.length&&props.multipassRawEvents?.length===suite?.events.length;
  const shared=draft.mappings.length;
  const own=(name:string)=>draft.eventProfiles?.variants.find(variant=>variant.name===name)?.mappings.length??0;
  return <>
    <section className="normalization-runtime-note" role="note" aria-label="Mapping by event type">
      <strong>This parser has {scopes.length} event types with their own field matches</strong>
      <span>Choose an event type to see, add, change or remove its field matches. The other event types keep theirs.
        {shared>0?' '+shared+' field match'+(shared===1?' is':'es are')+' shared by every event type; changing a shared match changes it for all of them.':''}</span>
      <label>Event type to map
        <select aria-label="Mapping event type" value={active.name} disabled={props.pending}
          onChange={event=>{setChosen(event.target.value);setPicked(0);setNotice('');}}>
          {scopes.map(scope=><option key={scope.name} value={scope.name}>
            {scope.name+' - '+scope.records.length+(scope.records.length===1?' record':' records')+', '+own(scope.name)+' own field match'+(own(scope.name)===1?'':'es')}
          </option>)}
        </select>
      </label>
      {notice&&<p role="alert" aria-label="Event type mapping refusal">{notice}</p>}
    </section>
    <NormalizationMappingReview {...props} key={active.name} draft={scoped.draft} setDraft={scopedSetDraft}
      suite={scoped.suite} selected={picked} setSelected={setPicked}
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
