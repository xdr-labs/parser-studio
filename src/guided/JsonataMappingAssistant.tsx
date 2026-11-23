import {useEffect,useMemo,useState} from 'react';
import type {Dispatch,ReactNode,SetStateAction} from 'react';
import {CheckCircle2,ClipboardCopy,ShieldAlert,Sparkles,X} from 'lucide-react';
import type {ParserDraft,SuiteResult} from '../model';
import {
  createJsonataMappingPrompt,jsonataDraftSignature,reviewJsonataMapping,
  applyReviewedJsonataMapping,type ReviewedJsonataMapping,
} from './jsonataMappingAssist';
import {preview} from '../parser';
import {familyPromptContext,familyScopes,mergeFamilyCandidate,projectFamilyDraft,UNRECOGNIZED_SCOPE} from './familyScopedAssist';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  suite:SuiteResult;
  pending:boolean;
}
interface Prepared {prompt:string;sha256:string;signature:string}
/** One event type of a parser with event profiles, handled as an ordinary single-type draft. */
interface FamilyScopeBinding{label:string;context:string;selector:ReactNode;onApply:(candidate:ParserDraft)=>string|null}

function JsonataMappingCore({draft,setDraft,suite,pending,familyScope}:Props&{familyScope?:FamilyScopeBinding}){
  const [open,setOpen]=useState(false);
  const [includeValues,setIncludeValues]=useState(false);
  const [prepared,setPrepared]=useState<Prepared|null>(null);
  const [reply,setReply]=useState('');
  const [review,setReview]=useState<ReviewedJsonataMapping[]|null>(null);
  const [selected,setSelected]=useState<number[]>([]);
  const [approved,setApproved]=useState(false);
  const [approveUncertain,setApproveUncertain]=useState(false);
  const [error,setError]=useState('');
  const [notice,setNotice]=useState('');
  const [busy,setBusy]=useState(false);
  const signature=useMemo(()=>jsonataDraftSignature(suite,draft),[suite,draft]);
  useEffect(()=>{
    setPrepared(null);setReview(null);setSelected([]);
    setApproved(false);setApproveUncertain(false);setError('');setReply('');
  },[signature]);

  const prepare=async()=>{
    setBusy(true);setError('');setNotice('');setReview(null);
    setSelected([]);setApproved(false);setApproveUncertain(false);
    try{
      const next=await createJsonataMappingPrompt(suite,draft,includeValues,
        familyScope?{eventProfileContext:familyScope.context}:{});
      setPrepared({prompt:next.prompt,sha256:next.sha256,signature});
    }catch(err){
      setError(err instanceof Error?err.message:'Could not create a local mapping prompt.');
    }finally{setBusy(false);}
  };
  const copy=async()=>{
    if(!prepared||prepared.signature!==signature)return;
    try{
      await navigator.clipboard.writeText(prepared.prompt);
      setNotice('Prompt copied. Paste it into ChatGPT, then paste the strict JSON response below.');
    }catch{
      setError('Clipboard access was not available. Select and copy the prompt text manually.');
    }
  };
  const check=async()=>{
    if(!prepared||prepared.signature!==signature){
      setError('The parsed sample or mappings changed. Prepare a new prompt first.');return;
    }
    setBusy(true);setError('');setReview(null);setSelected([]);
    try{
      const result=await reviewJsonataMapping(reply,suite,draft,prepared.sha256);
      if(!result.ok){setError(result.reason);return;}
      setReview(result.rows);
      setSelected(result.rows.flatMap((row,i)=>row.status==='READY'?[i]:[]));
      setApproved(false);setApproveUncertain(false);
      setNotice('This is a review-only proposal. No parser mappings have changed.');
    }catch{setError('Could not validate the pasted mapping response.');}
    finally{setBusy(false);}
  };
  const chosen=review?.filter((_,index)=>selected.includes(index))??[];
  const hasUncertain=chosen.some(row=>row.status==='CHECK_FIRST');
  const apply=()=>{
    if(!review||!prepared||prepared.signature!==signature){
      setError('The source or current field mappings changed. Prepare a new prompt.');return;
    }
    if(!approved||(hasUncertain&&!approveUncertain)){
      setError('Review and explicitly approve every selected mapping before applying.');return;
    }
    const result=applyReviewedJsonataMapping(draft,suite,chosen);
    if(!result.ok){setError(result.reason);return;}
    if(familyScope){
      const refused=familyScope.onApply(result.draft);
      if(refused){setError(refused);return;}
    }else setDraft(result.draft);
    setNotice('Applied '+chosen.length+' reviewed native-compatible field mapping'+(chosen.length===1?'':'s')+
      (familyScope?' to event type '+familyScope.label+'. Other event types are unchanged':'')+
      '. Check the refreshed field preview before creating a parser.');
    setReview(null);setSelected([]);setPrepared(null);setApproved(false);setReply('');
    setError('');
  };
  const setChecked=(index:number,checked:boolean)=>
    setSelected(old=>checked?[...old,index]:old.filter(item=>item!==index));

  return <section className="normalization-suggestions jsonata-mapping-assistant"
    aria-label="ChatGPT JSONata field mapping">
    <div className="normalization-section-head">
      <div>
        <h3>Improve with ChatGPT (JSONata)</h3>
        <p>Ask ChatGPT for Stellar field matches using the JSON-like parsed fields. Review and test locally before applying them.</p>
      </div>
      <button type="button" aria-label="Improve mappings with ChatGPT JSONata"
        aria-expanded={open} onClick={()=>setOpen(value=>!value)}>
        <Sparkles size={15}/>{open?'Close assistant':'Improve with ChatGPT'}
      </button>
    </div>
    {!open?null:<div className="jsonata-assist-body">
      {familyScope?.selector}
      <div className="normalization-runtime-note" role="note">
        <strong>Review-only, manual copy and paste</strong>
        <span>Nothing is sent to ChatGPT automatically. By default the prompt includes field names, types and coverage, but no raw logs or observed values. Review it before sharing.</span>
        <span>Only JSONata field selectors are supported. Functions, arithmetic and conditionals cannot be applied to generated Ruby parser files.</span>
      </div>
      <div className="jsonata-assist-step">
        <h4>1. Prepare a mapping prompt</h4>
        <label className="jsonata-assist-check">
          <input type="checkbox" checked={includeValues} disabled={busy||pending}
            aria-label="Include observed values in ChatGPT mapping prompt"
            onChange={event=>{setIncludeValues(event.target.checked);setPrepared(null);setReview(null);setSelected([]);}}/>
          Include up to two original field values per source path (may contain sensitive information).
        </label>
        <button type="button" disabled={busy||pending} onClick={()=>void prepare()}>
          <Sparkles size={14}/>Prepare Mapping Prompt
        </button>
        {prepared?.signature===signature&&<>
          <label>Review the exact prompt before copying
            <textarea aria-label="ChatGPT JSONata mapping prompt" readOnly rows={7} value={prepared.prompt}/>
          </label>
          <button type="button" disabled={busy||pending} onClick={()=>void copy()}>
            <ClipboardCopy size={14}/>Copy Mapping Prompt
          </button>
        </>}
      </div>
      {prepared?.signature===signature&&<div className="jsonata-assist-step">
        <h4>2. Paste the ChatGPT JSON response</h4>
        <p>Use the exact sample fingerprint from the copied prompt. Pasted JSONata is never executed.</p>
        <textarea aria-label="Paste ChatGPT JSONata mapping response" rows={6}
          value={reply} onChange={event=>{setReply(event.target.value);setReview(null);setSelected([]);setApproved(false);}}
          placeholder='{"contract":"parser-studio.mapping-jsonata.v0.1","sample":{"sha256":"...","events":2},"mappings":[{"expression":"src_ip","target":"srcip"}]}'/>
        <button type="button" disabled={!reply.trim()||pending||busy}
          onClick={()=>void check()}>Check JSONata Mappings</button>
      </div>}
      {review&&<div className="jsonata-assist-step" aria-label="Reviewed ChatGPT JSONata mappings">
        <h4>3. Review mapping changes across all events</h4>
        <p>Only selected, locally validated mappings will change. Unsupported expressions and value mismatches cannot be applied.</p>
        {review.length===0?<p>No mapping improvements were proposed.</p>:
          <div className="jsonata-assist-rows">
            {review.map((row,index)=><label key={index} className="jsonata-assist-row">
              <input type="checkbox" checked={selected.includes(index)}
                disabled={row.status==='BLOCKED'||row.status==='UNCHANGED'||pending||busy}
                aria-label={'Approve JSONata mapping '+row.source+' to '+row.target}
                onChange={event=>setChecked(index,event.target.checked)}/>
              <div>
                <strong>{row.source||row.expression} → {row.target}</strong>
                <span>{row.status.replace('_',' ')} · {row.observed}/{row.total} events · {row.type??'unknown'} · {row.reason}</span>
                {row.when&&<small>Apply only when {row.when.sourcePath} is one of
                  {' '+row.when.values.join(' / ')}. Other events retain the original vendor fields.</small>}
                <small>{row.values.join(' · ')||'No observed values'}</small>
              </div>
            </label>)}
          </div>}
        {chosen.length>0&&<>
          <label className="jsonata-assist-check">
            <input type="checkbox" checked={approved}
              aria-label="I reviewed the selected JSONata mappings"
              onChange={event=>setApproved(event.target.checked)}/>
            I reviewed the selected field mappings and sample values.
          </label>
          {hasUncertain&&<label className="jsonata-assist-check">
            <input type="checkbox" checked={approveUncertain}
              aria-label="I confirm uncertain mapping meanings"
              onChange={event=>setApproveUncertain(event.target.checked)}/>
            I confirmed the meaning of the mappings marked Check first.
          </label>}
          <button type="button" disabled={!approved||(hasUncertain&&!approveUncertain)||pending||busy}
            onClick={apply}><CheckCircle2 size={14}/>Apply {chosen.length} Reviewed Mapping{chosen.length===1?'':'s'}</button>
        </>}
      </div>}
      {error&&<p className="jsonata-assist-error" role="alert"><ShieldAlert size={14}/>{error}</p>}
      {notice&&<p className="jsonata-assist-info" role="status">{notice}</p>}
      <button className="jsonata-assist-close" type="button" onClick={()=>setOpen(false)}><X size={14}/>Close</button>
    </div>}
  </section>;
}

const MERGE_REFUSAL:Record<string,string>={
  DESTINATION_COLLISION:'A selected mapping writes a Stellar Cyber field that this parser already fills. Nothing was changed.',
  SOURCE_NOT_IN_FAMILY:'A selected mapping reads a field that no record of this event type contains. Nothing was changed.',
  FAMILY_SOURCE_REMOVED:'The change leaves out a field this event type maps; its values would be lost. Nothing was changed.',
  NO_FAMILY_CHANGE:'The selected mappings leave this event type unchanged. Nothing was changed.',
  SHARED_MAPPING_CHANGED:'The change would alter a mapping shared by every event type. Nothing was changed.',
  NO_SINGLE_DISCRIMINATOR_VALUE:'The records of no event type do not share one event type value. Nothing was changed.',
};

/** ChatGPT JSONata mapping for a parser with event profiles: one event type at a time. The selected type is
 * projected to an ordinary single-type draft and checked on that type's records only; an approved result is
 * merged into that type, so other types keep their mappings and no destination is written twice. */
function FamilyScopedJsonata(props:Props){
  const {draft,setDraft,suite,pending}=props;
  const scopes=useMemo(()=>familyScopes(draft,suite)??[],[draft,suite]);
  const [selected,setSelected]=useState('');
  const active=scopes.find(scope=>scope.name===selected)??scopes.find(scope=>scope.state!=='READ')??scopes[0];
  const scoped=useMemo(()=>{
    if(!active)return null;
    const projected=projectFamilyDraft(draft,active.name);
    if(!projected)return null;
    const source=active.records.map(index=>suite.events[index]!.raw).join('\n');
    return {draft:projected,suite:preview(source,projected)};
  },[draft,suite,active]);
  if(!active||!scoped)return <JsonataMappingCore {...props}/>;
  const selector=<label className="jsonata-assist-check">Event type to map
    <select aria-label="ChatGPT mapping event type scope" value={active.name} disabled={pending}
      onChange={event=>setSelected(event.target.value)}>
      {scopes.map(scope=><option key={scope.name} value={scope.name}>
        {(scope.name===UNRECOGNIZED_SCOPE?'Not recognized by any event type':scope.name)+' - '+scope.records.length+
          (scope.records.length===1?' record':' records')}</option>)}
    </select>
  </label>;
  return <JsonataMappingCore draft={scoped.draft} setDraft={()=>{}} suite={scoped.suite} pending={pending}
    familyScope={{label:active.name,selector,context:familyPromptContext(draft,scopes,active.name),onApply:candidate=>{
      const merged=mergeFamilyCandidate(draft,active.name,candidate,suite);
      if(!merged.ok)return MERGE_REFUSAL[merged.reason]??'The change could not be applied to this event type ('+merged.reason+'). Nothing was changed.';
      setDraft(merged.draft);
      return null;
    }}}/>;
}

export default function JsonataMappingAssistant(props:Props){
  return props.draft.eventProfiles?<FamilyScopedJsonata {...props}/>:<JsonataMappingCore {...props}/>;
}
