import {useEffect,useMemo,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import {CheckCircle2,ClipboardCopy,ShieldAlert,Sparkles,X} from 'lucide-react';
import type {ParserDraft,SuiteResult} from '../model';
import {
  createJsonataMappingPrompt,jsonataDraftSignature,reviewJsonataMapping,
  applyReviewedJsonataMapping,type ReviewedJsonataMapping,
} from './jsonataMappingAssist';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  suite:SuiteResult;
  pending:boolean;
}
interface Prepared {prompt:string;sha256:string;signature:string}

export default function JsonataMappingAssistant({draft,setDraft,suite,pending}:Props){
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
      const next=await createJsonataMappingPrompt(suite,draft,includeValues);
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
    setDraft(result.draft);
    setNotice('Applied '+chosen.length+' reviewed native-compatible field mapping'+(chosen.length===1?'':'s')+'. Check the refreshed field preview before creating a parser.');
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
