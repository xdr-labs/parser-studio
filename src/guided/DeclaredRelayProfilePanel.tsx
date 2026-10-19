import {useMemo,useRef,useState} from 'react';
import type {Dispatch,SetStateAction} from 'react';
import type {ParserDraft} from '../model';
import {validForwarderConfig,inspectDeclaredForwarders} from './declaredForwarder';
import type {ForwarderConfig} from './declaredForwarder';
import {fetchBackendCapabilities} from './backendCapabilities';
import {HelpTip} from './BeginnerHelp';

/** Explicit operator-declared relay syntax. Never authenticate sender from text. */
export default function DeclaredRelayProfilePanel({
  sample,draft,setDraft,
}:{sample:string;draft:ParserDraft;setDraft:Dispatch<SetStateAction<ParserDraft>>}){
  // A restored local version must open with the reviewed relay values,
  // not a blank editable form that contradicts the active DRAFT.
  const [names,setNames]=useState(()=>draft.forwarder?.relayHosts.join(',')??'');
  const [maxHops,setMaxHops]=useState<1|2|3>(()=>draft.forwarder?.maxHops??1);
  const [notice,setNotice]=useState('');
  const [loading,setLoading]=useState(false);
  const latestSource=useRef(sample);latestSource.current=sample;
  const profile=useMemo<ForwarderConfig>(()=>({
    maxHops,relayHosts:names.split(',').map(name=>name.trim()).filter(Boolean),
  }),[maxHops,names]);
  const summary=useMemo(()=>{
    if(sample.includes('\0')||sample.includes('\r')||
      new TextEncoder().encode(sample).length>65536)
      return {count:0,unwrapped:0,unsafe:1,nonRelay:0};
    const records=sample.split('\n').filter(row=>row.trim());
    const checked=records.slice(0,501).map(row=>inspectDeclaredForwarders(row,profile));
    return {
      count:records.length,
      unwrapped:checked.filter(row=>row.status==='UNWRAPPED').length,
      unsafe:checked.filter(row=>row.status==='ABSTAIN_UNSAFE').length,
      nonRelay:checked.filter(row=>row.status==='DIRECT').length,
    };
  },[sample,profile]);
  const valid=validForwarderConfig(profile)&&summary.count>0&&summary.count<=500&&
    summary.unsafe===0&&summary.nonRelay===0&&summary.unwrapped===summary.count;
  async function apply(){
    if(!valid){setNotice('Every source event must match the declared relay hosts and hop limit. No source was changed.');return;}
    const source=sample;
    setLoading(true);setNotice('');
    try{
      const cap=await fetchBackendCapabilities();
      if(latestSource.current!==source){
        setNotice('The source changed during review. Recheck the current events.');
        return;
      }
      if(cap.authoring.declaredForwarderEnvelopeUnwrap!==true||
         cap.authoring.declaredForwarderMaximumHops!==3||
         JSON.stringify(cap.authoring.declaredForwarderFormats)!=='["rfc3164","rfc5424"]'){
        setNotice('The connected parser compiler does not support reviewed relay headers.');
        return;
      }
      setDraft(old=>({...old,forwarder:{
        maxHops:profile.maxHops,relayHosts:[...profile.relayHosts],
      }}));
      setNotice('Declared relays added to your local draft. Review all source events and verify the generated DRAFT separately.');
    }catch{
      setNotice('The local parser compiler is unavailable. Original logs were not changed.');
    }finally{setLoading(false);}
  }
  return <details className="auto-parser-recipe" aria-label="Review declared relay hosts">
    <summary>Optional: declare Syslog forwarder hostnames
      <HelpTip label="Declared forwarder hostnames"
        text="Only user-approved RFC3164/RFC5424 relay hosts may be unwrapped. A hostname inside a log does not authenticate its actual sender."/></summary>
    <p>Use this if a known forwarder adds a complete Syslog header around each event.
      Variable timestamps and nested relay headers are handled only through the
      exact compiler contract; never blindly trim arbitrary source characters.</p>
    <label>Relay hostnames (comma-separated)
      <input aria-label="Declared relay hostname list" value={names}
        placeholder="relay01,relay02"
        onChange={event=>setNames(event.target.value)}/>
    </label>
    <label>Maximum declared hops
      <select aria-label="Maximum declared relay hops" value={maxHops}
        onChange={event=>setMaxHops(Number(event.target.value) as 1|2|3)}>
        <option value={1}>1</option><option value={2}>2</option><option value={3}>3</option>
      </select>
    </label>
    <p aria-label="Relay source preview">Whole-sample review: {summary.unwrapped} of
      {' '}{summary.count} events recognized, {summary.unsafe} unsafe and
      {' '}{summary.nonRelay} without a declared relay.</p>
    <div className="manual-boundary-buttons">
      <button type="button" disabled={loading||!valid}
        onClick={()=>void apply()}>{loading?'Checking compiler…':'Apply declared relay profile'}</button>
      {draft.forwarder&&<button type="button" onClick={()=>{
        setDraft(old=>({...old,forwarder:undefined}));
        setNotice('Declared relays cleared. Original source bytes remain unchanged.');
      }}>Clear declared relay profile</button>}
    </div>
    {draft.forwarder&&<p role="status" aria-label="Active declared relays">
      Local profile: {draft.forwarder.relayHosts.join(', ')} · maximum
      {' '}{draft.forwarder.maxHops} hop(s).</p>}
    {notice&&<p role="status">{notice}</p>}
    <p role="note">Unknown relays and unsupported source forms are not unwrapped.
      Only the exact authoring compiler may generate a conditional DRAFT.
      No DP, sensor or other target connection occurs here.</p>
  </details>;
}
