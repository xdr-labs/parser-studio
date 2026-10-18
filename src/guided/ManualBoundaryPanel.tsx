import {useEffect,useMemo,useState} from 'react';
import type {RefObject} from 'react';
import {HelpTip} from './BeginnerHelp';
import {inspectMarkedBoundaries,markBoundarySelection} from './manualSourceBoundaries';
import {inspectDeclaredForwarders,validForwarderConfig} from './declaredForwarder';
import {splitEvents} from '../parser';

interface Props{
  source:string;
  sourceTextareaRef:RefObject<HTMLTextAreaElement|null>;
}

/**
 * Explicit local-only prefix and suffix marking. Original logs and parser
 * draft are never rewritten, and a preview cannot enable generation for a
 * wrapper that the native compiler has not independently implemented.
 */
export default function ManualBoundaryPanel({source,sourceTextareaRef}:Props){
  const [open,setOpen]=useState(false);
  const [prefix,setPrefix]=useState('');
  const [suffix,setSuffix]=useState('');
  const [notice,setNotice]=useState('');
  const [selected,setSelected]=useState(0);
  const [relayHosts,setRelayHosts]=useState('');
  const [maxHops,setMaxHops]=useState<1|2|3>(1);
  const [relaySelected,setRelaySelected]=useState(0);
  const relayConfig=useMemo(()=>{
    const values=relayHosts.split(',').map(name=>name.trim());
    if(values.length===1&&!values[0])return null;
    const profile={relayHosts:values,maxHops};
    return validForwarderConfig(profile)?profile:null;
  },[relayHosts,maxHops]);
  const relayPreview=useMemo(()=>{
    if(!relayConfig)return [];
    return splitEvents(source,'single-line',501).map(entry=>({
      line:entry.line,...inspectDeclaredForwarders(entry.raw,relayConfig),
    }));
  },[source,relayConfig]);
  const preview=useMemo(()=>inspectMarkedBoundaries(source,{prefix,suffix}),[source,prefix,suffix]);
  useEffect(()=>{
    setPrefix('');setSuffix('');setNotice('');setSelected(0);
    setRelayHosts('');setMaxHops(1);setRelaySelected(0);
  },[source]);
  if(!source.trim())return null;

  const mark=(kind:'prefix'|'suffix')=>{
    const area=sourceTextareaRef.current;
    if(!area){setNotice('Select a prefix or suffix in the original log box first.');return;}
    const picked=markBoundarySelection(source,area.selectionStart,area.selectionEnd,kind);
    if(!picked.ok){setNotice(picked.reason);return;}
    if(kind==='prefix')setPrefix(picked.value);
    else setSuffix(picked.value);
    setNotice(kind==='prefix'?'Marked the first log prefix for exact local comparison.':
      'Marked the first log suffix for exact local comparison.');
  };
  const example=preview.events[Math.min(selected,preview.events.length-1)];
  return <details className="auto-parser-recipe manual-boundary-panel"
    aria-label="Mark a forwarding prefix or suffix"
    open={open} onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>Optional: mark a forwarding prefix or suffix <HelpTip
      label="Mark a forwarding prefix or suffix"
      text="Use this when a log forwarding service adds fixed text before or after an original event. Highlight that exact text in the first log above and click the matching mark button, or enter it manually. The raw log never changes."/></summary>
    <p>Some forwarding services add text around each log. You can show Parser Studio
      exactly which characters were added instead of asking it to guess.</p>
    <p><strong>How:</strong> Select the extra text in the first log above, then click Mark selected prefix
      or Mark selected suffix. If selecting is difficult, enter the exact text below.</p>
    <div className="manual-boundary-actions">
      <button type="button" onClick={()=>mark('prefix')}>Mark selected prefix</button>
      <button type="button" onClick={()=>mark('suffix')}>Mark selected suffix</button>
      <button type="button" onClick={()=>{setPrefix('');setSuffix('');setSelected(0);setNotice('All manual marks cleared. The original logs are unchanged.');}}>
        Clear marks</button>
    </div>
    <div className="manual-boundary-inputs">
      <label>Extra text before each log
        <input aria-label="Declared literal prefix" value={prefix}
          placeholder="e.g. relay: " maxLength={512}
          onChange={event=>{setPrefix(event.target.value);setSelected(0);setNotice('');}}/>
      </label>
      <label>Extra text after each log
        <input aria-label="Declared literal suffix" value={suffix}
          placeholder="e.g. [end]" maxLength={512}
          onChange={event=>{setSuffix(event.target.value);setSelected(0);setNotice('');}}/>
      </label>
    </div>
    {notice&&<p role="status" aria-label="Manual boundary marking status">{notice}</p>}
    {(prefix||suffix)&&<>
      <div role="status" aria-label="Manual boundary coverage"
        className={'manual-boundary-status '+(preview.status==='READY'?'ready':'needs-review')}>
        <strong>{preview.status==='READY'?'All example wrappers matched':
          preview.status==='PARTIAL'?'Some wrappers need review':'Source boundary review unavailable'}</strong>
        <span>Matched {preview.matched} of {preview.total} events ·
          Not matched {preview.unmatched}</span>
        <small>{preview.reason}</small>
      </div>
      {example&&<div aria-label="Marked log body preview" className="manual-boundary-body">
        <label>Choose a log to review
          <select aria-label="Manual boundary event" value={Math.min(selected,preview.events.length-1)}
            onChange={event=>setSelected(Number(event.target.value))}>
            {preview.events.map((entry,index)=><option key={index} value={index}>
              Event {entry.line} · {entry.status==='MATCHED'?'Wrapper matched':'Wrapper different'}
            </option>)}
          </select>
        </label>
        <label>Local body preview (read only)
          <textarea aria-label="Manually unwrapped log preview" readOnly rows={3}
            value={example.body}/>
        </label>
        <small>Original UTF-8 byte positions: {example.payloadStartByte}–{example.payloadEndByte}.
          {' '}The source log above is untouched.</small>
      </div>}
    </>}
    <div className="manual-relay-review" aria-label="Declared changing Syslog relay headers">
      <h3>Does a forwarding server add a changing Syslog header?</h3>
      <p>A changing timestamp is not a fixed prefix. Enter the relay hostname
        from the forwarded log to review a recognized Syslog wrapper instead.
        Only the hostnames you enter will be considered.</p>
      <div className="manual-boundary-inputs">
        <label>Forwarder hostnames (comma-separated)
          <input aria-label="Declared forwarding hosts" value={relayHosts}
            placeholder="e.g. relay01,relay02"
            onChange={event=>{setRelayHosts(event.target.value);setRelaySelected(0);}}/>
        </label>
        <label>Maximum forwarding layers
          <select aria-label="Declared forwarder hop limit" value={maxHops}
            onChange={event=>{setMaxHops(Number(event.target.value) as 1|2|3);setRelaySelected(0);}}>
            {[1,2,3].map(n=><option value={n} key={n}>{n} layer{n===1?'':'s'}</option>)}
          </select>
        </label>
      </div>
      {relayHosts.trim()&&!relayConfig&&
        <p role="alert">Enter 1–8 unique hostnames containing only letters, numbers,
          dots, hyphens, or underscores. No wildcards or regular expressions.</p>}
      {relayConfig&&<div role="status" aria-label="Declared relay coverage"
        className="manual-boundary-status">
        <strong>Recognized forwarding headers: {relayPreview.filter(row=>row.status==='UNWRAPPED').length}
          {' '}of {relayPreview.length} events</strong>
        <span>Needs review: {relayPreview.filter(row=>row.status!=='UNWRAPPED').length}</span>
        <small>This is read-only envelope recognition, not a verified parser output rule.</small>
      </div>}
      {relayConfig&&relayPreview.length>0&&(()=>{
        const entry=relayPreview[Math.min(relaySelected,relayPreview.length-1)]!;
        return <div className="manual-boundary-body" aria-label="Declared relay payload preview">
          <label>Log to inspect
            <select aria-label="Declared relay event" value={Math.min(relaySelected,relayPreview.length-1)}
              onChange={event=>setRelaySelected(Number(event.target.value))}>
              {relayPreview.map((item,index)=><option value={index} key={index}>
                Event {item.line} · {item.status==='UNWRAPPED'?'Forwarder recognized':
                  item.status==='DIRECT'?'No declared forwarder found':'Unsafe wrapper'}
              </option>)}
            </select>
          </label>
          <label>Original message after the declared relay header (read only)
            <textarea aria-label="Declared relay body" rows={3} readOnly value={entry.payload}/>
          </label>
          <small>Source payload begins at UTF-8 byte {entry.payloadStartByte} in this log.
            {' '}Matched layers: {entry.hops.length}.</small>
        </div>;
      })()}
    </div>
    <p role="note" className="manual-boundary-warning">
      <strong>Review only:</strong> This does not rewrite the original logs or enable
      parser downloads for an unsupported wrapper. A changing forwarding timestamp
      or hostname needs a separate reviewed parsing rule. This is not a native
      parser, DP installation, or sensor test.
    </p>
  </details>;
}
