import {useMemo,useState} from 'react';
import type {RefObject} from 'react';
import {inspectManualBoundaries,selectedBoundary} from './manualSourceBoundaries';
import type {ManualBoundaryMarks} from './manualSourceBoundaries';
import {HelpTip} from './BeginnerHelp';

export default function ManualSourceBoundaryReview({
  source,sourceInput,
}:{source:string;sourceInput:RefObject<HTMLTextAreaElement|null>}){
  const [marks,setMarks]=useState<ManualBoundaryMarks>({prefix:'',postfix:''});
  const [notice,setNotice]=useState('');
  const reviewed=useMemo(()=>inspectManualBoundaries(source,marks),[source,marks]);

  const mark=(kind:'prefix'|'postfix')=>{
    const area=sourceInput.current;
    if(!area){setNotice('Select text in the original log input first.');return;}
    const choice=selectedBoundary(source,area.selectionStart,area.selectionEnd,kind);
    if(!choice.ok){setNotice(choice.reason);return;}
    setMarks(previous=>({...previous,[kind]:choice.literal}));
    setNotice('');
  };
  return <details className="auto-parser-recipe" aria-label="Manually mark a log prefix or postfix">
    <summary>Optional: mark a forwarded prefix or trailing suffix
      <HelpTip label="Prefix and postfix marks"
        text="Select the exact, repeated wrapper text in the first event. Mark it as a prefix or postfix to review the body and UTF-8 byte boundaries. This does not create a native parser rule."/></summary>
    <p>Use this when a forwarder adds the same fixed text around each log.
      Highlight wrapper characters in the first line of the original log input, then select the matching action.
      Variable timestamps or changing relay headers need a separately reviewed rule, not literal trimming.</p>
    <div className="manual-boundary-buttons">
      <button type="button" onClick={()=>mark('prefix')}>Mark selection as prefix</button>
      <button type="button" onClick={()=>mark('postfix')}>Mark selection as postfix</button>
      <button type="button" onClick={()=>{setMarks({prefix:'',postfix:''});setNotice('');}}>
        Clear marks</button>
    </div>
    <div className="manual-boundary-labels" aria-label="Selected wrapper values">
      <span>Prefix: <code>{marks.prefix||'(none)'}</code></span>
      <span>Postfix: <code>{marks.postfix||'(none)'}</code></span>
    </div>
    {notice&&<p role="alert">{notice}</p>}
    <div role="status" aria-label="Literal boundary review status">
      {reviewed.status==='NO_MARKS'?'No manual boundaries selected.':
        reviewed.status==='ABSTAIN_UNSAFE'?
          'Cannot apply the selected literal wrapper consistently. Original events are preserved.':
          'Exact boundary matches: '+reviewed.count+' source events. Original bytes preserved.'}
    </div>
    {reviewed.status==='REVIEW_READY'&&<div aria-label="Marked payload examples">
      {reviewed.records.slice(0,3).map(item=><div className="manual-boundary-example" key={item.number}>
        <strong>Event {item.number}</strong>
        <span>Payload bytes {item.payloadStartByte}–{item.payloadEndByte}</span>
        <pre>{item.payload}</pre>
      </div>)}
    </div>}
    <p role="note">Source-only review. This does not remove characters from your logs,
      change the analyzed parser, or certify that a downloaded Ruby parser will
      recognize changing prefixes or postfixes. Continue with the original source
      until a matching compiler capability is independently verified.</p>
  </details>;
}
