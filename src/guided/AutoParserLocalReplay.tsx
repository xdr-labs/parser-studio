import {useEffect,useRef,useState} from 'react';
import type {ParserDraft} from '../model';
import {createLocalReplayPlan,synthesizeFromReplayPlan,type LocalReplayPlan,
  type ReplayMutation} from './replayPreview';

interface Props {
  sample:string;
  draft:ParserDraft;
}
type Rate=1|2|5|10;
type Output={log:string;mutations:ReplayMutation[];sourceEvent:number;
  sourceLine:number;sourceTotal:number};

/** An explicit, in-memory browser preview, never a sensor sender.
 * Source edits, result navigation, or unmount terminate the timer. */
export default function AutoParserLocalReplay({sample,draft}:Props){
  const [rate,setRate]=useState<Rate>(2);
  const [running,setRunning]=useState(false);
  const [count,setCount]=useState(0);
  const [output,setOutput]=useState<Output|null>(null);
  const [error,setError]=useState('');
  const timer=useRef<number|null>(null);
  const plan=useRef<LocalReplayPlan|null>(null);
  const cursor=useRef(0);

  const supported=['json','kv','csv','cef','leef','syslog_rfc5424'].includes(draft.format)&&
    (!draft.guided?.eventBoundary||draft.guided.eventBoundary==='single-line');

  function stopTimer(){
    if(timer.current!==null){window.clearInterval(timer.current);timer.current=null;}
    plan.current=null;
  }
  useEffect(()=>{
    stopTimer();
    cursor.current=0;
    setRunning(false);setCount(0);setOutput(null);setError('');
    return ()=>stopTimer();
  },[sample,draft]);

  function stop(){
    stopTimer();
    setRunning(false);
  }
  function start(){
    if(!supported)return;
    stopTimer();
    setRunning(false);setCount(0);setOutput(null);setError('');
    try{
      // Validate the *entire* current sample before emitting even one event.
      const candidate=createLocalReplayPlan(sample,draft);
      const first=synthesizeFromReplayPlan(candidate,draft,0);
      plan.current=candidate;cursor.current=1;
      setOutput(first);setCount(1);
      timer.current=window.setInterval(()=>{
        try{
          if(!plan.current){stop();return;}
          const next=synthesizeFromReplayPlan(plan.current,draft,cursor.current);
          cursor.current++;
          setOutput(next);setCount(value=>value+1);
        }catch{
          stop();
          setError('Local replay stopped because the current event could not be safely synthesized.');
        }
      },1000/rate);
      setRunning(true);
    }catch{
      stop();
      setError('Cannot start local replay. All events must use one reviewed, supported single-line format and meet the browser limits.');
    }
  }

  return <details className="auto-parser-recipe" aria-label="Local synthetic replay preview">
    <summary>Synthetic Replay Preview · Browser Only</summary>
    <p>Repeatedly generate current timestamps, documentation-only IP addresses,
      synthetic usernames and example.test URLs from reviewed single-line logs.
      Other source field values may remain unchanged in this local display.
      Nothing is uploaded, stored or delivered to a sensor.</p>
    <div className="two-path-mapping-editor">
      <label>Preview rate
        <select aria-label="Replay preview rate" value={rate} disabled={running||!supported}
          onChange={event=>setRate(Number(event.target.value) as Rate)}>
          {([1,2,5,10] as const).map(value=>
            <option key={value} value={value}>{value} events/sec</option>)}
        </select>
      </label>
      <div>
        <button type="button" disabled={!running&&!supported} onClick={running?stop:start}>
          {running?'Stop Local Replay':'Start Local Replay'}
        </button>
      </div>
    </div>
    {!supported&&<p role="status" aria-label="Local replay unsupported format notice">
      Browser-only replay is unavailable for this compiled mixed or multiline format.
      The verified DRAFT parser remains available; no events have been sent.
    </p>}
    <p role="status" aria-label="Local synthetic replay status">
      Locally generated {count} events · Sensor deliveries 0 events ·
      {running?' Running locally':' Stopped'}
      {output&&<span> · Source {output.sourceEvent}/{output.sourceTotal}
        {' '}(line {output.sourceLine})</span>}
    </p>
    {error&&<p role="alert">{error}</p>}
    {output&&<div aria-label="Browser-only replay result">
      <p>Latest synthetic log · Changed fields: {output.mutations.join(', ')||'none'}</p>
      <pre aria-label="Local synthetic replay output">{output.log}</pre>
    </div>}
    <small>No target Apply, backend Test Lab session, UDP/TCP sensor send or
      Interflow read happens from this browser preview. Supported mixed-family
      parsers require independent replay review.</small>
  </details>;
}
