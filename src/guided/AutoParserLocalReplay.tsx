import {useEffect,useRef,useState} from 'react';
import type {ParserDraft} from '../model';
import {createLocalReplayPlan,synthesizeFromReplayPlan,type LocalReplayPlan,
  type ReplayMutation} from './replayPreview';
import {HelpTip} from './BeginnerHelp';

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
    <summary className="beginner-tool-summary">Preview changing test logs
      <HelpTip label="Preview changing test logs"
        text="Use this after a parser is created when you want to see how the same log shape behaves with changing timestamps, example IPs, usernames, and URLs. It runs only in this browser and sends nothing to a sensor."/>
    </summary>
    <span className="beginner-tool-when">Use when: you want a quick local sanity check with changing example values before any separately approved live test.</span>
    <p>Parser Studio creates safe synthetic variations from your reviewed sample and displays them locally.
      It does not upload, store, or transmit these events.</p>
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
          {running?'Stop Preview':'Start Local Preview'}
        </button>
      </div>
    </div>
    {!supported&&<p role="status" aria-label="Local replay unsupported format notice">
      This local preview is not available for mixed or multi-line parser formats. Your generated parser files are unchanged and nothing was sent.
    </p>}
    <p role="status" aria-label="Local synthetic replay status">
      {count} synthetic event{count===1?'':'s'} generated locally · Nothing sent ·
      {running?' Preview running':' Preview stopped'}
      {output&&<span> · Based on source event {output.sourceEvent}/{output.sourceTotal}
        {' '}(line {output.sourceLine})</span>}
    </p>
    {error&&<p role="alert">{error}</p>}
    {output&&<div aria-label="Browser-only replay result">
      <p>Latest synthetic log · Changed fields: {output.mutations.join(', ')||'none'}</p>
      <pre aria-label="Local synthetic replay output">{output.log}</pre>
    </div>}
    <small>This preview stays in the browser. It does not contact a live Stellar system, start a test session, or send network traffic.</small>
  </details>;
}
