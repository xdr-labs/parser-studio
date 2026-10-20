import {useEffect,useState} from 'react';
import type {AnalysisInterruption,AnalysisProgress} from './useAnalysisRun';

export default function AnalysisProgressPanel({progress,interruption,onCancel}:{
  progress:AnalysisProgress|null;
  interruption:AnalysisInterruption;
  onCancel:()=>void;
}){
  const [now,setNow]=useState(Date.now);
  const startedAt=progress?.startedAt;
  useEffect(()=>{
    if(startedAt===undefined)return;
    setNow(Date.now());
    const timer=window.setInterval(()=>setNow(Date.now()),1000);
    return ()=>window.clearInterval(timer);
  },[startedAt]);

  if(!progress)return interruption?<p className="analysis-interruption" role="status">
    {interruption==='cancelled'
      ?'Analysis canceled. Your logs are unchanged. You can edit them or analyze again.'
      :'The logs or parser settings changed, so the previous analysis was canceled. Analyze the current logs again.'}
  </p>:null;
  const elapsed=Math.max(0,Math.floor((now-progress.startedAt)/1000));
  return <section className="analysis-progress" aria-label="Log analysis progress" aria-busy="true">
    <div className="analysis-progress-heading">
      <strong role="status">{progress.phase==='analyzing'
        ?'Analyzing source':'Checking analysis results'}</strong>
      <button type="button" onClick={onCancel}>Cancel analysis</button>
    </div>
    <progress aria-label="Analysis in progress"/>
    <p aria-live="off">{progress.sourceBytes.toLocaleString('en-US')} UTF-8 bytes · {elapsed}s elapsed</p>
    <p>{progress.phase==='analyzing'
      ?'Larger samples can take longer. Event counts appear after the engine returns and the source checks finish.'
      :'The engine returned a result. Parser Studio is checking every event and its original source bytes.'}</p>
  </section>;
}
