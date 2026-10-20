import {useCallback,useEffect,useRef,useState} from 'react';
import type {MultiPassRequestPhase} from './multipassPreviewClient';

export interface AnalysisProgress {
  startedAt:number;
  sourceBytes:number;
  phase:MultiPassRequestPhase;
}
interface AnalysisRun extends AnalysisProgress {
  identity:string;
  controller:AbortController;
}
export type AnalysisInterruption='cancelled'|'changed'|null;

/** Bind each asynchronous analysis to the exact source and parser settings. */
export function useAnalysisRun(identity:string){
  const identityRef=useRef(identity);identityRef.current=identity;
  const active=useRef<AnalysisRun|null>(null);
  const [progress,setProgress]=useState<AnalysisProgress|null>(null);
  const [interruption,setInterruption]=useState<AnalysisInterruption>(null);

  const isCurrent=useCallback((run:AnalysisRun)=>
    active.current===run&&!run.controller.signal.aborted&&
    identityRef.current===run.identity,[]);

  useEffect(()=>{
    const run=active.current;
    if(run&&run.identity!==identity){
      active.current=null;
      run.controller.abort();
      setProgress(null);
      setInterruption('changed');
    }
  },[identity]);
  useEffect(()=>()=>{
    const run=active.current;
    active.current=null;
    run?.controller.abort();
  },[]);

  const begin=useCallback((sourceBytes:number)=>{
    active.current?.controller.abort();
    const run:AnalysisRun={identity:identityRef.current,controller:new AbortController(),
      startedAt:Date.now(),sourceBytes,phase:'analyzing'};
    active.current=run;
    setProgress({startedAt:run.startedAt,sourceBytes,phase:run.phase});
    setInterruption(null);
    return run;
  },[]);
  const setPhase=useCallback((run:AnalysisRun,phase:MultiPassRequestPhase)=>{
    if(isCurrent(run))setProgress({startedAt:run.startedAt,sourceBytes:run.sourceBytes,phase});
  },[isCurrent]);
  const finish=useCallback((run:AnalysisRun)=>{
    if(!isCurrent(run))return;
    active.current=null;
    setProgress(null);
  },[isCurrent]);
  const cancel=useCallback(()=>{
    const run=active.current;
    if(!run)return;
    active.current=null;
    run.controller.abort();
    setProgress(null);
    setInterruption('cancelled');
  },[]);

  return {progress,interruption,begin,isCurrent,setPhase,finish,cancel};
}
