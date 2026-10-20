import {act,renderHook} from '@testing-library/react';
import {describe,expect,it} from 'vitest';
import {useAnalysisRun} from './useAnalysisRun';

describe('analysis source identity and cancellation',()=>{
  it('keeps a newer request active when a canceled request finishes late',async()=>{
    const {result}=renderHook(()=>useAnalysisRun('source A / draft A'));
    let release!:()=>void;
    const delayed=new Promise<void>(resolve=>{release=resolve;});
    const accepted:string[]=[];
    let oldRun!:ReturnType<typeof result.current.begin>;
    act(()=>{oldRun=result.current.begin(1000);});
    const oldResult=(async()=>{
      await delayed;
      if(result.current.isCurrent(oldRun))accepted.push('old result');
      result.current.finish(oldRun);
    })();
    act(()=>result.current.cancel());
    expect(oldRun.controller.signal.aborted).toBe(true);
    expect(result.current.interruption).toBe('cancelled');
    let newRun!:ReturnType<typeof result.current.begin>;
    act(()=>{newRun=result.current.begin(4000);});
    await act(async()=>{release();await oldResult;});
    expect(accepted).toEqual([]);
    expect(result.current.isCurrent(newRun)).toBe(true);
    expect(result.current.progress?.sourceBytes).toBe(4000);
    expect(result.current.interruption).toBeNull();
    act(()=>result.current.finish(newRun));
    expect(result.current.progress).toBeNull();
  });

  it('revokes an in-flight result after a source or parser edit, including edit then revert',()=>{
    const original=JSON.stringify(['original logs','original draft']);
    const {result,rerender}=renderHook(({identity})=>useAnalysisRun(identity),
      {initialProps:{identity:original}});
    let run!:ReturnType<typeof result.current.begin>;
    act(()=>{run=result.current.begin(100);});
    rerender({identity:JSON.stringify(['edited logs','original draft'])});
    expect(run.controller.signal.aborted).toBe(true);
    expect(result.current.progress).toBeNull();
    expect(result.current.interruption).toBe('changed');
    rerender({identity:original});
    expect(result.current.isCurrent(run)).toBe(false);
    act(()=>{run=result.current.begin(100);});
    rerender({identity:JSON.stringify(['original logs','edited draft'])});
    expect(run.controller.signal.aborted).toBe(true);
    expect(result.current.isCurrent(run)).toBe(false);
  });

  it('preserves successful completion when the result adopts an automatic draft',()=>{
    const {result,rerender}=renderHook(({identity})=>useAnalysisRun(identity),
      {initialProps:{identity:'source / auto draft'}});
    let run!:ReturnType<typeof result.current.begin>;
    act(()=>{run=result.current.begin(400);});
    act(()=>result.current.setPhase(run,'validating'));
    expect(result.current.progress?.phase).toBe('validating');
    act(()=>result.current.finish(run));
    rerender({identity:'source / automatically reviewed draft'});
    expect(result.current.progress).toBeNull();
    expect(result.current.interruption).toBeNull();
    expect(run.controller.signal.aborted).toBe(false);
  });

  it('aborts an outstanding request when the analysis screen is removed',()=>{
    const {result,unmount}=renderHook(()=>useAnalysisRun('source / draft'));
    let run!:ReturnType<typeof result.current.begin>;
    act(()=>{run=result.current.begin(100);});
    const isCurrent=result.current.isCurrent;
    unmount();
    expect(run.controller.signal.aborted).toBe(true);
    expect(isCurrent(run)).toBe(false);
  });
});
