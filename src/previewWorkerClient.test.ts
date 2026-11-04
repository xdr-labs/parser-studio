import {afterEach,describe,expect,it,vi} from 'vitest';
import {createDraft} from './model';
import {runInWorker} from './previewWorkerClient';

describe('isolated browser preview worker has a hard timeout',()=>{
 afterEach(()=>{vi.unstubAllGlobals();vi.useRealTimers();});
 it('terminates a hung regex worker without executing any parsing on the UI thread',async()=>{
  vi.useFakeTimers();
  const workers:{terminate:ReturnType<typeof vi.fn>;postMessage:ReturnType<typeof vi.fn>}[]=[];
  class FakeWorker{
   onmessage:((e:MessageEvent)=>void)|null=null;
   onerror:(()=>void)|null=null;
   terminate=vi.fn();
   postMessage=vi.fn();
   constructor(){workers.push(this);}
  }
  vi.stubGlobal('Worker',FakeWorker);
  const future=runInWorker('a'.repeat(40)+'!',{...createDraft(),format:'regex',
   pattern:'^(?<field>(a{1,3})+)$'});
  const observed=expect(future).rejects.toThrow('The local parser preview timed out.');
  expect(workers).toHaveLength(1);
  expect(workers[0]!.postMessage).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(15000);
  await observed;
  expect(workers[0]!.terminate).toHaveBeenCalledOnce();
 });
 it('blocks oversized input before creating a worker',async()=>{
  const constructor=vi.fn();
  vi.stubGlobal('Worker',constructor);
  await expect(runInWorker('X'.repeat(64*1024+1),createDraft())).rejects
   .toThrow(/larger than 64 KiB/);
  expect(constructor).not.toHaveBeenCalled();
 });
});
