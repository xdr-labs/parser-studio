import type {ParserDraft,SuiteResult} from './model';
import {MAX_DATASET_BYTES} from './parser';

/** One isolated browser worker for both parser creation paths.
 * No backend calls, LLM egress or sensor delivery occur during live preview.
 */
export function runInWorker(raw:string,draft:ParserDraft):Promise<SuiteResult>{
  if(new TextEncoder().encode(raw).byteLength>MAX_DATASET_BYTES)
    return Promise.reject(new Error('The local log sample is larger than 64 KiB.'));
  return new Promise((resolve,reject)=>{
    if(typeof Worker==='undefined'){
      reject(new Error('This browser cannot start the private parser preview.'));return;
    }
    const worker=new Worker(new URL('./preview.worker.ts',import.meta.url),{type:'module'});
    let finished=false;
    const end=()=>{finished=true;window.clearTimeout(deadline);worker.terminate();};
    const deadline=window.setTimeout(()=>{
      if(!finished){end();reject(new Error('The local parser preview timed out.'));}
    },15000);
    worker.onmessage=(event:MessageEvent<{suite?:SuiteResult;error?:string}>)=>{
      if(finished)return;
      end();
      if(event.data.suite)resolve(event.data.suite);
      else reject(new Error(event.data.error??'The preview could not be completed.'));
    };
    worker.onerror=()=>{
      if(!finished){end();reject(new Error('The browser preview worker failed.'));}
    };
    worker.postMessage({raw,draft});
  });
}
