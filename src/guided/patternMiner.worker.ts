/** Isolated browser worker: bounded in-memory structural hints only. */
import {mineLocalStructuralHints} from './localPatternMining';
self.onmessage=(message:MessageEvent<{source?:unknown}>)=>{
 try{
   const source=message.data?.source;
   if(typeof source!=='string')throw new Error('INVALID_SOURCE');
   self.postMessage({report:mineLocalStructuralHints(source)});
 }catch{self.postMessage({error:'STRUCTURAL_HINTS_UNAVAILABLE'});}
};
