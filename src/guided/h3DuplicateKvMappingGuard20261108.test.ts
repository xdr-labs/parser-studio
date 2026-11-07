import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {listSafeLeafPaths,countUnaddressableSourceValues} from '../fieldPaths';

describe('H3 duplicate KV values cannot silently become an official scalar',()=>{
 it('rejects duplicate source keys before any IP is normalized',()=>{
   const draft=createDraft();
   draft.format='kv';
   draft.mappings=[{id:'ip',source:'srcip',target:'srcip',type:'ip'}];
   const original='srcip=192.0.2.10 srcip=198.51.100.10';
   const event=preview(original,draft).events[0]!;
   expect(event.raw).toBe(original);
   expect(event.normalizedOk).toBe(false);
   expect(event.normalized).not.toHaveProperty('srcip');
   expect(event.diagnostics).toEqual(expect.arrayContaining([
     expect.objectContaining({code:'EXTRACTION_FAILED',stage:'extract',severity:'error'}),
   ]));
 });
 it('preserves repeated original observations as unaddressable array values',()=>{
   const independentlyObserved={
     srcip:['192.0.2.10','198.51.100.10'], action:'deny',
   };
   expect(listSafeLeafPaths(independentlyObserved)).toEqual(['action']);
   expect(countUnaddressableSourceValues(independentlyObserved)).toBe(1);
   expect(independentlyObserved.srcip).toEqual(['192.0.2.10','198.51.100.10']);
 });
});
