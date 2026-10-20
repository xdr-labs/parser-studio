import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {prepareLocalVersion,verifyLocalRestoreCandidate,type LocalWorkingCopy} from './localWorkspaceHistory';

const working=():LocalWorkingCopy=>({
  datasetName:'Synthetic local experiment',
  source:'{"event":"allow","user":"김민수"}',draft:createDraft(),
});

describe('verified full-history restore checkpoint identity',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('allows a complete verified copy without requiring the same display name',async()=>{
    const copy=working();const row=await prepareLocalVersion(copy,'Saved V1');
    expect(await verifyLocalRestoreCandidate(row,copy)).toBe(true);
    expect(await verifyLocalRestoreCandidate(await prepareLocalVersion(copy,'Saved V2'),copy)).toBe(true);
  });
  it('rejects a matching row with a changed source and stale checksum',async()=>{
    const copy=working();const row=await prepareLocalVersion(copy,'Saved V1');
    const changed={...copy,source:copy.source+' '};
    expect(await verifyLocalRestoreCandidate({...row,source:changed.source},changed)).toBe(false);
  });
  it('rejects a shape-invalid row even when source and draft match',async()=>{
    const copy=working();const row=await prepareLocalVersion(copy,'Saved V1');
    expect(await verifyLocalRestoreCandidate({...row,id:'unverified'},copy)).toBe(false);
    expect(await verifyLocalRestoreCandidate(null,copy)).toBe(false);
  });
  it.each(['source','dataset','mapping','delimiter'])('never treats differing %s as protected',async(kind)=>{
    const copy=working();const row=await prepareLocalVersion(copy,'Saved V1');
    const changed=structuredClone(copy);
    if(kind==='source')changed.source+=' ';
    if(kind==='dataset')changed.datasetName='Different dataset';
    if(kind==='mapping')changed.draft.mappings[0].target='custom.changed';
    if(kind==='delimiter')changed.draft.csvDelimiter=';';
    expect(await verifyLocalRestoreCandidate(row,changed)).toBe(false);
  });
  it('requires exact named source groups as well as concatenated source',async()=>{
    const copy=working();copy.logTypes=[{id:'logs-1',name:'Traffic',sample:copy.source}];
    const row=await prepareLocalVersion(copy,'Named V1');
    expect(await verifyLocalRestoreCandidate(row,copy)).toBe(true);
    const renamed=structuredClone(copy);renamed.logTypes![0].name='Threat';
    expect(await verifyLocalRestoreCandidate(row,renamed)).toBe(false);
  });
});
