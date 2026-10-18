import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {compareLocalVersions,sameLocalWorking,validLocalDraft} from './localWorkspaceHistory';

describe('browser-only parser experiment version contract',()=>{
  it('distinguishes source, parser grammar and field-mapping experiments without changing source objects',()=>{
    const base=createDraft();
    const changed=structuredClone(base);
    changed.format='kv';
    changed.csvColumns='action,source,destination';
    changed.mappings[0]={...changed.mappings[0],target:'srcip'};
    changed.mappings.push({id:'hostname',source:'syslog.hostname',target:'hostname',type:'string'});
    const left={source:'action=allow src=192.0.2.10',datasetName:'Draft one',draft:base};
    const right={source:'action=deny src=192.0.2.11',datasetName:'Draft two',draft:changed};
    const result=compareLocalVersions(left,right);
    expect(result).toMatchObject({
      sourceChanged:true,changedLines:1,draftChanged:true,
      addedMappings:['hostname'],removedMappings:[],editedMappings:['source-ip'],
    });
    expect(result.changes).toEqual(expect.arrayContaining([
      'Dataset name','Parser format','CSV schema / delimiter','Field mappings',
    ]));
    expect(sameLocalWorking(left,right)).toBe(false);
    expect(base.format).toBe('auto');
    expect(base.mappings).toHaveLength(3);
  });

  it('preserves exact event source, mapping order and JSON-safe draft settings',()=>{
    const draft=createDraft();
    const a={source:'allowed 😀,allow,\n"quoted,cell"',datasetName:'UTF-8 source',draft};
    const copied=structuredClone(a);
    expect(validLocalDraft(copied.draft)).toBe(true);
    expect(sameLocalWorking(a,copied)).toBe(true);
    expect(compareLocalVersions(a,copied)).toMatchObject({
      sourceChanged:false,changedLines:0,draftChanged:false,
      addedMappings:[],removedMappings:[],editedMappings:[],changes:[],
    });
  });

  it('rejects duplicate, malformed and unsafe persisted parser settings',()=>{
    const draft=createDraft();
    expect(validLocalDraft({...draft,format:'forged'})).toBe(false);
    expect(validLocalDraft({...draft,mappings:[...draft.mappings,draft.mappings[0]]})).toBe(false);
    expect(validLocalDraft({...draft,mappings:[{id:'a',source:'src',target:'dst',type:'run_code'}]})).toBe(false);
    expect(validLocalDraft({...draft,guided:JSON.parse('{"__proto__":{"isAdmin":true}}')})).toBe(false);
    expect(validLocalDraft({...draft,mappings:Array.from({length:101},(_,i)=>({
      id:String(i),source:'src',target:'custom.foo',type:'string'}))})).toBe(false);
  });
});
