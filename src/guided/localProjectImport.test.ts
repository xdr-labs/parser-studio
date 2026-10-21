import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { toBackendProject } from './backendAdapter';
import { MAX_PROJECT_JSON_BYTES, reviewLocalProjectJson } from './localProjectImport';

function fixture(){
  const draft=createDraft();draft.format='json';draft.name='Local Synthetic Import';
  const mapped=toBackendProject(draft);
  if(!mapped.ok)throw Error('Reviewed fixture is not valid');
  return mapped.project;
}
const bytes=(x:unknown)=>new TextEncoder().encode(JSON.stringify(x));

describe('strict offline Project JSON import, without network, raw samples or lossy conversion',()=>{
  it('accepts only the full reviewed JSON schema and restores identical parser fields',()=>{
    const original=fixture();
    const draft=reviewLocalProjectJson(bytes(original));
    expect(draft).toMatchObject({name:'Local Synthetic Import',format:'json'});
    expect(draft.guided?.receiver.port).toBe(6801);
    const projected=toBackendProject(draft);
    expect(projected.ok).toBe(true);
    if(projected.ok)expect(projected.project).toEqual(original);
  });
  it('denies unsafe edits and unsupported protocol/schema without altering the original JSON',()=>{
    const original=fixture();
    const str=JSON.stringify(original);
    for(const item of [
      {...original,projectId:'private-tenant'},
      {...original,extraRawLog:'PRIVATE_EVENT'},
      {...original,slug:'../escape'},
      {...original,receiver:{...original.receiver,protocols:['http']}},
      {...original,normalization:{...original.normalization,
        vendorFields:{some:{normalized_name:'constructor.foo',data_type:'string'}}}},
      {...original,classification:{...original.classification,defaultIndex:'unknown'}},
    ]){
      expect(()=>reviewLocalProjectJson(bytes(item))).toThrow();
    }
    expect(JSON.stringify(original)).toBe(str);
  });
  it('rejects malformed UTF-8, empty files and oversized inputs fail-closed',()=>{
    expect(()=>reviewLocalProjectJson(new Uint8Array())).toThrow();
    expect(()=>reviewLocalProjectJson(new Uint8Array([0xc3,0x28]))).toThrow();
    expect(()=>reviewLocalProjectJson(new Uint8Array(MAX_PROJECT_JSON_BYTES+1))).toThrow();
    expect(()=>reviewLocalProjectJson(bytes([]))).toThrow();
    expect(()=>reviewLocalProjectJson(bytes({slug:'demo_fw'}))).toThrow();
  });
});
