import {describe,it,expect} from 'vitest';
import {hasUnlabeledGenericPositions} from './genericTokenRoleReview';
import type {MultiPassSourcePreview} from './multipassPreviewClient';

const preview=(status:MultiPassSourcePreview['status'],fields:MultiPassSourcePreview['fields'])=>({status,fields});

describe('unlabeled structural token roles',()=>{
  it('identifies published Firebox-like generic tokens even with named KV or a Syslog wrapper',()=>{
    expect(hasUnlabeledGenericPositions(preview('SOURCE_PARSED',{generic:{
      tokens:['2024-03-29','Allow','192.168.228.202','10.0.1.1'],
      kv:{proc_id:'firewall'}
    }}))).toBe(true);
    expect(hasUnlabeledGenericPositions(preview('SOURCE_PARSED',{syslog:{host:'fw'},generic:{
      tokens:['Allow','10.0.1.2','198.51.100.1']
    }}))).toBe(true);
  });
  it('does not downgrade named KV/JSON, partial sources, or empty token groups',()=>{
    expect(hasUnlabeledGenericPositions(preview('SOURCE_PARSED',{srcip:'192.0.2.1'}))).toBe(false);
    expect(hasUnlabeledGenericPositions(preview('SOURCE_PARSED',{generic:{kv:{srcip:'192.0.2.1'}}}))).toBe(false);
    expect(hasUnlabeledGenericPositions(preview('SOURCE_PARSED',{generic:{tokens:[]}}))).toBe(false);
    expect(hasUnlabeledGenericPositions(preview('PARTIAL',{generic:{tokens:['192.0.2.1']}}))).toBe(false);
  });
});
