import {describe,expect,it} from 'vitest';
import {listSafeLeafPaths,lookupFieldValue,safeLocalFieldPath,countUnaddressableSourceValues} from './fieldPaths';

describe('safe browser field paths',()=>{
 it('supports backend-safe hyphenated security field segments',()=>{
  const fields={generic:{kv:{'AD-Domain':'example.local','AD-IP-Address':'192.0.2.10'}}};
  expect(safeLocalFieldPath('generic.kv.AD-Domain')).toBe(true);
  expect(lookupFieldValue(fields,'generic.kv.AD-Domain')).toEqual({found:true,value:'example.local'});
  expect(listSafeLeafPaths(fields)).toContain('generic.kv.AD-IP-Address');
 });
 it('still rejects unsafe prototype and unsupported slash segments',()=>{
  expect(safeLocalFieldPath('generic.kv.__proto__')).toBe(false);
  expect(safeLocalFieldPath('generic.kv.bad/name')).toBe(false);
 });
});

describe('literal dotted source keys versus nested object paths',()=>{
  it('discloses a nested field hidden by a conflicting literal dotted root key',()=>{
    const fields={user:{name:'nested-value'},'user.name':'literal-value'};
    expect(listSafeLeafPaths(fields)).toEqual(['user.name']);
    expect(lookupFieldValue(fields,'user.name')).toEqual({found:true,value:'literal-value'});
    expect(countUnaddressableSourceValues(fields)).toBe(1);
  });
});

describe('loss-aware source field coverage',()=>{
  it('does not propose unresolvable nested keys and reports unsupported values',()=>{
    const fields={
      timestamp:'2026-11-03T11:00:00Z',
      metadata:{
        'session.id':'ABC-123',
        'actor@realm':'alice',
        evidence:['IOC-A','IOC-B'],
        'source-address':'192.0.2.10',
      },
    };
    const paths=listSafeLeafPaths(fields);
    expect(paths).toEqual(['timestamp','metadata.source-address']);
    for(const path of paths)expect(lookupFieldValue(fields,path).found).toBe(true);
    expect(countUnaddressableSourceValues(fields)).toBe(3);
  });

  it('counts source fields beyond the safe mapping budget, without erasing the input',()=>{
    const fields=Object.fromEntries(Array.from({length:120},(_,i)=>['field_'+i,'value']));
    expect(listSafeLeafPaths(fields)).toHaveLength(100);
    expect(countUnaddressableSourceValues(fields)).toBe(20);
  });
});
