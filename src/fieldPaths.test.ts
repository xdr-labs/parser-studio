import {describe,expect,it} from 'vitest';
import {listSafeLeafPaths,lookupFieldValue,safeLocalFieldPath} from './fieldPaths';

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
