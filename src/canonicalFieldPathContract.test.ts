import {describe,expect,it} from 'vitest';
import {countUnaddressableSourceValues,hasAmbiguousFieldPath,hasAmbiguousSourceFields,
  listSafeLeafPaths,lookupFieldValue,mappingWhenApplies} from './fieldPaths';

describe('H1 source path contract: browser follows native Ruby partition resolution',()=>{
  it('resolves a unique intermediate dotted object key',()=>{
    const fields={syslog_sd:{'element.sub':{params:{'protocol-id':'6'}}}};
    const path='syslog_sd.element.sub.params.protocol-id';
    expect(lookupFieldValue(fields,path)).toEqual({found:true,value:'6'});
    expect(listSafeLeafPaths(fields)).toEqual([path]);
    expect(countUnaddressableSourceValues(fields)).toBe(0);
    expect(mappingWhenApplies(fields,{sourcePath:path,operator:'in',values:['6']})).toBe(true);
  });
  it('rejects ambiguous root/nested interpretations even for a reviewed selector',()=>{
    const fields={'user.name':'literal',user:{name:'nested'}};
    expect(hasAmbiguousFieldPath(fields,'user.name')).toBe(true);
    expect(hasAmbiguousSourceFields(fields)).toBe(true);
    for(const kind of [undefined,'literal_root','nested'] as const){
      expect(lookupFieldValue(fields,'user.name',kind)).toEqual({found:false});
    }
    expect(listSafeLeafPaths(fields)).toEqual([]);
    expect(countUnaddressableSourceValues(fields)).toBe(2);
  });
  it('rejects competing nested partitions without flattening or altering source',()=>{
    const fields={a:{'b.c':'dotted',b:{c:'nested'}}};
    const before=JSON.stringify(fields);
    expect(hasAmbiguousFieldPath(fields,'a.b.c')).toBe(true);
    expect(hasAmbiguousSourceFields(fields)).toBe(true);
    expect(lookupFieldValue(fields,'a.b.c')).toEqual({found:false});
    expect(lookupFieldValue(fields,'a.b.c','nested')).toEqual({found:false});
    expect(listSafeLeafPaths(fields)).toEqual([]);
    expect(countUnaddressableSourceValues(fields)).toBe(2);
    expect(JSON.stringify(fields)).toBe(before);
  });
});
