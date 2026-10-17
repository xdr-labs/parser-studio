import {describe,expect,it} from 'vitest';
import {compareJsonValues,jsonLeaves} from './jsonFieldFidelity';

describe('source JSON value precision and recall scorer',()=>{
  it('preserves nested paths, type identities, JSON Pointer escapes and empty containers',()=>{
    const original={'a/b':{'~key':['text',0,false,null]},empty:{},list:[]};
    const leaves=jsonLeaves(original);
    expect([...leaves]).toEqual([
      ['/a~1b/~0key/0','text'],['/a~1b/~0key/1',0],
      ['/a~1b/~0key/2',false],['/a~1b/~0key/3',null],
    ]);
    expect(compareJsonValues(leaves,structuredClone(original),original))
      .toEqual({expected:4,extracted:4,exactValues:4,mismatchedValues:0,
        missingPaths:0,unexpectedPaths:0,exactStructure:true});
    expect(compareJsonValues(leaves,{'a/b':{'~key':['text',0,false,null]}},original))
      .toMatchObject({exactValues:4,exactStructure:false});
  });

  it('counts wrong field values as BOTH failed recall and a false positive',()=>{
    const original={src:443,action:'deny',flag:true,removed:1};
    expect(compareJsonValues(jsonLeaves(original),
      {src:'443',action:'deny',flag:false,added:4},original)).toEqual({
      expected:4,extracted:4,exactValues:1,mismatchedValues:2,
      missingPaths:1,unexpectedPaths:1,exactStructure:false,
    });
  });

  it('does not convert unstructured records into JSON field successes',()=>{
    const original={action:'deny',nested:{value:1}};
    const r=compareJsonValues(jsonLeaves(original),undefined,original);
    expect(r).toMatchObject({expected:2,extracted:0,exactValues:0,
      missingPaths:2,exactStructure:false});
  });

  it('refuses unsafe names, invalid numeric precision, invalid or empty documents',()=>{
    expect(()=>jsonLeaves([])).toThrow('source object');
    expect(()=>jsonLeaves({})).toThrow('Empty');
    expect(()=>jsonLeaves(JSON.parse('{"constructor":"x"}'))).toThrow('Unsafe');
    expect(()=>jsonLeaves({count:Number.MAX_SAFE_INTEGER+1})).toThrow('Unscoreable');
    expect(()=>jsonLeaves({count:NaN})).toThrow('Unscoreable');
  });

  it('considers container shape differences even when scalar leaves are equal',()=>{
    const original={meta:{items:[],level:2}};
    const result=compareJsonValues(jsonLeaves(original),{meta:{items:{},level:2}},original);
    expect(result.exactValues).toBe(1);
    expect(result.exactStructure).toBe(false);
  });
});
