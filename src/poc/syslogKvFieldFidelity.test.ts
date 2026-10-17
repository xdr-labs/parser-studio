import {describe,expect,it} from 'vitest';
import {scoreKvFields,sourceKvReference} from './syslogKvFieldFidelity';

const qualified=()=>sourceKvReference([['src','10.0.0.1'],['act','allow']]);

describe('private Syslog/KV source-only field scoring contract',()=>{
  it('requires exact original key case and string value',()=>{
    expect(scoreKvFields(qualified(),{src:'10.0.0.1',act:'allow'})).toEqual({
      expected:2,extracted:2,exact:2,wrongValue:0,missing:0,unexpected:0,
      exactNameSet:true,exactEvent:true,
    });
  });
  it('counts a wrong value as an FP and an FN',()=>{
    const s=scoreKvFields(qualified(),{src:'bad',act:'allow'});
    expect([s.exact,s.wrongValue,s.missing,s.unexpected,s.exactEvent]).toEqual([1,1,0,0,false]);
    expect(s.extracted-s.exact).toBe(1);
    expect(s.expected-s.exact).toBe(1);
  });
  it('counts missing and spurious original key names separately',()=>{
    const s=scoreKvFields(qualified(),{src:'10.0.0.1',mode:'unexpected'});
    expect([s.exact,s.missing,s.unexpected,s.exactNameSet]).toEqual([1,1,1,false]);
  });
  it('abstains when the existing contract path is absent',()=>{
    const s=scoreKvFields(qualified(),null);
    expect([s.expected,s.extracted,s.exact,s.missing,s.exactEvent]).toEqual([2,0,0,2,false]);
  });
  it('rejects coerced values even at the right source key',()=>{
    const s=scoreKvFields(sourceKvReference([['port','443'],['enabled','true']]),
      {port:443,enabled:true});
    expect([s.exact,s.wrongValue,s.missing,s.unexpected]).toEqual([0,2,0,0]);
  });
  it('does not equate original hyphens, underscores, or mixed case',()=>{
    const s=scoreKvFields(sourceKvReference([['Src-IP','10.0.0.1'],['action','pass']]),
      {'Src_IP':'10.0.0.1',action:'pass'});
    expect([s.exact,s.missing,s.unexpected]).toEqual([1,1,1]);
  });
  it('rejects duplicate or canonically colliding source names',()=>{
    expect(()=>sourceKvReference([['a-b','1'],['a_b','2']])).toThrow(/Ambiguous/);
    expect(()=>sourceKvReference([['act','1'],['act','2']])).toThrow(/Ambiguous/);
  });
  it('rejects invalid or unsafe source oracle shapes',()=>{
    expect(()=>sourceKvReference([])).toThrow();
    expect(()=>sourceKvReference([['a','1'],['constructor','2']])).toThrow();
    expect(()=>sourceKvReference([['a',1],['b','2']])).toThrow();
    expect(()=>sourceKvReference([['a','1'],['b','2','3']])).toThrow();
    expect(()=>sourceKvReference([['a','1'],['b','new\nline']])).toThrow();
  });
  it('preserves empty and escaped-looking quoted source values exactly',()=>{
    const expected=sourceKvReference([['a',''],['b','a"b\\c']]);
    const actual={a:'',b:'a"b\\c'};
    expect(scoreKvFields(expected,actual).exactEvent).toBe(true);
  });
});
