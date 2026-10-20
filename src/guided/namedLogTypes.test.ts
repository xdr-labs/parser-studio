import {describe,it,expect} from 'vitest';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {assembleNamedLogs,newNamedLogType,validateNamedLogs,analyzeNamedLogs} from './namedLogTypes';

const parsed=(fields:Record<string,unknown>,status:MultiPassSourcePreview['status']='SOURCE_PARSED')=>({
  status,fields,
}) as MultiPassSourcePreview;
const u8=(value:string)=>new TextEncoder().encode(value).length;
describe('explicit user-named log type inputs',()=>{
  it('keeps every original multilingual source byte unchanged with exact group boundaries',()=>{
    const first='{"event_type":"threat","username":"김민수"}';
    const second='{"event_type":"user","message":"認証 失敗"}';
    const groups=[
      newNamedLogType('a','Threat',first),
      newNamedLogType('b','User',second),
    ];
    const joined=assembleNamedLogs(groups);
    expect(joined.source).toBe(first+'\n'+second);
    const bytes=new TextEncoder().encode(joined.source);
    expect(new TextDecoder().decode(bytes.slice(joined.spans[0]!.startByte,joined.spans[0]!.endByte)))
      .toBe(first);
    expect(new TextDecoder().decode(bytes.slice(joined.spans[1]!.startByte,joined.spans[1]!.endByte)))
      .toBe(second);
    expect(joined.spans[1]!.startByte).toBe(u8(first)+1);
    expect(validateNamedLogs(groups)).toMatchObject({ok:true,bytes:u8(joined.source)});
  });

  it('prevents missing, duplicate, unsafe and over-budget entries from silently disappearing',()=>{
    const source=newNamedLogType('a','Threat','{"action":"deny"}');
    expect(validateNamedLogs([source,newNamedLogType('b','User')])).toMatchObject({ok:false});
    expect(validateNamedLogs([source,newNamedLogType('b','threat','foo')]).issues)
      .toContain('Log type 2: choose a unique log type name.');
    expect(validateNamedLogs([newNamedLogType('__proto__','Unsafe','x')]).ok).toBe(false);
    expect(validateNamedLogs([newNamedLogType('a','X'.repeat(65),'x')]).ok).toBe(false);
    expect(validateNamedLogs([newNamedLogType('a','Big','😀'.repeat(17000))]).ok).toBe(false);
    expect(validateNamedLogs(Array.from({length:11},(_,i)=>
      newNamedLogType('id-'+i,'Type '+i,'x'))).ok).toBe(false);
  });

  it('reports per-type source fields and strict statuses without creating routing predicates',()=>{
    const groups=[
      newNamedLogType('a','Threat','{"event_type":"threat","action":"deny"}'),
      newNamedLogType('b','User','{"event_type":"user","username":"이름"}'),
      newNamedLogType('c','Asset','{"host":"fw1"}'),
    ];
    const joined=assembleNamedLogs(groups);
    const events=joined.spans.map((span,i)=>({
      startByte:span.startByte,endByte:span.endByte,
      preview:i===0?parsed({event_type:'threat',action:'deny'}):
        i===1?parsed({event_type:'user',username:'이름'},'PARTIAL'):
        parsed({},'RAW_ONLY'),
    }));
    const report=analyzeNamedLogs(groups,events);
    expect(report.unassigned).toBe(0);
    expect(report.groups.map(g=>[g.name,g.events,g.parsed,g.partial,g.rawOnly]))
      .toEqual([
        ['Threat',1,1,0,0],['User',1,0,1,0],['Asset',1,0,0,1],
      ]);
    expect(report.groups[0]?.fields).toEqual(['action','event_type']);
    expect(report.groups[1]?.fields).toEqual([]);
  });

  it('refuses to assign an event crossing two named source ranges',()=>{
    const groups=[newNamedLogType('a','A','foo'),newNamedLogType('b','B','bar')];
    const report=analyzeNamedLogs(groups,[{
      startByte:0,endByte:7,preview:parsed({event_type:'anything'}),
    }]);
    expect(report.unassigned).toBe(1);
    expect(report.groups.map(row=>row.events)).toEqual([0,0]);
    expect(report.groups.every(row=>row.boundaryWarning)).toBe(true);
  });
});
