import {describe,expect,it} from 'vitest';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {analyzeNamedLogs,assembleNamedLogs,newNamedLogType,validateNamedLogs} from './namedLogTypes';

const criStdout='2026-10-19T08:20:00Z stdout F user=김민수\n';
const criStderr='2026-10-19T08:20:01Z stderr F denied\n';
const dockerStdout=JSON.stringify({log:'user=김민수\n',stream:'stdout',
  time:'2026-10-19T08:20:00Z'})+'\n';
const dockerStderr=JSON.stringify({log:'denied\n',stream:'stderr',
  time:'2026-10-19T08:20:01Z'})+'\n';
const bytes=(source:string)=>new TextEncoder().encode(source);
const partial={
  status:'PARTIAL',
  fields:{},
} as MultiPassSourcePreview;

describe('Named source groups preserve physical record boundaries',()=>{
  for(const [name,first,second] of [
    ['Kubernetes CRI stdout and stderr',criStdout,criStderr],
    ['Docker JSON-file stdout and stderr',dockerStdout,dockerStderr],
  ] as const){
    it(name+' never inserts a second LF after complete physical records',()=>{
      const groups=[
        newNamedLogType('one','stdout',first),
        newNamedLogType('two','stderr',second),
      ];
      const combined=assembleNamedLogs(groups);
      expect(combined.source).toBe(first+second);
      expect(bytes(combined.source)).toEqual(bytes(first+second));
      expect(combined.spans.map(x=>[x.startByte,x.endByte]))
        .toEqual([[0,bytes(first).length],
                  [bytes(first).length,bytes(first+second).length]]);
      const analyzed=analyzeNamedLogs(groups,combined.spans.map(span=>({
        startByte:span.startByte,endByte:span.endByte,preview:partial,
      })));
      expect(analyzed.unassigned).toBe(0);
      expect(analyzed.groups.map(g=>({name:g.name,events:g.events,partial:g.partial,
        crossed:g.boundaryWarning})))
        .toEqual([
          {name:'stdout',events:1,partial:1,crossed:false},
          {name:'stderr',events:1,partial:1,crossed:false},
        ]);
      expect(validateNamedLogs(groups).ok).toBe(true);
    });
  }
  it('adds only one explicit LF between adjacent unterminated records',()=>{
    const first='{"type":"a","actor":"김민수"}';
    const second='{"type":"b","actor":"山田"}';
    const groups=[
      newNamedLogType('one','Threat',first),
      newNamedLogType('two','User',second),
    ];
    expect(assembleNamedLogs(groups).source).toBe(first+'\n'+second);
  });
  it('does not append a separator when one group already supplies the next LF',()=>{
    const first='{"kind":"a"}';
    const second='\n{"kind":"b"}';
    const groups=[
      newNamedLogType('one','First',first),
      newNamedLogType('two','Second',second),
    ];
    expect(assembleNamedLogs(groups).source).toBe(first+second);
  });
  it('does not strip intentionally authored empty lines or original CRLF',()=>{
    const first='{"type":"a"}\r\n';
    const second='\n{"type":"b"}\r\n';
    const groups=[
      newNamedLogType('one','First',first),
      newNamedLogType('two','Second',second),
    ];
    expect(assembleNamedLogs(groups).source).toBe(first+second);
  });
});
