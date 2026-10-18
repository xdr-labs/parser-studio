import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildSampleUnionSchema} from './sampleUnionSchema';

describe('Union Schema from diverse samples of a common event family',()=>{
  it('combines username and hostname evidence across same-type logs without inventing absent fields',()=>{
    const draft={...createDraft(),format:'json' as const};
    const source=[
      '{"event_type":"threat","username":"alice","action":"deny"}',
      '{"event_type":"threat","hostname":"fw01","action":"allow"}',
      '{"event_type":"threat","username":"","hostname":"fw02","action":"deny"}',
    ].join('\n');
    const union=buildSampleUnionSchema(preview(source,draft));
    expect(union.reviewed).toBe(3);
    expect(union.groups).toHaveLength(1);
    const fields=Object.fromEntries(union.groups[0]!.fields.map(f=>[f.source,f]));
    expect(fields.username).toMatchObject({populated:1,blank:1,missing:1,optional:true});
    expect(fields.hostname).toMatchObject({populated:2,blank:0,missing:1,optional:true});
    expect(fields.action).toMatchObject({populated:3,missing:0,optional:false});
  });
  it('keeps threat, user and asset groups separate when explicitly labeled',()=>{
    const d={...createDraft(),format:'json' as const};
    const events=[
      '{"event_type":"threat","username":"alice"}',
      '{"event_type":"user","username":"alice"}',
      '{"event_type":"asset","hostname":"fw01"}',
    ].join('\n');
    const summary=buildSampleUnionSchema(preview(events,d));
    expect(summary.groups.map(x=>x.eventType)).toEqual(['threat','user','asset']);
    expect(summary.groups.find(x=>x.eventType==='asset')?.fields.some(f=>f.source==='username')).toBe(false);
  });
  it('never claims semantic names for positional temporary columns',()=>{
    const d={...createDraft(),format:'csv' as const,csvColumns:'field_001,field_002,field_003'};
    const s=preview('threat,,fw01\nthreat,alice,',d);
    const x=buildSampleUnionSchema(s,'field_001');
    expect(x.groups).toHaveLength(1);
    expect(x.groups[0]?.fields.find(x=>x.source==='field_002')?.semanticStatus).toBe('POSITIONAL_UNVERIFIED');
  });
  it('selects at most ten novel samples for inference but retains full test denominator',()=>{
    const d={...createDraft(),format:'json' as const};
    const s=Array.from({length:14},(_,i)=>JSON.stringify({event_type:'threat',action:'deny',
      ...(i<8?{username:'user'+i}:{hostname:'fw'+i})})).join('\n');
    const result=buildSampleUnionSchema(preview(s,d));
    expect(result.totalEvents).toBe(14);
    expect(result.reviewed).toBe(10);
    expect(result.moreSamplesNotUsed).toBe(4);
    const fields=result.groups[0]!.fields;
    expect(fields.some(f=>f.source==='username')).toBe(true);
    expect(fields.some(f=>f.source==='hostname')).toBe(true);
  });
});
