import { describe, expect, it } from 'vitest';
import { createDraft } from '../model';
import { preview } from '../parser';
import { summarizeFamilyCoverage } from './familyCoverage';

describe('mixed-family browser preview diagnosis and privacy',()=>{
  it('counts JSON/KV/unknown separately and flags cross-family samples with no embedded values',()=>{
    const draft=createDraft();
    draft.format='json';
    const input=[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
      'action=deny src_ip=203.0.113.7 dst_port=22',
      '{"action":"allow","src_ip":"192.0.2.2","dst_port":80}',
      'no well-formed structure here',
    ].join('\n');
    const report=summarizeFamilyCoverage(preview(input,draft).events,draft.format);
    expect(report).toEqual({
      total:4,
      groups:[
        {format:'json',count:2},
        {format:'kv',count:1},
        {format:'unknown',count:1},
      ],
      detectedFamilyCount:2,
      unexpected:1,unknown:1,
      incompatible:true,
      firstUnexpectedEventId:'event-2',
    });
    expect(JSON.stringify(report)).not.toContain('198.51.100.10');
    expect(JSON.stringify(report)).not.toContain('203.0.113.7');
  });
  it('keeps single format fixtures free of false multi-family alerts',()=>{
    const draft=createDraft();draft.format='json';
    const report=summarizeFamilyCoverage(preview('{"action":"allow"}\n{"action":"deny"}',draft).events,draft.format);
    expect(report).toMatchObject({total:2,detectedFamilyCount:1,unexpected:0,unknown:0,incompatible:false});
  });
  it('requires explicit format when Auto is selected and multiple families detected',()=>{
    const draft=createDraft();draft.format='auto';
    const report=summarizeFamilyCoverage(preview('{"action":"allow"}\naction=deny',draft).events,draft.format);
    expect(report).toMatchObject({total:2,detectedFamilyCount:2,unexpected:0,incompatible:true});
  });
  it('does not report sample contents or claim target-supported routing',()=>{
    const report=summarizeFamilyCoverage([], 'json');
    expect(report).toEqual({
      total:0,groups:[],detectedFamilyCount:0,unexpected:0,unknown:0,
      incompatible:false,firstUnexpectedEventId:null,
    });
  });
});
