import {describe,expect,it} from 'vitest';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {materializeParserSetFamily,planParserSet,type ParserSetFrame} from './parserSetPlanner';

function preview(type:string,syntax='SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV'):MultiPassSourcePreview{
  return {
    contract:'parser-studio.multipass-source-preview.v0.1',
    status:'SOURCE_PARSED',syntax,sourceSha256:'a'.repeat(64),sourceBytes:1,
    fields:{generic:{fields:{type}}},spans:[],residuals:[],issues:[],
    nativeVerified:false,targetVerified:false,
  };
}

describe('parser set planner',()=>{
  it('separates explicit source-parsed event families instead of forcing one parser',()=>{
    const frames:ParserSetFrame[]=[
      {startByte:0,endByte:1,preview:preview('TRAFFIC')},
      {startByte:2,endByte:3,preview:preview('THREAT','SECURITY_SYSLOG_ENVELOPE+PANOS_THREAT_CSV')},
      {startByte:4,endByte:5,preview:preview('TRAFFIC')},
    ];
    const plan=planParserSet(frames);
    expect(plan.status).toBe('MULTI_FAMILY');
    expect(plan.accounted).toBe(3);
    expect(plan.groups.map(group=>[group.family,group.count])).toEqual([
      ['TRAFFIC',2],['THREAT',1],
    ]);
  });

  it('does not claim a parser set when any event lacks family evidence',()=>{
    const unresolved={...preview('TRAFFIC'),fields:{},syntax:'GENERIC_POSITIONAL_CSV'};
    const plan=planParserSet([
      {startByte:0,endByte:1,preview:preview('TRAFFIC')},
      {startByte:2,endByte:3,preview:unresolved},
    ]);
    expect(plan.status).toBe('INSUFFICIENT_EVIDENCE');
    expect(plan.accounted).toBe(1);
  });

  it('materializes only the exact selected event frames',()=>{
    const source='A\nB\nC';
    const frames:ParserSetFrame[]=[
      {startByte:0,endByte:1,preview:preview('TRAFFIC')},
      {startByte:2,endByte:3,preview:preview('THREAT')},
      {startByte:4,endByte:5,preview:preview('TRAFFIC')},
    ];
    const group=planParserSet(frames).groups[0]!;
    expect(materializeParserSetFamily(source,frames,group)).toEqual({ok:true,source:'A\nC',count:2});
  });
});
