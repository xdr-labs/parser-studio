import {describe,expect,it} from 'vitest';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {materializeParserSetFamily,planParserSet,type ParserSetFrame} from './parserSetPlanner';

function parsedPreview():MultiPassSourcePreview{
  return {
    contract:'parser-studio.multipass-source-preview.v0.1',
    status:'SOURCE_PARSED',
    syntax:'SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV',
    sourceSha256:'a'.repeat(64),
    sourceBytes:1,
    fields:{generic:{fields:{type:'TRAFFIC'}}},
    spans:[],residuals:[],issues:[],
    nativeVerified:false,targetVerified:false,
  };
}

describe('parser set materialization bounds',()=>{
  it('rejects inconsistent count and repeated or out-of-order indexes',()=>{
    const source='A\nB\nC';
    const frames:ParserSetFrame[]=[
      {startByte:0,endByte:1,preview:parsedPreview()},
      {startByte:2,endByte:3,preview:parsedPreview()},
      {startByte:4,endByte:5,preview:parsedPreview()},
    ];
    const group=planParserSet(frames).groups[0]!;
    expect(materializeParserSetFamily(source,frames,{...group,count:group.count+1}))
      .toEqual({ok:false,reason:'SOURCE_MISMATCH'});
    expect(materializeParserSetFamily(source,frames,{...group,eventIndexes:[0,0,2]}))
      .toEqual({ok:false,reason:'SOURCE_MISMATCH'});
    expect(materializeParserSetFamily(source,frames,{...group,eventIndexes:[2,1,0]}))
      .toEqual({ok:false,reason:'SOURCE_MISMATCH'});
  });

  it('rejects overlapping selected byte frames',()=>{
    const source='ABCD';
    const frames:ParserSetFrame[]=[
      {startByte:0,endByte:2,preview:parsedPreview()},
      {startByte:1,endByte:3,preview:parsedPreview()},
    ];
    const group=planParserSet(frames).groups[0]!;
    expect(materializeParserSetFamily(source,frames,group))
      .toEqual({ok:false,reason:'SOURCE_MISMATCH'});
  });
});
