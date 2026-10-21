import {describe,it,expect} from 'vitest';
import {analyzeLogEnvelopes} from './autoParserEnvelope';
import {createDraft} from '../model';
import {extractFields} from '../parser';

const samples=[
  'action=allow action=deny',
  'src_ip=192.0.2.10 src_ip=198.51.100.10',
  'message="action=deny" action=allow action=block',
  '<34>1 2026-10-21T00:00:00Z gw app 1 EV01 - action=allow action=deny',
  '<134>Jan 16 15:19:05 gw app: action=allow action=deny',
];
const positives=[
  'message="action=deny" action=allow',
  'Action=allow action=deny',
  'src_ip=192.0.2.10 action=deny',
  '<34>1 2026-10-21T00:00:00Z gw app 1 EV01 - src_ip=192.0.2.10 action=allow',
];

describe('single-line KV source census uses the same duplicate-key policy as reviewed native parsing',()=>{
  it.each(samples)('marks repeated KV member names as malformed before compiler recommendation: %s',raw=>{
    const result=analyzeLogEnvelopes(raw,'single-line');
    expect(result).toMatchObject({sourceCount:1,accounted:1,unsupported:1,complete:true,
      nativeVerified:false,targetVerified:false});
    expect(result.events[0]).toMatchObject({body:'kv',status:'BODY_MALFORMED'});
    expect(JSON.stringify(result)).not.toContain('192.0.2.10');
    expect(JSON.stringify(result)).not.toContain('198.51.100.10');
    expect(JSON.stringify(result)).not.toContain('action=allow');
  });
  it('confirms the explicit KV extractor already rejects duplicate keys rather than overwriting',()=>{
    const draft=createDraft();draft.format='kv';
    const result=extractFields('action=allow action=deny','kv',draft);
    expect(result.errors).toContain('Duplicate key: action');
    expect(result.fields).toEqual({action:'allow'});
  });
  it.each(positives)('keeps valid distinct keys and quotes unambiguous: %s',raw=>{
    const result=analyzeLogEnvelopes(raw,'single-line');
    expect(result).toMatchObject({sourceCount:1,accounted:1,unsupported:0,complete:true});
    expect(result.events[0]).toMatchObject({body:'kv',status:'RECOGNIZED'});
  });
});
