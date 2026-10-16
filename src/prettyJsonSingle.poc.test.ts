import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const payload={
  metadata:{customerIDString:'public-example',eventType:'EndpointThreat',version:'1.0'},
  event:{timestamp:'2026-10-16T15:44:21Z',src:'192.0.2.10',severity:5,
    child:{processName:'app.exe',signals:['network','execution']}},
};
describe('complete pretty-printed JSON security input',()=>{
  it('accepts one multiline JSON object as a single reviewed event before line-event fallback',()=>{
    const raw=JSON.stringify(payload,null,2);
    const result=parseSecurityInput(raw);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.kind).toBe('single_event');
    expect(result.container).toBe(false);
    expect(result.events).toHaveLength(1);
    expect(result.events[0]?.fields).toEqual(payload);
    expect(result.source_raw).toBe(raw);
  });
  it('accepts complete nested JSON even when an inner object begins at column zero',()=>{
    const raw='{"outer":\n{"inner":{"event":"alert","src":"192.0.2.10"}}\n}';
    const result=parseSecurityInput(raw);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.kind).toBe('single_event');
    expect(result.events[0]?.fields).toEqual({outer:{inner:{event:'alert',src:'192.0.2.10'}}});
  });
  it('accepts one CRLF pretty JSON object without rewriting source values',()=>{
    const raw=JSON.stringify(payload,null,2).replaceAll('\n','\r\n');
    const result=parseSecurityInput(raw);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.kind).toBe('single_event');
    expect(result.events[0]?.fields).toEqual(payload);
    expect(result.source_raw).toBe(raw);
  });
  it('does not downgrade malformed, unsafe, or mixed JSON text into success',()=>{
    const invalid=[
      '{"metadata":{\n "event":"alert"\n',
      '{"event":"alert",\n "x":true} extra',
      '{"__proto__":{"polluted":true},\n "event":"alert"}',
      '{"event":{} }\nnot a JSON event',
      '{"event":"alert"}\n{"event":}',
    ];
    expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false,false,false]);
  });
});
