import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const BOM='\uFEFF';

describe('file-level UTF-8 BOM preamble PoC',()=>{
  it('strips exactly one BOM before standalone JSON parsing while preserving top-level raw input',()=>{
    const raw=BOM+'{"event":"alert","src":"192.0.2.1"}';
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('single_event');
    expect(parsed.source_raw).toBe(raw);
    expect(parsed.context).toMatchObject({utf8_bom:true});
    expect(parsed.events[0].fields).toMatchObject({event:'alert',src:'192.0.2.1'});
    expect(parsed.events[0].raw).toBe('{"event":"alert","src":"192.0.2.1"}');
  });

  it('reuses existing container grammars after a BOM without adding format-specific BOM rules',()=>{
    const inputs=[
      {kind:'ndjson',raw:BOM+'{"event":"a"}\n{"event":"b"}\n'},
      {kind:'rfc4180_csv',raw:BOM+'timestamp,src_ip,action\n2026-10-16T15:44:21Z,192.0.2.1,deny\n'},
      {kind:'single_event',raw:BOM+'<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow'},
    ];
    for(const sample of inputs){
      const parsed=parseSecurityInput(sample.raw);
      expect(parsed.ok,sample.kind).toBe(true);
      if(!parsed.ok)continue;
      expect(parsed.kind,sample.kind).toBe(sample.kind);
      expect(parsed.context?.utf8_bom,sample.kind).toBe(true);
      expect(parsed.source_raw,sample.kind).toBe(sample.raw);
    }
  });

  it('preserves line framing context when a BOM precedes a heterogeneous line stream',()=>{
    const raw=BOM+[
      'CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1',
      '{"event":"alert","src":"192.0.2.2"}',
    ].join('\n')+'\n';
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('line_event_stream');
    expect(parsed.context).toEqual({framing:'lf',utf8_bom:true});
    expect(parsed.events).toHaveLength(2);
  });

  it('rejects duplicate BOMs, BOM-only input, and BOM appearing inside a line stream',()=>{
    const invalid=[
      BOM+BOM+'{"event":"a"}',
      BOM,
      'CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1\n'+BOM+'CEF:1|Vendor|EDR|1|43|Threat|8|src=192.0.2.2\n',
    ];
    const results=invalid.map(raw=>parseSecurityInput(raw));
    expect(results.map(result=>result.ok)).toEqual([false,false,false]);
  });
});
