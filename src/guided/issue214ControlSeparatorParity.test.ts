import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from '../genericStructural';
import {analyzeLogEnvelopes} from './autoParserEnvelope';

const BASE='<134>Nov  5 13:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6';
const UNSAFE=[0x0b,0x0c,0x0d,0x1c,0x1d,0x1e,0x1f];

describe('Issue #214: physical controls are never accepted as generic KV separators',()=>{
  it.each(UNSAFE)('rejects physical codepoint 0x%s without creating fields',code=>{
    const raw=BASE.replace('action=deny','action='+String.fromCharCode(code)+'deny');
    const structured=extractGenericStructural(raw);
    expect(structured.fields).toEqual({});
    expect(structured.errors).not.toEqual([]);
    const census=analyzeLogEnvelopes(raw,'single-line');
    expect(census.sourceCount).toBe(1);
    expect(census.unsupported).toBe(1);
    expect(census.events[0]?.status).not.toBe('RECOGNIZED');
  });
  it('retains support for ordinary space, tab, and UTF-8 log values',()=>{
    for(const raw of [BASE,BASE+' note=한😀']){
      expect(extractGenericStructural(raw).errors).toEqual([]);
      expect(analyzeLogEnvelopes(raw,'single-line').unsupported).toBe(0);
    }
  });
});