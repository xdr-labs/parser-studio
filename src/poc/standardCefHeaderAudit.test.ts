import {describe,expect,it} from 'vitest';
import {extractStructuredFamily} from '../structuredFamilies';
import {inspectCefStandardHeader} from './standardCefHeaderAudit';

const good='CEF:0|ACME|IDS|1|E1|blocked a \\| pipe|5|msg=hello\\nworld src=192.0.2.1';
describe('STD-3 required CEF header grammar and false-complete source review',()=>{
 it('recovers escaped header pipes and preserves original UTF-8 lexical spans',()=>{
  const value='CEF:0|Exämple|IDS|1|E1|blocked a \\| pipe|5|src=192.0.2.1';
  const out=inspectCefStandardHeader(value);
  expect(out.disposition).toBe('REVIEW_ONLY_HEADER');
  expect(out.fields).toHaveLength(7);
  expect(out.fields.find(x=>x.name==='name')?.decoded).toBe('blocked a | pipe');
  const rawBytes=new TextEncoder().encode(value);
  for(const field of out.fields){
    expect(new TextDecoder().decode(rawBytes.subarray(field.startByte,field.endByte)))
      .toBe(field.sourceLexeme);
  }
  expect(out.completeEvent).toBe(false);
  expect(out.nativeStellar).toBe('NOT_VERIFIED');
 });
 it('does not overclaim a complete event merely from a valid header',()=>{
  const out=inspectCefStandardHeader(good);
  expect(out.disposition).toBe('REVIEW_ONLY_HEADER');
  expect(out.fields).toHaveLength(7);
  expect(out.reason).toContain('EXTENSION_UNSCORED');
  expect(out.autoPromoted).toBe(false);
 });
 it('identifies missing required CEF vendor/severity that browser parser currently accepts',()=>{
  const invalid=[
    'CEF:0||IDS|1|E1|blocked|5|src=192.0.2.1',
    'CEF:0|ACME|IDS|1|E1|blocked||src=192.0.2.1',
    'CEF:0|ACME|IDS|1|E1|blocked|99|src=192.0.2.1',
  ];
  for(const raw of invalid){
    const browser=extractStructuredFamily(raw,'cef');
    expect(browser.errors).toEqual([]); // reproducible baseline risk
    const gate=inspectCefStandardHeader(raw);
    expect(gate.disposition).toBe('ABSTAIN_UNSAFE');
    expect(gate.fields).toEqual([]);
    expect(gate.completeEvent).toBe(false);
  }
 });
 it('rejects malformed header escapes, control bytes and unknown grammar',()=>{
  for(const raw of [
    'CEF:0|ACME|IDS|1|E1|bad \\q|5|src=1',
    'CEF:0|ACME|IDS|1|E1|bad|5',
    'CEF:0|ACME|IDS|1|E1|bad|5|\nsecond event',
    'CEF:0|ACME|IDS|1|E1|bad|5|'+('x'.repeat(9000)),
    'CEF:4|ACME|IDS|1|E1|bad|5|src=1',
  ]){
    const out=inspectCefStandardHeader(raw);
    expect(out.disposition).toBe('ABSTAIN_UNSAFE');
    expect(out.fields).toEqual([]);
  }
 });
 it('supports independently allowed CEF severity labels and exact UTF-8 spans',()=>{
  for(const severity of ['0','10','Unknown','Low','High','Very-High']){
    const raw='CEF:1|Vendor|Product|1|Class|Event|'+severity+'|';
    const out=inspectCefStandardHeader(raw);
    expect(out.disposition).toBe('REVIEW_ONLY_HEADER');
    expect(out.fields.at(-1)?.decoded).toBe(severity);
  }
 });
 it('enforces vendor and product declared limits instead of silently truncating',()=>{
  for(const value of [
    'X'.repeat(64)+'|P|1|E1|Alert|5|',
    'Acme|P|'+('1'.repeat(32))+'|E1|Alert|5|',
    'Acme|P|1|'+('E'.repeat(1024))+'|Alert|5|',
  ]){
    const out=inspectCefStandardHeader('CEF:0|'+value);
    expect(out.disposition).toBe('ABSTAIN_UNSAFE');
    expect(out.fields).toEqual([]);
  }
 });
});
