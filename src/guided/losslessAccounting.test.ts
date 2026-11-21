import {describe,it,expect} from 'vitest';
import {preview} from '../parser';
import {createDraft,type ParserDraft} from '../model';
import {accountLosslessSource} from './losslessAccounting';
import {sha256Utf8Hex} from '../sha256';

describe('independent lossless source accounting',()=>{
 it('accounts UTF-8 multi-event source, parsed leaves, actual output and exact supplied residuals',async()=>{
  const raw='{"name":"東京","nested":[{"ok":true},null]}\nnot-json';
  const draft={...createDraft(),format:'json' as const};
  const suite=preview(raw,draft);
  const result=await accountLosslessSource(raw,suite.events.map((event,index)=>({event:{...event,parseStatus:index===0?'PARTIAL':'ERROR'},
   ...(index===0?{residuals:[]}:{residuals:[{startByte:0,endByte:new TextEncoder().encode(event.raw).length}]})})),draft);
  expect(result.sourceSha256).toBe(await sha256Utf8Hex(raw));
  expect(result.sourceBytes).toBe(new TextEncoder().encode(raw).length);
  expect(result.eventCount).toBe(2);
  expect(result.events[0]?.structuralLeafPaths).toContain('name');
  expect(result.events[0]?.structuralLeafPaths).not.toContain('generic.source_raw');
  expect(result.events[1]?.residuals).toEqual([{startByte:0,endByte:new TextEncoder().encode('not-json').length}]);
  expect(result.events[0]?.notMappablePaths.some(path=>path.includes('[array]'))).toBe(true);
  expect(result.proof).toBe('COMPLETE');
 });
 it('keeps absent proof UNKNOWN and counts only real normalized output leaves',async()=>{
  const raw='CEF:0|A|1|x|y|z|src=192.0.2.1';
  const draft={...createDraft(),format:'cef' as const};
  const suite=preview(raw,draft);
  const result=await accountLosslessSource(raw,suite.events.map(event=>({event})),draft);
  expect(result.proof).toBe('UNKNOWN');
  expect(result.events[0]?.residuals).toBeNull();
  expect(result.events[0]?.outputEvidence).toBe('PRESENT_BROWSER_PREVIEW');
 });
 it('bounds oversized source path reporting without truncating the event count',async()=>{
  const raw=JSON.stringify(Object.fromEntries(Array.from({length:130},(_,i)=>['field_'+i,i])));
  const draft={...createDraft(),format:'json' as const};const suite=preview(raw,draft);
  const result=await accountLosslessSource(raw,suite.events.map(event=>({event:{...event,parseStatus:'FULL'},residuals:[]})),draft);
  expect(result.eventCount).toBe(1);
  expect(result.events[0]!.structuralLeafPaths.length).toBeGreaterThan(100);
 });
 it('preserves exact records and reports unknown grammar proof without promoting malformed input',async()=>{
  const cases:[string,ParserDraft['format']][]=[
   ['name,message\n"café","hello, world"','csv'],
   ['CEF:0|Vendor|Product|1|bad|Malformed CEF','cef'],
   ['LEEF:2.0|Vendor|Product|1|bad','leef'],
   ['{"x":1}','json'],
   ['opaque unsupported record','regex'],
  ];
  for(const [raw,format] of cases){
   const draft={...createDraft(),format};const suite=preview(raw,draft);
   const result=await accountLosslessSource(raw,suite.events.map(event=>({event})),draft);
   expect(result.sourceSha256).toMatch(/^[a-f0-9]{64}$/);
   expect(result.sourceBytes).toBe(new TextEncoder().encode(raw).length);
   expect(result.events.every(event=>event.structuralStatus!=='FULL'||event.structuralLeafPaths.length>0)).toBe(true);
   expect(result.proof).toBe('UNKNOWN');
  }
 });
 it('does not confuse colliding dotted paths or null and array values with safe mapped leaves',async()=>{
  const raw='{"a.b":"literal","a":{"b":"nested"},"n":null,"arr":[1,null]}';
  const draft={...createDraft(),format:'json' as const};const suite=preview(raw,draft);
  const result=await accountLosslessSource(raw,suite.events.map(event=>({event:{...event,parseStatus:'PARTIAL'},residuals:[]})),draft);
  expect(result.events[0]!.notMappablePaths.some(path=>path.includes('ambiguous'))).toBe(true);
  expect(result.events[0]!.notMappablePaths.some(path=>path.includes('[null]'))).toBe(true);
  expect(result.events[0]!.notMappablePaths.some(path=>path.includes('[array]'))).toBe(true);
 });
 it('fails closed when caller events do not independently reconcile to source bytes',async()=>{
  const raw='{"a":1}\n{"b":2}';const draft={...createDraft(),format:'json' as const};
  const event=preview('{"a":1}',draft).events[0]!;
  const result=await accountLosslessSource(raw,[{event:{...event,parseStatus:'FULL'},residuals:[]}],draft);
  expect(result.proof).toBe('UNKNOWN');
  expect(result.unaccountedEventIds).toContain(event.id);
 });
 it('fails closed on invalid UTF-8 residual ranges and truncated structural accounting',async()=>{
  const draft={...createDraft(),format:'json' as const};
  const raw=JSON.stringify(Object.fromEntries(Array.from({length:2100},(_,i)=>['f'+i,i])));
  const event=preview(raw,draft).events[0]!;
  const result=await accountLosslessSource(raw,[{event:{...event,parseStatus:'FULL'},residuals:[
   {startByte:0,endByte:new TextEncoder().encode(raw).length+1},
  ]}],draft);
  expect(result.proof).toBe('UNKNOWN');
  expect(result.events[0]?.pathListTruncated).toBe(true);
 });
});
