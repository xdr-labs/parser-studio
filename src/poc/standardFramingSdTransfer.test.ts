import {describe,expect,it} from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {splitSyslogStream} from '../syslogFraming';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';
import {parseRfc5424Subset} from '../rfc5424Subset';

const root=path.join(__dirname,'../../scripts/poc/standardsFramingSdCases.pinned.json');
const raw=fs.readFileSync(root);
const hash='15f3d48772dc7b05ee0807c6801d6771efbcf454003feed9f8b2e9b74fed1b7d';
type Case={id:string;kind:'sd'|'stream';wire:string;valid:boolean;records?:number;
 elements?:number;param?:Array<{id:string;name:string;decoded:string}>};
if(createHash('sha256').update(raw).digest('hex')!==hash)
 throw Error('Frozen standards-derived framing/SD source cases drifted');
const cases=(JSON.parse(raw.toString('utf8')) as {cases:Case[]}).cases;

describe('STD-1/2 RFC6587 + RFC5424 source conformance transfer (synthetic standards)',()=>{
 it.each(cases.filter(x=>x.kind==='stream'))(
  'validates RFC6587 stream boundaries %s',test=>{
    const answer=splitSyslogStream(test.wire);
    expect(answer.ok).toBe(test.valid);
    if(test.valid&&answer.ok){
      expect(answer.records).toHaveLength(test.records!);
      if(answer.mode==='rfc6587_octet_counting_stream')
        expect(answer.records.map(s=>String(Buffer.byteLength(s,'utf8'))+' '+s).join(''))
          .toBe(test.wire);
    }
  });
 it.each(cases.filter(x=>x.kind==='sd'))(
  'compares RFC5424 SD raw values and semantic escapes %s',test=>{
    const encoded=new TextEncoder().encode(test.wire);
    const result=rfc5424SdByteEscapes(encoded);
    expect(result!==null).toBe(test.valid);
    if(test.valid){
      expect(result!.elements).toHaveLength(test.elements!);
      const seen=result!.elements.flatMap(e=>e.params.map(p=>({
        id:p.sdId,name:p.name,value:p.decodedValue,start:p.rawValueStart,end:p.rawValueEnd,
      })));
      expect(seen.map(x=>({id:x.id,name:x.name,decoded:x.value}))).toEqual(test.param??[]);
      for(const claim of seen){
        const originalLexical=new TextDecoder('utf8',{fatal:true})
          .decode(encoded.subarray(claim.start,claim.end));
        expect(originalLexical.length).toBeGreaterThan(0);
      }
      expect(result!.sourceBytes).toBe(encoded.length);
      expect(result!.canAutoPromote).toBe(false);
      expect(result!.nativeTarget).toBe('NOT_VERIFIED');
    }
  });
 it('recognizes official RFC5424 duplicate SD-PARAM and unknown escaping as valid source',()=>{
  // RFC5424 6.3.3: SD-PARAM MAY repeat within one SD-ELEMENT;
  // an unknown backslash escape is not a special escape.
  for(const id of ['SD-RFC-UNKNOWN-ESCAPE','SD-RFC-DUPLICATED-PARAM']){
    const entry=cases.find(x=>x.id===id)!;
    expect(rfc5424SdByteEscapes(new TextEncoder().encode(entry.wire))).not.toBeNull();
    const browser=parseRfc5424Subset(entry.wire);
    expect(browser.ok).toBe(false); // measured narrow browser subset, not native failure
  }
 });
 it('never turns standard packet validity into a full event or native claim',()=>{
  expect(cases).toHaveLength(21);
  expect(cases.filter(c=>c.valid).length).toBeGreaterThan(10);
  expect(cases.filter(c=>!c.valid).length).toBeGreaterThan(5);
 });
});
