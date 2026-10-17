import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {extractStructuredFamily} from '../structuredFamilies';
import {inspectCefStandardHeader} from './standardCefHeaderAudit';

type Field={name:string;lexeme:string;decoded:string;startByte:number;endByte:number};
type Case={id:string;wire:string;valid:boolean;extension?:string;fields:Field[];sourceBytes:number};
const file=fs.readFileSync(path.join(__dirname,'../../scripts/poc/standardCefHeaderParity.pinned.json'));
const sha='b898bf634b5d4e82676b17c799778c8f0ea5f187c449e70f325269483f1ec0fe';
if(createHash('sha256').update(file).digest('hex')!==sha)
  throw Error('Independently frozen CEF header answer changed');
const {cases}=JSON.parse(file.toString('utf8')) as {cases:Case[]};
const browserNames=['cef_version','cef_device_vendor','cef_device_product',
  'cef_device_version','cef_signature_id','cef_name','cef_severity'];

describe('P0-STD-3 CEF standard header shared grammar parity (synthetic CEF v26)',()=>{
  it('has pre-registered outcome denominators and isolated provenance',()=>{
    expect(cases).toHaveLength(13);
    expect(cases.filter(x=>x.valid)).toHaveLength(6);
    expect(cases.filter(x=>!x.valid)).toHaveLength(7);
  });
  it.each(cases)('matches required header, decoded value and absolute byte position: $id',t=>{
    const bytes=new TextEncoder().encode(t.wire);
    expect(bytes.length).toBe(t.sourceBytes);
    const browser=extractStructuredFamily(t.wire,'cef');
    const source=inspectCefStandardHeader(t.wire);
    expect(browser.errors.length===0).toBe(t.valid);
    expect(source.disposition==='REVIEW_ONLY_HEADER').toBe(t.valid);
    expect(source.completeEvent).toBe(false);
    expect(source.nativeStellar).toBe('NOT_VERIFIED');
    if(!t.valid){
      expect(source.fields).toEqual([]);
      return;
    }
    expect(source.fields).toHaveLength(7);
    t.fields.forEach((expected,i)=>{
      const s=source.fields[i]!;
      expect({name:s.name,decoded:s.decoded,lexeme:s.sourceLexeme,
        startByte:s.startByte,endByte:s.endByte})
        .toEqual({name:expected.name,decoded:expected.decoded,lexeme:expected.lexeme,
          startByte:expected.startByte,endByte:expected.endByte});
      expect(new TextDecoder('utf8',{fatal:true})
        .decode(bytes.subarray(expected.startByte,expected.endByte))).toBe(expected.lexeme);
      expect(browser.fields[browserNames[i]!]).toBe(expected.decoded);
    });
  });
});
