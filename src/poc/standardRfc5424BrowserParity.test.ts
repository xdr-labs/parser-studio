import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe, expect, it} from 'vitest';
import {parseRfc5424Subset} from '../rfc5424Subset';
import {extractStructuredFamily} from '../structuredFamilies';
import {rfc5424SdByteEscapes} from './rfc5424SdByteEscapes';

type Param = {
  sdId:string;name:string;rawLexeme:string;decoded:string;
  nameStart:number;nameEnd:number;valueStart:number;valueEnd:number;
};
type Case = {
  id:string;wire:string;sdRaw:string;message:string;valid:boolean;
  expected:Param[];eventBytes:number;sdStart:number;sdEnd:number;
};
const pathToFrozen = path.join(__dirname, '../../scripts/poc/standardsRfc5424BrowserParity.pinned.json');
const frozen = fs.readFileSync(pathToFrozen);
const expectedHash = '8e5866687e04ee6f796278a6e7cce0a79e4a42222d7e79f02f67035f9fcdfd26';
if (createHash('sha256').update(frozen).digest('hex') !== expectedHash)
  throw Error('RFC5424 browser parity independent answer has changed');
const {cases} = JSON.parse(frozen.toString('utf8')) as {cases:Case[]};
const decoder = new TextDecoder('utf-8', {fatal:true});

describe('P0-STD-2 RFC5424 SD browser/source general grammar parity (authored normative oracle)',()=>{
  it('uses a fixed, synthetic-only and SHA-pinned answer set',()=>{
    expect(cases).toHaveLength(10);
    expect(cases.filter(x=>x.valid)).toHaveLength(6);
    expect(cases.filter(x=>!x.valid)).toHaveLength(4);
  });

  it.each(cases)('checks browser, byte observer and original offsets: $id',test=>{
    const original = new TextEncoder().encode(test.wire);
    expect(original.length).toBe(test.eventBytes);
    const source = rfc5424SdByteEscapes(original);
    const browser = parseRfc5424Subset(test.wire);
    const structured = extractStructuredFamily(test.wire, 'syslog_rfc5424', 'raw');
    expect(source !== null).toBe(test.valid);
    expect(browser.ok).toBe(test.valid);
    expect(structured.errors.length === 0).toBe(test.valid);
    if (!test.valid) return;
    expect(source).not.toBeNull();
    expect(source!.sourceBytes).toBe(test.eventBytes);
    expect(source!.structuredDataStart).toBe(test.sdStart);
    expect(source!.structuredDataEnd).toBe(test.sdEnd);
    expect(decoder.decode(original.subarray(test.sdStart,test.sdEnd))).toBe(test.sdRaw);
    const observed = source!.elements.flatMap(x=>x.params);
    expect(observed).toHaveLength(test.expected.length);
    test.expected.forEach((p,index)=>{
      const value = observed[index]!;
      expect({sdId:value.sdId,name:value.name,decoded:value.decodedValue,
        nameStart:value.rawNameStart,nameEnd:value.rawNameEnd,
        valueStart:value.rawValueStart,valueEnd:value.rawValueEnd})
        .toEqual({sdId:p.sdId,name:p.name,decoded:p.decoded,
          nameStart:p.nameStart,nameEnd:p.nameEnd,
          valueStart:p.valueStart,valueEnd:p.valueEnd});
      expect(decoder.decode(original.subarray(p.valueStart,p.valueEnd))).toBe(p.rawLexeme);
      expect(decoder.decode(original.subarray(p.nameStart,p.nameEnd))).toBe(p.name);
    });
    if (browser.ok) {
      expect(browser.fields.syslog_structured_data).toBe(test.sdRaw);
      expect(browser.message).toBe(test.message);
    }
    expect(structured.fields.syslog_structured_data).toBe(test.sdRaw);
    expect(structured.fields.message).toBe(test.message);
    expect(source!.nativeTarget).toBe('NOT_VERIFIED');
    expect(source!.canAutoPromote).toBe(false);
  });
});
