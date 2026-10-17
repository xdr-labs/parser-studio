import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {parseZeekTsvBlock} from '../zeekTabular';

type Claim={row:number;name:string;rawLexeme:string;startByte:number;endByte:number};
type Case={id:string;wire:string;valid:boolean;path?:string;fields?:string[];
  rows?:string[];closed?:boolean;claims:Claim[];sourceBytes:number};
const raw=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardZeekRecordBoundaries.pinned.json'));
const expectedHash='7f4b4c4309409dc3e92bf4fb86f1b369f88f0039980db5e63b9cc1d8fb3ac561';
if(createHash('sha256').update(raw).digest('hex')!==expectedHash)
  throw Error('Pinned independently authored Zeek source-boundary oracle drifted');
const {cases}=JSON.parse(raw.toString('utf8')) as {cases:Case[]};
const decoder=new TextDecoder('utf-8',{fatal:true});

describe('P0-STD-7 Zeek declared schema, record close, and original source bytes',()=>{
  it('records immutable synthetic case denominators',()=>{
    expect(cases).toHaveLength(14);
    expect(cases.filter(c=>c.valid)).toHaveLength(4);
    expect(cases.filter(c=>!c.valid)).toHaveLength(10);
  });
  it.each(cases)('never misattributes Zeek rows across source boundaries: $id',test=>{
    const bytes=new TextEncoder().encode(test.wire);
    expect(bytes.length).toBe(test.sourceBytes);
    const observed=parseZeekTsvBlock(test.wire);
    expect(observed.ok).toBe(test.valid);
    if(!observed.ok)return;
    expect(observed.block.path).toBe(test.path);
    expect(observed.block.fields).toEqual(test.fields);
    expect(observed.block.closed).toBe(test.closed);
    expect(observed.block.rows).toHaveLength(test.rows!.length);
    expect(observed.block.rowFieldSpans).toHaveLength(test.rows!.length);
    const fields=observed.block.rowFieldSpans.flat();
    expect(fields).toHaveLength(test.claims.length);
    test.claims.forEach((claim,index)=>{
      const value=fields[index]!;
      expect(value).toEqual({
        name:claim.name,rawLexeme:claim.rawLexeme,
        startByte:claim.startByte,endByte:claim.endByte,
      });
      expect(decoder.decode(bytes.subarray(claim.startByte,claim.endByte)))
        .toBe(claim.rawLexeme);
      expect(observed.block.rows[claim.row]![claim.name]).toBe(claim.rawLexeme);
    });
    // Source offsets are lexical only: no inferred Zeek null/time/native types.
    expect(observed.block.unsetField).toBe('-');
    expect(observed.block.emptyField).toBe('(empty)');
  });
});
