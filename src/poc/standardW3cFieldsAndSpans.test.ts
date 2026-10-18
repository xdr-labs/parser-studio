import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {parseW3cLogBlock} from '../w3cTabular';

type Claim={name:string;rawLexeme:string;decoded:string;startByte:number;endByte:number};
type Case={id:string;wire:string;valid:boolean;delimiter?:'space'|'tab';
  expected:Claim[][];sourceBytes:number;physicalLines?:number;rowCount?:number};
const bytes=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardsW3cFieldsAndSpans.pinned.json'));
const digest='fed289f4d21e22109121875b3d0b5ec6afa470fb9018621a26d8db4b25327071';
if(createHash('sha256').update(bytes).digest('hex')!==digest)
  throw Error('Independently frozen W3C source oracle changed');
const {cases}=JSON.parse(bytes.toString('utf8')) as {cases:Case[]};
const decode=new TextDecoder('utf8',{fatal:true});

describe('P0-STD-7 W3C EFL declared fields / original byte spans (narrow subset)',()=>{
  it('seals independently authored syntax, negative and byte-exact denominators',()=>{
    expect(cases).toHaveLength(15);
    expect(cases.filter(x=>x.valid)).toHaveLength(7);
    expect(cases.filter(x=>!x.valid)).toHaveLength(8);
  });
  it.each(cases)('matches bounded W3C header, row and source field boundaries: $id',c=>{
    const original=new TextEncoder().encode(c.wire);
    expect(original).toHaveLength(c.sourceBytes);
    const out=parseW3cLogBlock(c.wire);
    expect(out.ok).toBe(c.valid);
    if(!out.ok)return;
    expect(out.block.schema.delimiter).toBe(c.delimiter);
    expect(out.block.rows).toHaveLength(c.rowCount!);
    expect(out.block.sourceBytes).toBe(c.sourceBytes);
    expect(out.block.physicalLines).toBe(c.physicalLines);
    expect(out.block.rowFieldSpans).toHaveLength(c.rowCount!);
    c.expected.forEach((expected,rowIndex)=>{
      const spans=out.block.rowFieldSpans[rowIndex]!;
      expect(spans).toHaveLength(expected.length);
      expected.forEach((item,columnIndex)=>{
        const got=spans[columnIndex]!;
        expect(got).toEqual({
          name:item.name,rawLexeme:item.rawLexeme,
          startByte:item.startByte,endByte:item.endByte,
        });
        expect(decode.decode(original.subarray(item.startByte,item.endByte)))
          .toBe(item.rawLexeme);
        expect(out.block.rows[rowIndex]![item.name]).toBe(item.decoded);
      });
    });
    expect(out.block.directives['Version']).toBe('1.0');
  });
});
