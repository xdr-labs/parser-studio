import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {inspectStandardZeekRotationSource} from './standardZeekRotationSource';
import {parseZeekTsvBlock} from '../zeekTabular';

type Claim={row:number;name:string;rawLexeme:string;startByte:number;endByte:number};
type Block={blockIndex:number;path:string;fields:string[];
 sourceStartByte:number;sourceEndByte:number;physicalLines:number;
 rowCount:number;claims:Claim[]};
type SourceCase={
 id:string;wire:string;valid:boolean;expected:Block[];
 sourceBytes:number;sourceSha256:string;eventCount:number;
};
const buf=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standardZeekRotationStream.pinned.json'));
const frozenHash='6415e09bafa6ecac25889c1a882d5b6c9f9017b47f77a246039d80b4f030e7ee';
if(createHash('sha256').update(buf).digest('hex')!==frozenHash)
 throw Error('Independently authored Zeek rotation source truth drift');
const {cases}=JSON.parse(buf.toString('utf8')) as {cases:SourceCase[]};
const decoder=new TextDecoder('utf8',{fatal:true});

describe('P0-STD-7 Zeek repeated fully closed metadata blocks source segmentation',()=>{
 it('pins independent source grammar fixtures and scoped denominators',()=>{
  expect(cases).toHaveLength(13);
  expect(cases.filter(x=>x.valid)).toHaveLength(5);
  expect(cases.filter(x=>!x.valid)).toHaveLength(8);
 });
 it.each(cases)('prevents rows being assigned to the wrong Zeek rotation schema: $id',c=>{
  const original=new TextEncoder().encode(c.wire);
  expect(original).toHaveLength(c.sourceBytes);
  expect(createHash('sha256').update(original).digest('hex')).toBe(c.sourceSha256);
  const observed=inspectStandardZeekRotationSource(c.wire);
  expect(observed.ok).toBe(c.valid);
  expect(observed.sourceBytes).toBe(c.sourceBytes);
  expect(observed.autoPromoted).toBe(false);
  expect(observed.nativeVerified).toBe(false);
  expect(observed.producerProfileQualified).toBe(false);
  if(!observed.ok){
    expect(observed.blocks).toEqual([]);
    expect(observed.reason.length).toBeGreaterThan(0);
    return;
  }
  expect(observed.blocks).toHaveLength(c.expected.length);
  expect(observed.eventCount).toBe(c.eventCount);
  expect(observed.blocks).toEqual(c.expected);
  for(const block of observed.blocks){
    const originalBlock=decoder.decode(original.subarray(
      block.sourceStartByte,block.sourceEndByte));
    const single=parseZeekTsvBlock(originalBlock);
    expect(single.ok).toBe(true);
    if(single.ok){
      expect(single.block.closed).toBe(true);
      expect(single.block.rows).toHaveLength(block.rowCount);
    }
    for(const claim of block.claims)
      expect(decoder.decode(original.subarray(claim.startByte,claim.endByte)))
        .toBe(claim.rawLexeme);
  }
 });
});
