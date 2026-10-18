import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {parseRfc4180HeaderCsv} from '../rfc4180Csv';

type Claim={
 rowIndex:number;columnIndex:number;columnName:string;
 rawLexeme:string;decodedValue:string;quoted:boolean;
 startByte:number;endByte:number;
};
type RecordClaim={
 rowIndex:number;startByte:number;endByte:number;
 terminatorBytes:number;physicalLines:number;
};
type Case={
 id:string;wire:string;valid:boolean;header:string[];
 dataRows:number;lineEnding?:'lf'|'crlf';
 originalClaims:Claim[];records:RecordClaim[];
 sourceBytes:number;sourceSha256:string;
};
const raw=fs.readFileSync(path.join(__dirname,
 '../../scripts/poc/standardCsvMultilineOriginalSpans.pinned.json'));
const pinnedSha='25c3f27ff07e13e37bf7ff78ad8fe05bac15143a496db61e5a7e9a95fe4eebff';
const sha=(value:Uint8Array)=>createHash('sha256').update(value).digest('hex');
if(sha(raw)!==pinnedSha)
 throw Error('Independent RFC4180 multiline CSV source/field oracle SHA changed');
const {cases}=JSON.parse(raw.toString('utf8')) as {cases:Case[]};
const decoder=new TextDecoder('utf8',{fatal:true});

describe('P0-STD RFC4180 multiline CSV original field and record byte intervals',()=>{
  it('pins independent synthetic denominators before any source implementation',()=>{
    expect(cases).toHaveLength(22);
    expect(cases.filter(x=>x.valid)).toHaveLength(11);
    expect(cases.filter(x=>!x.valid)).toHaveLength(11);
    expect(cases.flatMap(x=>x.originalClaims)).toHaveLength(100);
  });
  it.each(cases)('replays exact original multiline cell and row source: $id',c=>{
    const input=new TextEncoder().encode(c.wire);
    expect(input).toHaveLength(c.sourceBytes);
    expect(sha(input)).toBe(c.sourceSha256);
    const parsed=parseRfc4180HeaderCsv(c.wire);
    expect(parsed.ok).toBe(c.valid);
    if(!parsed.ok){
      expect(parsed.error.length).toBeGreaterThan(0);
      return;
    }
    expect(parsed.table.header).toEqual(c.header);
    expect(parsed.table.rows).toHaveLength(c.dataRows);
    expect(parsed.table.lineEnding).toBe(c.lineEnding);
    expect(parsed.table.sourceBytes).toBe(c.sourceBytes);
    const flattened=[
      ...parsed.table.headerFieldSpans,
      ...parsed.table.rowFieldSpans.flat(),
    ];
    expect(flattened).toHaveLength(c.originalClaims.length);
    for(const [index,field] of c.originalClaims.entries()){
      const actual=flattened[index]!;
      expect(actual).toEqual(field);
      expect(decoder.decode(input.subarray(actual.startByte,actual.endByte)))
        .toBe(field.rawLexeme);
      if(field.rowIndex===-1){
        expect(parsed.table.header[field.columnIndex]).toBe(field.decodedValue);
      }else {
        expect(parsed.table.rows[field.rowIndex]?.[field.columnName])
          .toBe(field.decodedValue);
      }
    }
    expect(parsed.table.recordSourceSpans).toEqual(c.records);
    for(const record of parsed.table.recordSourceSpans){
      const slice=decoder.decode(input.subarray(
        record.startByte,record.endByte));
      expect(slice.length).toBeGreaterThan(0);
      const terminator=input.subarray(
        record.endByte,record.endByte+record.terminatorBytes);
      if(record.terminatorBytes)
        expect(decoder.decode(terminator)).toBe(
          c.lineEnding==='crlf'?'\r\n':'\n');
      else expect(terminator.length).toBe(0);
    }
    expect(parsed.table.recordSourceSpans.at(-1)!.endByte+
      parsed.table.recordSourceSpans.at(-1)!.terminatorBytes)
      .toBe(c.sourceBytes);
  });
});
