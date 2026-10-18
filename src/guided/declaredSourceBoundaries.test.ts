import {describe,it,expect} from 'vitest';
import {boundaryLiteralError,inspectDeclaredSourceBoundaries,selectedBoundaryLiteral} from './declaredSourceBoundaries';
describe('Explicit user-declared prefix and suffix, source-only',()=>{
  it('removes only exact shared markers, never rewrites source, with correct UTF-8 byte offsets',()=>{
    const rows=[
      '전달:{"event_type":"threat","user":"김민수"}:끝',
      '전달:{"event_type":"user","user":"山田"}:끝',
    ];
    const source=rows.join('\n'),unchanged=source;
    const result=inspectDeclaredSourceBoundaries(source,{prefix:'전달:',postfix:':끝'});
    expect(result).toMatchObject({status:'EXACT_PREVIEW',code:'MATCHED_ALL',total:2,matched:2,
      exportable:false,nativeVerified:false,targetVerified:false});
    expect(result.records.map(row=>JSON.parse(row.payload) as unknown))
      .toEqual([{event_type:'threat',user:'김민수'},{event_type:'user',user:'山田'}]);
    expect(result.records[0]!.payloadStartByte).toBe(new TextEncoder().encode('전달:').length);
    expect(result.records[0]!.payloadEndByte).toBe(
      new TextEncoder().encode('전달:{"event_type":"threat","user":"김민수"}').length);
    expect(result.records[1]!.recordStartByte).toBe(
      new TextEncoder().encode(rows[0]+'\n').length);
    expect(source).toBe(unchanged);
  });
  it('fails closed for missing or varying markers; keeps every record and source',()=>{
    const value='FW:{"type":"threat"}:END\nFW:{"type":"user"}:FINISH';
    const result=inspectDeclaredSourceBoundaries(value,{prefix:'FW:',postfix:':END'});
    expect(result).toMatchObject({status:'REVIEW_ONLY',total:2,matched:1,exportable:false});
    expect(result.records[1]!.raw).toBe('FW:{"type":"user"}:FINISH');
    expect(result.records[1]!.payload).toBe('');
  });
  it('rejects invalid Unicode, unbounded, multi-line, empty payload, and over-500 events',()=>{
    expect(boundaryLiteralError('a'.repeat(257))).toMatch(/256/);
    expect(boundaryLiteralError('bad\nline')).toMatch(/line breaks/);
    expect(boundaryLiteralError('\ud800')).toMatch(/Unicode/);
    expect(inspectDeclaredSourceBoundaries('X',{
      prefix:'X',postfix:''}).status).toBe('REVIEW_ONLY');
    expect(inspectDeclaredSourceBoundaries('X',{
      prefix:'X',postfix:''}).code).toBe('INCONSISTENT_MARKERS');
    expect(inspectDeclaredSourceBoundaries('A\n'.repeat(501),{
      prefix:'A',postfix:''}).code).toBe('UNSAFE_SOURCE');
  });
  it('supports mouse-marked first event prefix/suffix and rejects mid-body marks',()=>{
    const source='FW:{"action":"deny"}:END\nFW:{"action":"allow"}:END';
    expect(selectedBoundaryLiteral(source,0,3,'prefix')).toEqual({value:'FW:',error:null});
    const firstEnd=source.indexOf('\n');
    expect(selectedBoundaryLiteral(source,firstEnd-4,firstEnd,'postfix'))
      .toEqual({value:':END',error:null});
    expect(selectedBoundaryLiteral(source,3,9,'prefix').value).toBeNull();
    expect(selectedBoundaryLiteral(source,0,3,'postfix').value).toBeNull();
  });
  it('direct inputs are preview-only even when only one event matches',()=>{
    const result=inspectDeclaredSourceBoundaries('FW:action=deny',{prefix:'FW:',postfix:''});
    expect(result).toMatchObject({status:'EXACT_PREVIEW',total:1,matched:1,exportable:false});
    expect(result.records[0]!.payload).toBe('action=deny');
  });
});
