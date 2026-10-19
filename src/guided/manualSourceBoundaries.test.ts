import {describe,it,expect} from 'vitest';
import {inspectManualBoundaries,selectedBoundary} from './manualSourceBoundaries';

describe('Explicit literal prefix and postfix review',()=>{
  it('retains original UTF-8 source and reports exact byte spans per log',()=>{
    const source=[
      'RELAY: {"message":"로그인 실패","src":"192.0.2.1"} END',
      'RELAY: {"message":"認証に失敗","src":"192.0.2.2"} END',
      'RELAY: {"message":"用户认证失败","src":"192.0.2.3"} END',
    ].join('\n');
    const original=source;
    const marks={prefix:'RELAY: ',postfix:' END'};
    const review=inspectManualBoundaries(source,marks);
    expect(review.status).toBe('REVIEW_READY');
    expect(review.count).toBe(3);
    expect(source).toBe(original);
    const entire=new TextEncoder().encode(source);
    for(const record of review.records){
      const actual=new TextDecoder('utf-8',{fatal:true}).decode(
        entire.slice(record.payloadStartByte,record.payloadEndByte));
      expect(actual).toBe(record.payload);
      expect(record.payload.startsWith('{')).toBe(true);
      expect(record.originalEndByte).toBeGreaterThan(record.payloadEndByte);
    }
    expect(review.records[2]!.originalStartByte).toBeGreaterThan(
      source.split('\n').slice(0,2).join('\n').length);
    expect(review.compilerVerified).toBe(false);
    expect(review.originalSourcePreserved).toBe(true);
  });
  it('refuses inconsistent wrappers, missing bodies, or ambiguous data',()=>{
    expect(inspectManualBoundaries('X: aa\nY: bb',{prefix:'X: ',postfix:''}).status)
      .toBe('ABSTAIN_UNSAFE');
    expect(inspectManualBoundaries('BEGINEND',{prefix:'BEGIN',postfix:'END'}).status)
      .toBe('ABSTAIN_UNSAFE');
    expect(inspectManualBoundaries('X: aa',{prefix:'X: ',postfix:' aa'}).status)
      .toBe('ABSTAIN_UNSAFE');
    expect(inspectManualBoundaries('X: aa\r\nX: bb',{prefix:'X: ',postfix:''}).status)
      .toBe('ABSTAIN_UNSAFE');
    expect(inspectManualBoundaries('X: aa',{prefix:'',postfix:''}).status)
      .toBe('NO_MARKS');
  });
  it('accepts user-marked exact boundaries only from first event',()=>{
    const source='PRE: {"event":"threat"}!DONE\nPRE: {"event":"user"}!DONE';
    expect(selectedBoundary(source,0,5,'prefix'))
      .toEqual({ok:true,literal:'PRE: '});
    const end=source.indexOf('\n');
    expect(selectedBoundary(source,end-5,end,'postfix'))
      .toEqual({ok:true,literal:'!DONE'});
    expect(selectedBoundary(source,1,5,'prefix').ok).toBe(false);
    expect(selectedBoundary(source,0,end+1,'prefix').ok).toBe(false);
    expect(selectedBoundary(source,end-5,end-1,'postfix').ok).toBe(false);
    expect(selectedBoundary(source,0,0,'prefix').ok).toBe(false);
  });
});
