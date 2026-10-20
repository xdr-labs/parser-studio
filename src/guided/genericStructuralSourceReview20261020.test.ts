import {describe,expect,it} from 'vitest';
import fixture from '../../tests/fixtures/mixed-generic-profiles-20261020.json';
import {createDraft} from '../model';
import {buildAutomaticGenericStructuralDraft,buildSourceReviewedGenericStructuralDraft,
  type GenericStructuralSourceReview} from './genericStructuralAutoDraft';

const bytes=(value:string)=>new TextEncoder().encode(value).length;
function witness(records:string[],separator='\n'):GenericStructuralSourceReview{
  let cursor=0;
  return {raw:records.join(separator),events:records.map(raw=>{
    const startByte=cursor;
    cursor+=bytes(raw)+bytes(separator);
    return {startByte,endByte:startByte+bytes(raw),
      preview:{status:raw===fixture.syslog?'PARTIAL' as const:'SOURCE_PARSED' as const,issues:[]}};
  })};
}

describe('automatic compiler adoption against the reviewed original source',()=>{
  for(const [order,records] of [
    ['Syslog first',[fixture.syslog,fixture.leef]],
    ['LEEF first',[fixture.leef,fixture.syslog]],
  ] as const){
    for(const separator of ['\n','\r\n']){
      it('resolves only the strict additional grammar while keeping UTF-8 records: '+order+
        (separator==='\n'?' LF':' CRLF'),()=>{
        const review=witness([...records],separator);
        const before=JSON.stringify(review);
        const result=buildSourceReviewedGenericStructuralDraft(review.raw,createDraft(),review);
        expect(result?.draft.genericStructuralProfile).toBe(fixture.profile);
        expect(result?.suite.events.map(event=>event.raw)).toEqual(records);
        expect(result?.suite.counts).toMatchObject({total:2,extracted:2,normalized:2,failures:0});
        expect(JSON.stringify(review)).toBe(before);
      });
    }
  }

  for(const status of ['RAW_ONLY','STRUCTURED_EMPTY'] as const){
    it('keeps '+status+' source diagnostics in review',()=>{
      const review=witness([fixture.syslog,fixture.leef]);
      review.events[0]!.preview.status=status;
      expect(buildSourceReviewedGenericStructuralDraft(review.raw,createDraft(),review)).toBeNull();
    });
  }

  const legacy='<134>date=2023-02-23 time=22:49:29 type=event subtype=system status=success';
  for(const mixed of [false,true]){
    it('retains partial legacy-route review'+(mixed?' inside a combined profile':''),()=>{
      const review=witness(mixed?[fixture.syslog,fixture.leef,legacy]:[legacy]);
      review.events.at(-1)!.preview.status='PARTIAL';
      expect(buildAutomaticGenericStructuralDraft(review.raw,createDraft())).not.toBeNull();
      expect(buildSourceReviewedGenericStructuralDraft(review.raw,createDraft(),review)).toBeNull();
    });
  }

  it('preserves the existing complete legacy-source adoption',()=>{
    const review=witness([legacy]);
    expect(buildSourceReviewedGenericStructuralDraft(review.raw,createDraft(),review))
      .toEqual(buildAutomaticGenericStructuralDraft(review.raw,createDraft()));
  });

  it('rejects stale source, dropped or reordered events and invalid UTF-8 ranges',()=>{
    const original=witness([fixture.syslog,fixture.leef]);
    const variants:GenericStructuralSourceReview[]=[
      {...original,raw:original.raw+' '},
      {...original,events:original.events.slice(0,1)},
      {...original,events:[...original.events].reverse()},
      {...original,events:[original.events[0]!,original.events[0]!]},
      {...original,events:original.events.map((event,index)=>index===1?
        {...event,startByte:event.startByte-1}:event)},
      {...original,events:original.events.map((event,index)=>index===0?
        {...event,endByte:bytes(fixture.syslog.slice(0,fixture.syslog.indexOf('user=')))+7}:event)},
    ];
    for(const review of variants)
      expect(buildSourceReviewedGenericStructuralDraft(original.raw,createDraft(),review)).toBeNull();
  });

  it('keeps transport and schema review authoritative despite a compilable field tree',()=>{
    const original=witness([fixture.syslog,fixture.leef]);
    const framed=structuredClone(original);
    framed.events[0]!.preview.issues=['FRAMING_ORIGINAL_CONTAINER_NOT_IN_DRAFT_COMPILER'];
    const schema=structuredClone(original);
    schema.events[0]!.preview.issues=['SCHEMA_CONTEXT_NOT_IN_DRAFT_COMPILER'];
    for(const review of [framed,schema,{...original,metadataLines:1},
      {...original,transportFramingParts:1}]){
      expect(buildAutomaticGenericStructuralDraft(review.raw,createDraft())).not.toBeNull();
      expect(buildSourceReviewedGenericStructuralDraft(review.raw,createDraft(),review)).toBeNull();
    }
  });
});
