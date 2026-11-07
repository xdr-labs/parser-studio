import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {suggestNormalizationCandidatesFromSuite} from './normalizationCandidates';

/** Deterministic generated permutations, paired with independently authored
 * expected official destinations. The implementation never supplies its own
 * expected output, and the test corpus contains no customer log data. */
function seeded(seed:number){
  let state=seed>>>0;
  return ()=>{
    state^=state<<13;state^=state>>>17;state^=state<<5;
    return state>>>0;
  };
}
function suite(records:Record<string,unknown>[]):SuiteResult{
  return {events:records.map(fields=>({fields}))} as unknown as SuiteResult;
}
function candidates(records:Record<string,unknown>[]){
  const result=suggestNormalizationCandidatesFromSuite(suite(records),[]);
  return result.map(c=>({source:c.source,target:c.target,type:c.type,
    confidence:c.confidence,safeForBulk:c.safeForBulk,
    observed:c.observed,compatibleObserved:c.compatibleObserved,total:c.total,
  })).sort((a,b)=>a.source.localeCompare(b.source));
}

const expectedTargets=['dstip','dstport','proto','srcip','srcport'];
const official={
  srcip:'192.0.2.17',dstip:'198.51.100.20',
  srcport:51432,dstport:443,proto:6,
};

describe('H3 independently expected multi-event mapping invariants',()=>{
  it('preserves exactly five reviewed official candidates across 100 seeded 2–10-event reorderings',()=>{
    for(let seed=1;seed<=100;seed++){
      const next=seeded(seed);
      const count=2+(next()%9);
      const eligibleIndex=next()%count;
      const records:Record<string,unknown>[]=[];
      for(let event=0;event<count;event++){
        const fields:Record<string,unknown>={};
        const neutralFields=20+(next()%64);
        for(let offset=0;offset<neutralFields;offset++){
          const key='vendor_'+seed+'_'+event+'_'+String(offset).padStart(3,'0');
          fields[key]=offset%4===0?'보안 이벤트 🌐':offset%4===1?'café':
            offset%4===2?'данные':offset;
        }
        if(event===eligibleIndex)Object.assign(fields,official);
        records.push(fields);
      }
      const rawSnapshot=JSON.stringify(records);
      const forward=candidates(records);
      const reverse=candidates([...records].reverse());
      const offset=next()%count;
      const rotate=candidates([...records.slice(offset),...records.slice(0,offset)]);
      const shuffle=[...records];
      for(let i=shuffle.length-1;i>0;i--){
        const j=next()%(i+1);
        [shuffle[i],shuffle[j]]=[shuffle[j]!,shuffle[i]!];
      }
      const reordered=candidates(shuffle);
      expect(forward,'seed '+seed+' forward').toEqual(reverse);
      expect(forward,'seed '+seed+' rotate').toEqual(rotate);
      expect(forward,'seed '+seed+' shuffle').toEqual(reordered);
      expect(forward.map(x=>x.target).sort(),'seed '+seed+' targets').toEqual(expectedTargets);
      expect(forward.every(x=>x.confidence==='REVIEW'&&!x.safeForBulk),'seed '+seed+' review').toBe(true);
      expect(JSON.stringify(records),'seed '+seed+' raw values').toBe(rawSnapshot);
    }
  });

  it('marks two independent source aliases competing for srcip as ambiguous regardless of order',()=>{
    const baseline=[
      {vendor_status:'keep 원본'},
      {srcip:'192.0.2.22',src_ip:'198.51.100.33'},
    ];
    for(const records of [baseline,[...baseline].reverse()]){
      const results=candidates(records).filter(x=>x.target==='srcip');
      expect(results.map(x=>x.source).sort()).toEqual(['src_ip','srcip']);
      expect(results.every(x=>x.confidence==='REVIEW'&&!x.safeForBulk)).toBe(true);
    }
  });
});
