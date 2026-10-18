import type { EventResult, Format } from '../model';

export interface FamilyCount {
  format: EventResult['detected']['format'];
  count: number;
}
export interface FamilyCoverage {
  total:number;
  groups:FamilyCount[];
  detectedFamilyCount:number;
  unexpected:number;
  unknown:number;
  incompatible:boolean;
  firstUnexpectedEventId:string|null;
}

/**
 * Browser-only heuristic family distribution. Returns format identifiers
 * and counts, not raw sample values. Does not claim that a single backend
 * parser may author heterogeneous family routing.
 */
export function summarizeFamilyCoverage(
  events: readonly EventResult[], selected: Format,
): FamilyCoverage {
  const groups=new Map<EventResult['detected']['format'],number>();
  let unexpected=0;
  let unknown=0;
  let firstUnexpectedEventId:string|null=null;
  for(const event of events) {
    const detected=event.detected.format;
    groups.set(detected,(groups.get(detected)??0)+1);
    if (detected==='unknown') unknown++;
    else if (selected!=='auto' && detected!==selected) {
      unexpected++;
      if(firstUnexpectedEventId===null)firstUnexpectedEventId=event.id;
    }
  }
  const detectedFamilyCount=[...groups.keys()].filter(format=>format!=='unknown').length;
  return {
    total:events.length,
    groups:[...groups.entries()].map(([format,count])=>({format,count}))
      .sort((a,b)=>b.count-a.count),
    detectedFamilyCount,unexpected,unknown,
    incompatible:events.length>0 &&
      (selected==='auto' || detectedFamilyCount>1 || unexpected>0 || unknown>0),
    firstUnexpectedEventId,
  };
}
