import type {EventResult,ParserDraft,SuiteResult} from '../model';
import {splitEvents} from '../parser';
import {
  ISOLATABLE_FAMILIES,planFamilyIsolation,summarizeIsolatedFamilyPreview,
  type FamilyIsolationPlan,type FamilyIsolationReport,
} from './familyIsolation';

/**
 * Independent, browser-local audit of every format family in an exact source
 * sample. No mixed-format parser is generated and no customer event data is
 * persisted, uploaded or included in the user-visible report. All unsupported
 * and unknown records are counted explicitly; no sample can silently vanish.
 */
export interface AllFamilyAuditPlan {
  sourceCount:number;
  /** Ephemeral raw bytes, used solely for bounded local Web Worker tests. */
  plans:FamilyIsolationPlan[];
  unreviewableEvents:Array<{
    originalLine:number;
    format:EventResult['detected']['format'];
  }>;
}
export interface AllFamilyAuditReport {
  contract:'parser-studio.browser-all-family-audit.v0.1';
  sourceCount:number;
  reviewedCount:number;
  unreviewableCount:number;
  families:FamilyIsolationReport[];
  unreviewableEvents:Array<{
    originalLine:number;
    format:EventResult['detected']['format'];
  }>;
  browserOnly:true;
  nativeFluentdVerified:false;
  stellarExportVerified:false;
  notSingleParserProof:true;
}

function reject(detail:string):never {
  throw new Error('Cannot run a complete browser family audit: '+detail);
}

export function planAllFamilyAudit(
  source:string,draft:ParserDraft,suite:SuiteResult,
):AllFamilyAuditPlan {
  // planFamilyIsolation checks the exact sample/suite identity, physical
  // boundaries, 500-event/64-KiB limits and negative native verification flags.
  if(!suite || !Array.isArray(suite.events))reject('missing source preview.');
  const supported=ISOLATABLE_FAMILIES.filter(format=>
    suite.events.some(event=>event.detected.format===format));
  if(!supported.length)reject('no supported format families in this source.');
  const plans=supported.map(format=>planFamilyIsolation(source,draft,suite,format));
  const unreviewableEvents=suite.events.filter(event=>
    !ISOLATABLE_FAMILIES.some(format=>format===event.detected.format))
    .map(event=>({originalLine:event.line,format:event.detected.format}));
  const sourceCount=suite.events.length;
  if(plans.reduce((sum,item)=>sum+item.selectedCount,0)+
      unreviewableEvents.length!==sourceCount ||
    unreviewableEvents.some(entry=>!Number.isInteger(entry.originalLine)||entry.originalLine<1)){
    reject('one or more original events are not accounted for.');
  }
  return {sourceCount,plans,unreviewableEvents};
}

export function summarizeAllFamilyAudit(
  plan:AllFamilyAuditPlan,runs:readonly SuiteResult[],
):AllFamilyAuditReport {
  if(!plan || !Array.isArray(plan.plans)||!Array.isArray(runs)||
     plan.plans.length===0 || runs.length!==plan.plans.length ||
     !Array.isArray(plan.unreviewableEvents) ||
     !Number.isInteger(plan.sourceCount)||plan.sourceCount<1||plan.sourceCount>500) {
    reject('missing or mismatched review results.');
  }
  const families=plan.plans.map((p,index)=>{
    const run=runs[index];
    const source=splitEvents(p.sample,'single-line',501);
    // Never accept Web Worker data for another family or edited source. The
    // returned public report contains only selected/excluded counts and codes.
    if(!run || run.events.length!==source.length ||
       run.events.some((event:EventResult,i:number)=>
         event.raw!==source[i]?.raw ||
         event.line!==source[i]?.line ||
         event.effectiveFormat!==p.format)) {
      reject('a worker result does not match its exact selected source.');
    }
    return summarizeIsolatedFamilyPreview(p,run);
  });
  const reviewedCount=families.reduce((sum,r)=>sum+r.selectedCount,0);
  const accounted=[
    ...families.flatMap(f=>f.perEvent.map(event=>event.originalLine)),
    ...plan.unreviewableEvents.map(event=>event.originalLine),
  ];
  if(reviewedCount+plan.unreviewableEvents.length!==plan.sourceCount ||
     accounted.length!==plan.sourceCount ||
     new Set(accounted).size!==plan.sourceCount ||
     accounted.some(line=>!Number.isInteger(line)||line<1)) {
    reject('coverage is incomplete or double counted.');
  }
  return {
    contract:'parser-studio.browser-all-family-audit.v0.1',
    sourceCount:plan.sourceCount,reviewedCount,unreviewableCount:plan.unreviewableEvents.length,
    families,
    unreviewableEvents:plan.unreviewableEvents.map(event=>({...event})),
    browserOnly:true,
    nativeFluentdVerified:false,
    stellarExportVerified:false,
    notSingleParserProof:true,
  };
}
