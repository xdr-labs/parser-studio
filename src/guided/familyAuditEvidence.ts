import type {ParserDraft,SuiteResult} from '../model';
import {MAX_EVENTS} from '../parser';
import {createBrowserEvidence,type BrowserTestEvidence} from './browserEvidence';
import {planAllFamilyAudit,type AllFamilyAuditReport} from './familyAudit';
import {ISOLATABLE_FAMILIES,type IsolatableFamily} from './familyIsolation';

/**
 * User-initiated, SHA-256-bound, metadata-only evidence of local family
 * coverage. No raw/normalized events, sample values, field values, parser
 * snippets, diagnostic messages, credentials or tenant data are exported.
 * Never assert that independent browser family previews prove native routing.
 */
export interface AllFamilyAuditEvidence {
  reportSchema:'parser-studio.browser-family-audit-evidence.v0.1';
  engine:'browser-preview';
  status:'DRAFT_ONLY';
  privacy:{
    rawLogsIncluded:false; normalizedValuesIncluded:false;
    diagnosticMessagesIncluded:false;
  };
  compatibility:{
    nativeFluentdVerified:false; stellarTargetVerified:false;
    singleMixedFormatParserVerified:false;
  };
  source:BrowserTestEvidence['source'];
  overview:{sourceEvents:number;reviewedEvents:number;unreviewableEvents:number};
  families:Array<{
    format:IsolatableFamily;
    sourceEvents:number;matched:number;extracted:number;normalized:number;
    failures:number;warnings:number;originalLines:number[];
  }>;
  unreviewable:Array<{originalLine:number;format:string}>;
}
const DIAGNOSTICS=new Set([
  'DATASET_TOO_LARGE','EVENT_LIMIT','UNSUPPORTED_FORMAT','EXTRACTION_FAILED',
  'INVALID_MAPPING','TARGET_COLLISION','SOURCE_NOT_FOUND','TYPE_ERROR',
  'ENRICHMENT_TARGET','ENRICHMENT_SOURCE','ENRICHMENT_TYPE',
  'ENRICHMENT_UNSUPPORTED','UNMAPPED_FIELDS','NO_MAPPINGS',
  'DIAGNOSTIC_UNAVAILABLE',
]);
const FAMILY_KEYS='browserOnly,contract,counts,excludedCount,format,nativeFluentdVerified,perEvent,selectedCount,sourceCount,stellarExportVerified';
const REPORT_KEYS='browserOnly,contract,families,nativeFluentdVerified,notSingleParserProof,reviewedCount,sourceCount,stellarExportVerified,unreviewableCount,unreviewableEvents';

function exact(value:unknown,keys:string):boolean {
  return !!value&&typeof value==='object'&&!Array.isArray(value)&&
    Object.keys(value).sort().join(',')===keys;
}
function validCount(value:unknown,max:number):boolean {
  return typeof value==='number'&&Number.isInteger(value)&&value>=0&&value<=max;
}
function fail():never {
  throw new Error('The all-family audit does not match the current bounded source and cannot be safely exported.');
}

export async function createAllFamilyAuditEvidence(input:{
  sample:string; draft:ParserDraft; suite:SuiteResult;report:AllFamilyAuditReport;
}):Promise<AllFamilyAuditEvidence>{
  if(!input || !exact(input.report,REPORT_KEYS))fail();
  const {sample,draft,suite,report}=input;
  // Reconstruct only the in-memory source family allocation and validate
  // exact raw-source identity before hashing; no temporary raw data is saved.
  const plan=planAllFamilyAudit(sample,draft,suite);
  if(report.contract!=='parser-studio.browser-all-family-audit.v0.1' ||
     report.browserOnly!==true || report.nativeFluentdVerified!==false ||
     report.stellarExportVerified!==false || report.notSingleParserProof!==true ||
     report.sourceCount!==plan.sourceCount ||
     !validCount(report.reviewedCount,MAX_EVENTS) ||
     report.unreviewableCount!==plan.unreviewableEvents.length ||
     !Array.isArray(report.families) || report.families.length!==plan.plans.length ||
     !Array.isArray(report.unreviewableEvents) ||
     report.unreviewableEvents.length!==plan.unreviewableEvents.length)fail();
  for(let i=0;i<plan.unreviewableEvents.length;i++){
    const found=report.unreviewableEvents[i],original=plan.unreviewableEvents[i];
    if(!exact(found,'format,originalLine')||
       found.originalLine!==original.originalLine || found.format!==original.format)
      fail();
  }
  let reviewed=0;
  const families:AllFamilyAuditEvidence['families']=[];
  for(let i=0;i<plan.plans.length;i++){
    const expected=plan.plans[i],received=report.families[i];
    if(!expected || !received || !exact(received,FAMILY_KEYS) ||
       !ISOLATABLE_FAMILIES.includes(received.format) ||
       received.format!==expected.format ||
       received.contract!=='parser-studio.browser-family-isolation.v0.1' ||
       received.browserOnly!==true || received.nativeFluentdVerified!==false ||
       received.stellarExportVerified!==false ||
       received.selectedCount!==expected.selectedCount ||
       received.sourceCount!==expected.sourceCount ||
       received.excludedCount!==expected.sourceCount-expected.selectedCount ||
       !exact(received.counts,'extracted,failures,matched,normalized,total,warnings') ||
       received.counts.total!==expected.selectedCount ||
       !['extracted','matched','normalized','failures','warnings'].every(key=>
         validCount(received.counts[key as keyof typeof received.counts],expected.selectedCount)) ||
       !Array.isArray(received.perEvent) ||
       received.perEvent.length!==expected.selectedCount)fail();
    for(let j=0;j<expected.selectedCount;j++){
      const entry=received.perEvent[j];
      if(!entry || !exact(entry,'diagnosticCodes,originalLine,status') ||
         entry.originalLine!==expected.originalLines[j] ||
         !['pass','warning','fail'].includes(entry.status) ||
         !Array.isArray(entry.diagnosticCodes) || entry.diagnosticCodes.length>64 ||
         entry.diagnosticCodes.some(code=>!DIAGNOSTICS.has(code)))fail();
    }
    reviewed+=received.selectedCount;
    families.push({
      format:received.format,sourceEvents:received.selectedCount,
      matched:received.counts.matched,extracted:received.counts.extracted,
      normalized:received.counts.normalized,failures:received.counts.failures,
      warnings:received.counts.warnings,originalLines:[...expected.originalLines],
    });
  }
  if(reviewed!==report.reviewedCount ||
     reviewed+report.unreviewableCount!==plan.sourceCount)fail();
  const hashProof=await createBrowserEvidence({sample,draft,suite});
  if(hashProof.counts.total!==plan.sourceCount)fail();
  return {
    reportSchema:'parser-studio.browser-family-audit-evidence.v0.1',
    engine:'browser-preview',status:'DRAFT_ONLY',
    privacy:{rawLogsIncluded:false,normalizedValuesIncluded:false,diagnosticMessagesIncluded:false},
    compatibility:{
      nativeFluentdVerified:false,stellarTargetVerified:false,
      singleMixedFormatParserVerified:false,
    },
    source:hashProof.source,
    overview:{
      sourceEvents:plan.sourceCount,reviewedEvents:reviewed,
      unreviewableEvents:report.unreviewableCount,
    },
    families,
    unreviewable:plan.unreviewableEvents.map(event=>({...event})),
  };
}
