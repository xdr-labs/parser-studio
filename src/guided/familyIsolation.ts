import type {ConcreteFormat, EventStatus, ParserDraft, SuiteResult} from '../model';
import {MAX_DATASET_BYTES, MAX_EVENTS, splitEvents} from '../parser';

/**
 * Explicit browser-only isolation of independently detected format families.
 *
 * Caller retains the original draft and complete source data unchanged.
 * The temporary fixture holds source events only in memory for one Web Worker
 * preview. Never put this plan, its raw sample, or event values in a saved
 * revision, downloaded evidence, telemetry, or a backend request.
 *
 * The returned report is a separately safe, value-free projection; it does
 * not assert Fluentd or Stellar Cyber compatibility.
 */
export const ISOLATABLE_FAMILIES = [
  'json','kv','csv','syslog_rfc3164','syslog_rfc5424','cef','leef',
] as const satisfies readonly ConcreteFormat[];

export type IsolatableFamily=(typeof ISOLATABLE_FAMILIES)[number];

// Diagnostic codes originate in the browser parser, but a malformed worker
// must never turn a customer identifier into a report-visible 'code'.
const SAFE_DIAGNOSTIC_CODES=new Set([
  'DATASET_TOO_LARGE','EVENT_LIMIT','UNSUPPORTED_FORMAT','EXTRACTION_FAILED',
  'INVALID_MAPPING','TARGET_COLLISION','SOURCE_NOT_FOUND','TYPE_ERROR',
  'ENRICHMENT_TARGET','ENRICHMENT_SOURCE','ENRICHMENT_TYPE',
  'ENRICHMENT_UNSUPPORTED','UNMAPPED_FIELDS','NO_MAPPINGS',
  'DIAGNOSTIC_UNAVAILABLE',
]);

export interface FamilyIsolationPlan {
  format: IsolatableFamily;
  /** Ephemeral original event bytes, passed exclusively to local Web Worker. */
  sample: string;
  originalLines: number[];
  selectedCount: number;
  sourceCount: number;
}

export interface FamilyIsolationReport {
  contract: 'parser-studio.browser-family-isolation.v0.1';
  format: IsolatableFamily;
  sourceCount: number;
  selectedCount: number;
  excludedCount: number;
  counts: SuiteResult['counts'];
  perEvent: Array<{
    originalLine: number;
    status: EventStatus;
    diagnosticCodes: string[];
  }>;
  browserOnly: true;
  nativeFluentdVerified: false;
  stellarExportVerified: false;
}

function reject(message:string):never {
  throw new Error('Cannot isolate this family: '+message);
}

export function planFamilyIsolation(
  source: string,
  draft: ParserDraft,
  suite: SuiteResult,
  family: ConcreteFormat|'unknown'|'auto',
): FamilyIsolationPlan {
  if (!ISOLATABLE_FAMILIES.some(format=>format===family)) {
    reject('unsupported or unknown extraction family. Use a separate reviewed parser.');
  }
  if ((draft.guided?.eventBoundary??'single-line')!=='single-line') {
    reject('single-line source records are required; multiline grouping is browser preview only.');
  }
  if (new TextEncoder().encode(source).byteLength>MAX_DATASET_BYTES) {
    reject('input exceeds the 64 KiB browser test limit.');
  }
  const records=splitEvents(source,'single-line',MAX_EVENTS+1);
  if (!suite || suite.engine!=='browser-preview' ||
      suite.nativeFluentdVerified!==false || suite.stellarExportVerified!==false ||
      records.length===0 || records.length>MAX_EVENTS ||
      records.length!==suite.events.length ||
      records.length!==suite.counts.total ||
      records.some((record,index)=>
        record.raw!==suite.events[index]?.raw ||
        record.line!==suite.events[index]?.line)) {
    reject('stale, truncated, or incompatible browser suite; rerun the original sample first.');
  }
  const indices: number[]=[];
  const isolated: string[]=[];
  suite.events.forEach(event=>{
    if (event.detected.format===family) {
      indices.push(event.line);
      isolated.push(event.raw);
    }
  });
  if (!isolated.length)reject('no matching events for this family.');
  return {
    format: family as IsolatableFamily,
    sample: isolated.join('\n'),
    originalLines:indices,
    selectedCount:isolated.length,
    sourceCount:records.length,
  };
}

export function summarizeIsolatedFamilyPreview(
  plan: FamilyIsolationPlan,
  result: SuiteResult,
):FamilyIsolationReport {
  if(!result ||result.engine!=='browser-preview' ||
     result.nativeFluentdVerified!==false ||
     result.stellarExportVerified!==false) {
    throw new Error('Isolated preview verification flags are untrusted.');
  }
  const counts=result.counts;
  if(!counts || result.events.length!==plan.selectedCount ||
    counts.total!==plan.selectedCount ||
    ![counts.total,counts.matched,counts.extracted,counts.normalized,
      counts.failures,counts.warnings].every(value=>
        Number.isInteger(value) && value>=0 && value<=plan.selectedCount)) {
    throw new Error('Isolated preview event totals conflict with the selected family.');
  }
  const perEvent:FamilyIsolationReport['perEvent']=result.events.map((event,i)=>{
    if(!event || !['pass','warning','fail'].includes(event.status) ||
      !Number.isInteger(plan.originalLines[i]) ||
      !Array.isArray(event.diagnostics)) {
      throw new Error('Isolated preview event diagnostics are invalid.');
    }
    return {
      originalLine:plan.originalLines[i]!,
      status:event.status,
      diagnosticCodes:event.diagnostics.map(diag=>
        SAFE_DIAGNOSTIC_CODES.has(diag.code)?diag.code:'DIAGNOSTIC_UNAVAILABLE',
      ),
    };
  });
  return {
    contract:'parser-studio.browser-family-isolation.v0.1',
    format:plan.format,
    sourceCount:plan.sourceCount,
    selectedCount:plan.selectedCount,
    excludedCount:plan.sourceCount-plan.selectedCount,
    counts:{
      total:counts.total,
      matched:counts.matched,
      extracted:counts.extracted,
      normalized:counts.normalized,
      failures:counts.failures,
      warnings:counts.warnings,
    },
    perEvent,browserOnly:true,
    nativeFluentdVerified:false,stellarExportVerified:false,
  };
}
