import type { BrowserTestEvidence } from './browserEvidence';

export interface BrowserEvidenceComparison {
  sameSample: true;
  sameDraft: boolean;
  baselineEvents: number;
  currentEvents: number;
  improved: number;
  regressed: number;
  unchanged: number;
  changedDiagnostics: number;
  changed: Array<{
    event: number;
    line: number;
    change: 'improved' | 'regressed';
    fromNormalized: boolean;
    toNormalized: boolean;
  }>;
}

const HEX = /^[0-9a-f]{64}$/;
const STAGES = new Set(['break','detect','extract','normalize','enrichment','validate']);
const STATUSES = new Set(['pass','warning','fail']);
const SEVERITIES = new Set(['error','warning']);
const FORMATS = new Set(['auto','json','kv','csv','syslog_rfc5424','cef','leef','syslog','regex','unknown']);
const DIAGNOSTIC_CODES = new Set([
  'DATASET_TOO_LARGE','EVENT_LIMIT','UNSUPPORTED_FORMAT','EXTRACTION_FAILED',
  'INVALID_MAPPING','TARGET_COLLISION','SOURCE_NOT_FOUND','TYPE_ERROR',
  'ENRICHMENT_TARGET','ENRICHMENT_SOURCE','ENRICHMENT_TYPE',
  'ENRICHMENT_UNSUPPORTED','PROTOCOL_CONFLICT','UNMAPPED_FIELDS','NO_MAPPINGS','UNSPECIFIED',
]);
const TOTAL_COUNTS = ['total','matched','extracted','normalized','failures','warnings'];
const EVENT_KEYS = ['number','line','status','detectedFormat','effectiveFormat','matched','extracted','normalized','diagnostics'];

function record(value:unknown):value is Record<string,unknown> {
  return typeof value==='object' && value!==null && !Array.isArray(value);
}
function exact(value:unknown, allowed: readonly string[]):value is Record<string,unknown> {
  return record(value) && Object.keys(value).length===allowed.length &&
    Object.keys(value).every(key=>allowed.includes(key));
}
function reasonableInteger(value:unknown,min:number,max:number):boolean {
  return typeof value==='number' && Number.isInteger(value) && value>=min && value<=max;
}

/** Parse distrustful JSON metadata, never display or retain source-provided prose.
 * Reject extra keys, unknown codes and runtime success claims. */
function assertSafeEvidence(value:unknown): asserts value is BrowserTestEvidence {
  const error=()=>new Error('Incompatible or untrusted browser evidence report');
  if(!exact(value,['reportSchema','engine','artifactStatus','compatibility','privacy','source','counts','events']) ||
     value.reportSchema!=='parser-studio.browser-test-evidence.v0.1' ||
     value.engine!=='browser-preview' || value.artifactStatus!=='DRAFT_ONLY') throw error();
  const flags=value.compatibility,privacy=value.privacy,source=value.source,counts=value.counts,events=value.events;
  if(!exact(flags,['nativeFluentdVerified','stellarTargetVerified']) ||
     flags.nativeFluentdVerified!==false || flags.stellarTargetVerified!==false ||
     !exact(privacy,['rawLogsIncluded','normalizedValuesIncluded','diagnosticMessagesIncluded']) ||
     Object.values(privacy).some(v=>v!==false) ||
     !exact(source,['sampleSha256','draftSha256','sampleBytes']) ||
     typeof source.sampleSha256!=='string' || !HEX.test(source.sampleSha256) ||
     typeof source.draftSha256!=='string' || !HEX.test(source.draftSha256) ||
     !reasonableInteger(source.sampleBytes,1,65536) ||
     !exact(counts,TOTAL_COUNTS) ||
     !reasonableInteger(counts.total,1,500) ||
     !TOTAL_COUNTS.every(k=>reasonableInteger(counts[k],0,500)) ||
     !Array.isArray(events) || events.length!==counts.total) throw error();
  for(let i=0;i<events.length;i++) {
    const event=events[i];
    if(!exact(event,EVENT_KEYS) ||
       event.number!==i+1 || !reasonableInteger(event.line,1,1000000) ||
       !STATUSES.has(String(event.status)) ||
       !FORMATS.has(String(event.detectedFormat)) ||
       !FORMATS.has(String(event.effectiveFormat)) ||
       typeof event.matched!=='boolean' || typeof event.extracted!=='boolean' ||
       typeof event.normalized!=='boolean' ||
       !Array.isArray(event.diagnostics) || event.diagnostics.length>64) throw error();
    for(const diagnostic of event.diagnostics) {
      if(!exact(diagnostic,['stage','severity','code']) ||
         !STAGES.has(String(diagnostic.stage)) ||
         !SEVERITIES.has(String(diagnostic.severity)) ||
         !DIAGNOSTIC_CODES.has(String(diagnostic.code))) throw error();
    }
  }
}

/** Compare status of the same exact hashed sample, treating a changed event
 * breaker/line sequence as incompatible rather than inventing regressions. */
export function compareBrowserEvidence(
  baseline:unknown,
  current:BrowserTestEvidence,
):BrowserEvidenceComparison {
  assertSafeEvidence(baseline);
  assertSafeEvidence(current);
  if(baseline.source.sampleSha256!==current.source.sampleSha256 ||
     baseline.source.sampleBytes!==current.source.sampleBytes) {
    throw new Error('Cannot compare a different sample SHA-256: re-run with the identical fixture');
  }
  if(baseline.events.length!==current.events.length ||
     baseline.events.some((event,i)=>event.line!==current.events[i].line)) {
    throw new Error('Cannot compare changed event segmentation for the same fixture');
  }
  let improved=0,regressed=0,unchanged=0,changedDiagnostics=0;
  const changed:BrowserEvidenceComparison['changed']=[];
  baseline.events.forEach((old,i)=>{
    const next=current.events[i];
    if(JSON.stringify(old.diagnostics)!==JSON.stringify(next.diagnostics))changedDiagnostics++;
    if(old.normalized===next.normalized){unchanged++;return;}
    if(next.normalized) improved++; else regressed++;
    changed.push({
      event:i+1,line:next.line,
      change:next.normalized?'improved':'regressed',
      fromNormalized:old.normalized,toNormalized:next.normalized,
    });
  });
  return {
    sameSample:true,
    sameDraft:baseline.source.draftSha256===current.source.draftSha256,
    baselineEvents:baseline.events.length,currentEvents:current.events.length,
    improved,regressed,unchanged,changedDiagnostics,changed,
  };
}
