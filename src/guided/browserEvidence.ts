import type { Diagnostic, EventResult, ParserDraft, SuiteResult } from '../model';
import { MAX_DATASET_BYTES, MAX_EVENTS } from '../parser';

/** Offline, explicit-only evidence for the local browser preview.
 * Deliberately excludes raw log bodies, normalized values and diagnostic
 * messages because those may contain customer identities, URLs or IPs.
 */
const KNOWN_DIAGNOSTICS = new Set([
  'DATASET_TOO_LARGE','EVENT_LIMIT','UNSUPPORTED_FORMAT','EXTRACTION_FAILED',
  'INVALID_MAPPING','TARGET_COLLISION','SOURCE_NOT_FOUND','TYPE_ERROR',
  'ENRICHMENT_TARGET','ENRICHMENT_SOURCE','ENRICHMENT_TYPE',
  'ENRICHMENT_UNSUPPORTED','UNMAPPED_FIELDS','NO_MAPPINGS',
]);
const STAGES = new Set<Diagnostic['stage']>(['break','detect','extract','normalize','validate']);
const LEVELS = new Set<Diagnostic['severity']>(['error','warning']);
const STATUSES = new Set<EventResult['status']>(['pass','fail','warning']);
const FORMATS = new Set(['auto','json','kv','csv','syslog_rfc3164','syslog_rfc5424','cef','leef','syslog','regex','unknown']);
const MAX_DRAFT_BYTES = 262144;

export interface BrowserTestEvidence {
  reportSchema: 'parser-studio.browser-test-evidence.v0.1';
  engine: 'browser-preview';
  artifactStatus: 'DRAFT_ONLY';
  compatibility: {
    nativeFluentdVerified: false;
    stellarTargetVerified: false;
  };
  privacy: {
    rawLogsIncluded: false;
    normalizedValuesIncluded: false;
    diagnosticMessagesIncluded: false;
  };
  source: {
    sampleSha256: string;
    draftSha256: string;
    sampleBytes: number;
  };
  counts: SuiteResult['counts'];
  events: Array<{
    number: number;
    line: number;
    status: EventResult['status'];
    detectedFormat: string;
    effectiveFormat: string;
    matched: boolean;
    extracted: boolean;
    normalized: boolean;
    diagnostics: Array<{
      stage: Diagnostic['stage'];
      severity: Diagnostic['severity'];
      code: string;
    }>;
  }>;
}

function sha256(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('SHA-256 needs a secure browser context; no evidence generated');
  }
  return globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
    .then((result) => Array.from(new Uint8Array(result))
      .map((part) => part.toString(16).padStart(2,'0')).join(''));
}
function safeFormat(value: string): string {
  return FORMATS.has(value) ? value : 'unknown';
}
function safeDiagnostic(diag: Diagnostic): BrowserTestEvidence['events'][number]['diagnostics'][number] {
  return {
    stage: STAGES.has(diag.stage) ? diag.stage : 'validate',
    severity: LEVELS.has(diag.severity) ? diag.severity : 'warning',
    code: KNOWN_DIAGNOSTICS.has(diag.code) ? diag.code : 'UNSPECIFIED',
  };
}

/** Deterministic source-hash-bound report. This method is never called by
 * selection or render; only by a deliberate user download action. */
export async function createBrowserEvidence(input: {
  sample: string;
  draft: ParserDraft;
  suite: SuiteResult;
}): Promise<BrowserTestEvidence> {
  const { sample, draft, suite } = input;
  const sampleBytes = new TextEncoder().encode(sample).byteLength;
  const serializedDraft = JSON.stringify(draft);
  const draftBytes = new TextEncoder().encode(serializedDraft).byteLength;

  if (!sampleBytes || sampleBytes > MAX_DATASET_BYTES ||
      draftBytes > MAX_DRAFT_BYTES || suite.engine !== 'browser-preview' ||
      suite.nativeFluentdVerified !== false || suite.stellarExportVerified !== false ||
      !Number.isInteger(suite.counts.total) || suite.counts.total <= 0 ||
      suite.events.length !== suite.counts.total || suite.events.length > MAX_EVENTS) {
    throw new Error('No consistent browser suite for the current bounded sample and draft');
  }

  const [sampleSha256,draftSha256] = await Promise.all([
    sha256(sample), sha256(serializedDraft),
  ]);
  return {
    reportSchema:'parser-studio.browser-test-evidence.v0.1',
    engine:'browser-preview',
    artifactStatus:'DRAFT_ONLY',
    compatibility:{nativeFluentdVerified:false,stellarTargetVerified:false},
    privacy:{rawLogsIncluded:false,normalizedValuesIncluded:false,diagnosticMessagesIncluded:false},
    source:{sampleSha256,draftSha256,sampleBytes},
    counts:{
      total:suite.counts.total,matched:suite.counts.matched,
      extracted:suite.counts.extracted,normalized:suite.counts.normalized,
      failures:suite.counts.failures,warnings:suite.counts.warnings,
    },
    events:suite.events.map((event,index)=>({
      number:index+1,
      line:Number.isInteger(event.line) && event.line >= 1 ? event.line : index+1,
      status:STATUSES.has(event.status) ? event.status : 'fail',
      detectedFormat:safeFormat(event.detected.format),
      effectiveFormat:safeFormat(event.effectiveFormat),
      matched:event.matched === true,
      extracted:event.extracted === true,
      normalized:event.normalizedOk === true,
      diagnostics:event.diagnostics.slice(0,64).map(safeDiagnostic),
    })),
  };
}
