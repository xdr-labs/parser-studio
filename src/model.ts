import { defaultGuidedOptions, type GuidedOptions } from './guided/contract';
import type {EventProfileConfig} from './guided/multiEventRouting';
import type {ForwarderConfig,ForwarderHop} from './guided/declaredForwarder';
import type {GenericStructuralProfile} from './genericStructuralProfiles';

export const FORMATS = ['auto', 'json', 'kv', 'csv', 'syslog_rfc3164', 'syslog_rfc5424', 'cef', 'leef', 'mixed', 'java_stacktrace', 'generic_structural', 'syslog', 'regex'] as const;
export type Format = (typeof FORMATS)[number];
export type ConcreteFormat = Exclude<Format, 'auto'>;
export type FieldType = 'string' | 'integer' | 'number' | 'boolean' | 'ip' | 'port' | 'timestamp';

export interface MappingWhen {
  sourcePath:string;
  operator:'in';
  values:string[];
}
export interface MappingRule {
  /** v1 authoring provenance: never infer manual intent from an ID or field spelling.
   * Absence on a legacy draft means unknown and is never eligible for rewrites.
   * This metadata is excluded from the generated Stellar target mapping.
   */
  authoring?:{version:1;origin:'AUTO'|'USER_EDITED'|'APPROVED'|'REVIEW_REQUIRED'};
  /** Bounded per-event applicability. Nonmatching events preserve other mappings. */
  when?:MappingWhen;
  id: string;
  source: string;
  target: string;
  type: FieldType;
  /** JSONata-authored source selector. Absent is the legacy flexible source lookup. */
  sourcePathKind?: 'literal_root' | 'nested';
}

export interface ParserDraft {
  name: string;
  vendor: string;
  /** Product/parser version entered by the author. Kept optional for old saved drafts. */
  version?: string;
  format: Format;
  pattern: string;
  csvColumns: string;
  /** Data-record CSV delimiter; column names always use commas. Older saved drafts default to comma. */
  csvDelimiter?: ',' | ';' | '\t';
  /** Only for bounded RFC3164/RFC5424 headers; raw is the backward-compatible default. */
  syslogBodyFormat?: 'raw' | 'json' | 'kv' | 'cef' | 'leef' | 'regex';
  /** Explicit additional Generic Structural grammar; absent keeps V15 behavior. */
  genericStructuralProfile?: GenericStructuralProfile;
  /** Generic Structural only: leave the full raw line (source_raw) out of parserstudio_source. Absent keeps it. */
  omitSourceRaw?: true;
  /** Explicit supported one-line families only; no implicit fallback. */
  mixedFormats?: Array<'json'|'kv'|'cef'|'leef'|'rfc5424_cef'|'rfc5424_leef'|'rfc3164_kv'|'rfc5424_json'|'rfc5424_kv'|'rfc3164_cef'|'rfc3164_leef'|'csv'>;
  mappings: MappingRule[];
  /** One deployable parser, with conditional per-event normalization. */
  eventProfiles?: EventProfileConfig;
  /** Explicitly reviewed relay hostnames; never blindly trim prefixes. */
  forwarder?: ForwarderConfig;
  guided?: GuidedOptions;
}

export interface Detection {
  format: ConcreteFormat | 'unknown';
  confidence: number;
  reason: string;
}

export interface Diagnostic {
  stage: 'break' | 'detect' | 'extract' | 'normalize' | 'enrichment' | 'validate';
  severity: 'error' | 'warning';
  code: string;
  message: string;
  field?: string;
}

export interface TraceStep {
  stage: string;
  detail: string;
  ok: boolean;
}

export type EventStatus = 'pass' | 'warning' | 'fail';
/** Parsing Success Contract (src/grammar/parseStatus.ts): FULL is never reported when a field visible in the original log is missing. */
export type EventParseStatus = 'FULL' | 'PARTIAL' | 'UNKNOWN' | 'ERROR';
export interface EventResult {
  id: string;
  line: number;
  raw: string;
  detected: Detection;
  effectiveFormat: ConcreteFormat | 'unknown';
  fields: Record<string, unknown>;
  normalized: Record<string, unknown>;
  eventFamily?: string;
  forwarderHops?: ForwarderHop[];
  unmapped: string[];
  matched: boolean;
  extracted: boolean;
  normalizedOk: boolean;
  status: EventStatus;
  /** Set by the preview pipeline for every event. */
  parseStatus?: EventParseStatus;
  diagnostics: Diagnostic[];
  trace: TraceStep[];
}

export interface SuiteResult {
  events: EventResult[];
  counts: {
    total: number;
    matched: number;
    extracted: number;
    normalized: number;
    failures: number;
    warnings: number;
  };
  engine: 'browser-preview';
  nativeFluentdVerified: false;
  stellarExportVerified: false;
}

export const DEMO_SAMPLES = [
  '{"time":"2026-10-12T00:00:00Z","action":"allow","src_ip":"198.51.100.10","dst_port":443,"device":"DEMO-FW"}',
  'action=deny src_ip=203.0.113.12 dst_port=22 device=DEMO-FW',
  '{"time":"2026-10-12T00:00:02Z","action":"deny","src_ip":"invalid-ip","dst_port":65536,"device":"DEMO-FW"}',
].join('\n');

export function createDraft(): ParserDraft {
  return {
    name: 'Untitled parser',
    vendor: 'Demo Local Draft',
    version: '1.0.0',
    format: 'auto',
    pattern: '(?<action>\\w+)\\s+src=(?<src_ip>\\S+)',
    csvColumns: 'time,action,src_ip,dst_port',
    csvDelimiter: ',',
    syslogBodyFormat: 'raw',
    guided: defaultGuidedOptions(),
    mappings: [
      { id: 'source-ip', source: 'src_ip', target: 'custom.source_ip', type: 'ip',
        authoring:{version:1,origin:'AUTO'} },
      { id: 'target-port', source: 'dst_port', target: 'custom.destination_port', type: 'port',
        authoring:{version:1,origin:'AUTO'} },
      { id: 'action', source: 'action', target: 'custom.action', type: 'string',
        authoring:{version:1,origin:'AUTO'} },
    ],
  };
}
