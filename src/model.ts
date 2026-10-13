import { defaultGuidedOptions, type GuidedOptions } from './guided/contract';

export const FORMATS = ['auto', 'json', 'kv', 'csv', 'syslog_rfc3164', 'syslog_rfc5424', 'cef', 'leef', 'mixed', 'syslog', 'regex'] as const;
export type Format = (typeof FORMATS)[number];
export type ConcreteFormat = Exclude<Format, 'auto'>;
export type FieldType = 'string' | 'integer' | 'number' | 'boolean' | 'ip' | 'port' | 'timestamp';

export interface MappingRule {
  id: string;
  source: string;
  target: string;
  type: FieldType;
}

export interface ParserDraft {
  name: string;
  vendor: string;
  format: Format;
  pattern: string;
  csvColumns: string;
  /** Data-record CSV delimiter; column names always use commas. Older saved drafts default to comma. */
  csvDelimiter?: ',' | ';' | '\t';
  /** Only for bounded RFC3164/RFC5424 headers; raw is the backward-compatible default. */
  syslogBodyFormat?: 'raw' | 'json' | 'kv' | 'cef' | 'leef';
  /** Explicit supported one-line families only; no implicit fallback. */
  mixedFormats?: Array<'json'|'kv'|'cef'|'leef'>;
  mappings: MappingRule[];
  guided?: GuidedOptions;
}

export interface Detection {
  format: ConcreteFormat | 'unknown';
  confidence: number;
  reason: string;
}

export interface Diagnostic {
  stage: 'break' | 'detect' | 'extract' | 'normalize' | 'validate';
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
export interface EventResult {
  id: string;
  line: number;
  raw: string;
  detected: Detection;
  effectiveFormat: ConcreteFormat | 'unknown';
  fields: Record<string, unknown>;
  normalized: Record<string, unknown>;
  unmapped: string[];
  matched: boolean;
  extracted: boolean;
  normalizedOk: boolean;
  status: EventStatus;
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
    vendor: 'Demo / local draft',
    format: 'auto',
    pattern: '(?<action>\\w+)\\s+src=(?<src_ip>\\S+)',
    csvColumns: 'time,action,src_ip,dst_port',
    csvDelimiter: ',',
    syslogBodyFormat: 'raw',
    guided: defaultGuidedOptions(),
    mappings: [
      { id: 'source-ip', source: 'src_ip', target: 'custom.source_ip', type: 'ip' },
      { id: 'target-port', source: 'dst_port', target: 'custom.destination_port', type: 'port' },
      { id: 'action', source: 'action', target: 'custom.action', type: 'string' },
    ],
  };
}
