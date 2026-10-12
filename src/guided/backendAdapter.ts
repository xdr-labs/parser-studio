import type { ParserDraft } from '../model';
import {
  compilerDraftContract, defaultGuidedOptions,
  type EventClass, type FieldGroup, type SourceCategory,
} from './contract';

export type BackendLogIndex = 'session' | 'threat' | 'syslog' | 'winlogevent';
export type BackendFieldType = 'string' | 'integer' | 'ip' | 'port' | 'boolean' | 'date';

export interface BackendField {
  normalized_name: string;
  data_type: BackendFieldType;
  time_format?: 'iso8601';
  timezone?: 'UTC';
}

export type BackendEnrichmentRule =
  | { operator: 'set_const'; target: string; value: string }
  | { operator: 'copy' | 'lowercase' | 'uppercase'; source: string; target: string };

export interface BackendParserProject {
  schemaRevision: '0.1';
  projectId: string;
  revision: 1;
  slug: string;
  vendor: string;
  product: string;
  sourceCategory: SourceCategory;
  receiver: {
    protocols: ('udp' | 'tcp')[];
    port: number;
    bindAddress: '127.0.0.1' | '0.0.0.0';
    messageLengthLimit: number;
    tcpFraming: 'line';
  };
  extraction: { format: 'json' | 'kv' | 'cef' | 'leef' } | { format: 'syslog_rfc5424'; syslogBodyFormat?: 'raw' | 'json' | 'kv' | 'cef' | 'leef' } | { format: 'csv'; csvColumns: string[]; csvDelimiter: ',' | ';' | '\t' };
  normalization: {
    msgOriginSource: string;
    msgClass: string;
    msgOriginCategory: string;
    ignoreValues: string[];
    topFields: Record<string, BackendField>;
    nsFields: Record<string, BackendField>;
    vendorFields: Record<string, BackendField>;
  };
  enrichment?: BackendEnrichmentRule[];
  classification: {
    defaultIndex: BackendLogIndex;
    rules: { field: string; operator: 'equals'; value: string; index: BackendLogIndex }[];
  };
}

export interface AdapterIssue {
  code: string;
  path: string;
  message: string;
}
export type BackendProjectResult =
  | { ok: true; project: BackendParserProject; issues: [] }
  | { ok: false; issues: AdapterIssue[] };

const indexMap: Record<EventClass, BackendLogIndex> = {
  Session: 'session', Threat: 'threat', Syslog: 'syslog', Winlogevent: 'winlogevent',
};

const UNSAFE_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const SOURCE_CATEGORIES: SourceCategory[] = ['network', 'endpoint', 'cloud', 'application', 'other'];

function safeFieldPath(path: string): boolean {
  return path.split('.').every((part) => part && !UNSAFE_SEGMENTS.has(part));
}

/**
 * Explicit UI -> backend contract adapter for PR #4's ParserProject 0.1.
 * It never receives raw sample text; rejects all lossy/ambiguous conversions.
 */
export function toBackendProject(draft: ParserDraft): BackendProjectResult {
  const local = compilerDraftContract(draft);
  if (!local.ok) {
    return {
      ok: false,
      issues: local.errors.map((message, index) => ({
        code: 'UI_VALIDATION',
        path: '/draft/' + index,
        message,
      })),
    };
  }
  const options = draft.guided ?? defaultGuidedOptions();
  const issues: AdapterIssue[] = [];
  const topFields: Record<string, BackendField> = Object.create(null);
  const nsFields: Record<string, BackendField> = Object.create(null);
  const vendorFields: Record<string, BackendField> = Object.create(null);
  const fieldsByGroup: Record<FieldGroup, Record<string, BackendField>> = {
    top_fields: topFields, ns_fields: nsFields, vendor_fields: vendorFields,
  };
  const destinationForSource = new Map<string, string>();
  for (const [index, mapping] of draft.mappings.entries()) {
    const group = options.groups[mapping.id] ?? 'vendor_fields';
    if (!safeFieldPath(mapping.source) || !safeFieldPath(mapping.target)) {
      issues.push({ code: 'UNSAFE_FIELD', path: '/mappings/' + index, message: 'Prototype/constructor field paths are not allowed' });
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(fieldsByGroup, group)) {
      issues.push({ code: 'INVALID_GROUP', path: '/mappings/' + index, message: 'Unknown target field group' });
      continue;
    }
    const collection = fieldsByGroup[group];
    if (Object.prototype.hasOwnProperty.call(collection, mapping.source)) {
      issues.push({ code: 'DUPLICATE_SOURCE', path: '/mappings/' + index, message: 'This source is already mapped in the same output group: ' + mapping.source });
      continue;
    }
    const data_type: BackendFieldType = mapping.type === 'timestamp' ? 'date' : mapping.type as BackendFieldType;
    collection[mapping.source] = {
      normalized_name: mapping.target,
      data_type,
      ...(data_type === 'date' ? { time_format: 'iso8601' as const, timezone: 'UTC' as const } : {}),
    };
    // Backend classification is evaluated after normalization and currently
    // reads only top/namespace fields; vendor names need explicit remapping.
    if (group !== 'vendor_fields') destinationForSource.set(mapping.source, mapping.target);
  }
  const rules: BackendParserProject['classification']['rules'] = [];
  for (const [index, rule] of options.classification.rules.entries()) {
    const normalized = destinationForSource.get(rule.sourceField);
    if (!normalized) {
      issues.push({
        code: 'CLASSIFICATION_SOURCE_NOT_AVAILABLE',
        path: '/classification/rules/' + index,
        message: 'Classification rule ' + (index + 1) + ': ' + rule.sourceField + ' must map to Common or Network Fields to support classification on this backend.',
      });
      continue;
    }
    rules.push({ field: normalized, operator: 'equals', value: rule.equals, index: indexMap[rule.index] });
  }
  const category = options.sourceCategory ?? 'network';
  if (!SOURCE_CATEGORIES.includes(category)) {
    issues.push({ code: 'SOURCE_CATEGORY_UNSUPPORTED', path: '/sourceCategory', message: 'Unknown source category' });
  }
  if (issues.length) return { ok: false, issues };
  const project: BackendParserProject = {
    schemaRevision: '0.1',
    projectId: 'draft-' + options.slug,
    revision: 1,
    slug: options.slug,
    vendor: draft.vendor,
    product: draft.name,
    sourceCategory: category,
    receiver: {
      protocols: options.receiver.protocols,
      port: options.receiver.port,
      bindAddress: options.receiver.bindPolicy === 'all' ? '0.0.0.0' : '127.0.0.1',
      messageLengthLimit: options.receiver.messageLimit,
      tcpFraming: 'line',
    },
    extraction: draft.format === 'csv'
      ? { format: 'csv', csvColumns: draft.csvColumns.split(',').map((column) => column.trim()), csvDelimiter: draft.csvDelimiter ?? ',' }
      : draft.format === 'syslog_rfc5424'
        ? { format: 'syslog_rfc5424',
            ...(draft.syslogBodyFormat && draft.syslogBodyFormat !== 'raw'
              ? { syslogBodyFormat: draft.syslogBodyFormat } : {}) }
        : { format: draft.format as 'json' | 'kv' | 'cef' | 'leef' },
    normalization: {
      msgOriginSource: options.slug,
      msgClass: options.slug,
      msgOriginCategory: category,
      ignoreValues: ['', 'N/A', '-'],
      topFields, nsFields, vendorFields,
    },
    ...(options.enrichment?.length ? {
      enrichment: options.enrichment.map((rule): BackendEnrichmentRule =>
        rule.operator === 'set_const'
          ? { operator: 'set_const', target: rule.target, value: rule.value }
          : { operator: rule.operator, source: rule.source, target: rule.target }),
    } : {}),
    classification: {
      defaultIndex: indexMap[options.classification.defaultIndex],
      rules,
    },
  };
  return { ok: true, project, issues: [] };
}
