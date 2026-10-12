import type { FieldType, ParserDraft } from '../model';

export type EventClass = 'Session' | 'Threat' | 'Syslog' | 'Winlogevent';
export type FieldGroup = 'top_fields' | 'ns_fields' | 'vendor_fields';
export type Transport = 'udp' | 'tcp';
export type SourceCategory = 'network' | 'endpoint' | 'cloud' | 'application' | 'other';
export type EventBoundary = 'single-line' | 'blank-line';
export type EnrichmentOperator = 'set_const' | 'copy' | 'lowercase' | 'uppercase';
export interface GuidedEnrichmentRule {
  id: string;
  operator: EnrichmentOperator;
  source: string;
  target: string;
  value: string;
}

export interface GuidedOptions {
  slug: string;
  sourceCategory?: SourceCategory;
  /** Browser-local event boundary preview; unsupported for native pair generation. */
  eventBoundary?: EventBoundary;
  groups: Record<string, FieldGroup>;
  enrichment?: GuidedEnrichmentRule[];
  receiver: {
    protocols: Transport[];
    port: number;
    bindPolicy: 'loopback' | 'all';
    messageLimit: number;
    framing: 'newline';
  };
  classification: {
    defaultIndex: EventClass;
    rules: { id: string; sourceField: string; equals: string; index: EventClass }[];
  };
}

export interface PairProjectContract {
  schemaRevision: '0.1';
  slug: string;
  vendor: string;
  product: string;
  receiver: {
    protocols: Transport[];
    port: number;
    bindPolicy: 'loopback' | 'all';
    messageLimit: number;
    framing: 'newline';
  };
  input: { format: 'json' | 'kv' | 'csv' | 'syslog_rfc5424' | 'cef' | 'leef' | 'regex' | 'syslog' };
  normalization: Record<FieldGroup, {
    source: string;
    normalized_name: string;
    data_type: 'string' | 'integer' | 'date' | 'ip' | 'port' | 'boolean';
    time_format?: 'iso8601';
    timezone?: 'UTC';
  }[]>;
  classification: {
    rules: { sourceField: string; equals: string; index: EventClass }[];
    defaultIndex: EventClass;
  };
  exportProfile: 'host-customized-pair-draft';
}

export type ContractResult =
  | { ok: true; project: PairProjectContract; diagnostics: string[] }
  | { ok: false; errors: string[]; diagnostics: string[] };

export const CLASSIFICATIONS: EventClass[] = ['Session', 'Threat', 'Syslog', 'Winlogevent'];
export const FIELD_GROUPS: FieldGroup[] = ['top_fields', 'ns_fields', 'vendor_fields'];
// A conservative subset of the v0.1 backend field path grammar. The browser
// preview also uses this narrower syntax; do not claim a full Interflow dictionary.
const SAFE_UI_FIELD_PATH = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const UNSAFE_FIELD_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor']);
const RESERVED_OUTPUT_ROOTS = new Set([
  'msg_origin', 'stellar_log_index', 'parser_err_msg', 'parser_err_stage', 'parser_err_field',
]);
function safeUiPath(path: string): boolean {
  return path.length > 0 && path.length <= 128 && SAFE_UI_FIELD_PATH.test(path) &&
    path.split('.').every((part) => !UNSAFE_FIELD_SEGMENTS.has(part));
}
function overlappingDestination(first: string, second: string): boolean {
  return first.startsWith(second + '.') || second.startsWith(first + '.');
}


export function defaultGuidedOptions(): GuidedOptions {
  return {
    slug: 'demo_firewall',
    sourceCategory: 'network',
    eventBoundary: 'single-line',
    // Preserve the backend-validated classifier mapping; vendor-only is not routable.
    groups: { 'source-ip': 'top_fields', 'target-port': 'ns_fields', action: 'top_fields' },
    receiver: { protocols: ['udp', 'tcp'], port: 7501, bindPolicy: 'loopback', messageLimit: 8192, framing: 'newline' },
    classification: {
      defaultIndex: 'Syslog',
      rules: [
        { id: 'deny', sourceField: 'action', equals: 'deny', index: 'Threat' },
        { id: 'allow', sourceField: 'action', equals: 'allow', index: 'Session' },
      ],
    },
  };
}

export function compilerDraftContract(draft: ParserDraft): ContractResult {
  const options = draft.guided ?? defaultGuidedOptions();
  const errors: string[] = [];
  const diagnostics: string[] = [
    'UI-side contract preview only. The backend compiler and native target validation have not been connected.',
    'Stored reference configurations sharing a port do not prove an active target collision.',
  ];

  if (!/^[a-z][a-z0-9_]{2,47}$/.test(options.slug)) errors.push('Parser ID: 3–48 lowercase letters, digits and underscores, starting with a letter');
  if (!draft.vendor.trim() || !draft.name.trim()) errors.push('Set a product name and vendor');
  if (!options.receiver.protocols.length || new Set(options.receiver.protocols).size !== options.receiver.protocols.length) errors.push('Choose one or more unique UDP/TCP receiver protocols');
  if (!Number.isInteger(options.receiver.port) || options.receiver.port < 1024 || options.receiver.port > 65535) errors.push('Receiving port must be an integer in 1024–65535');
  if (!Number.isInteger(options.receiver.messageLimit) || options.receiver.messageLimit < 1024 || options.receiver.messageLimit > 65536) errors.push('Message limit must be an integer in 1024–65536 bytes');

  if (options.eventBoundary && options.eventBoundary !== 'single-line') {
    errors.push('Blank-line grouping is preview-only until the paired backend compiler declares a supported multiline event breaker');
  }

  if (!(['json', 'kv', 'csv', 'syslog_rfc5424', 'cef', 'leef'] as string[]).includes(draft.format)) {
    errors.push('This compiler subset requires explicit JSON, Key / Value, comma CSV, RFC5424, standalone CEF or LEEF; Auto, generic Syslog and Regex are preview-only');
  }
  if (draft.format === 'csv') {
    const columns = draft.csvColumns.split(',').map((name) => name.trim());
    if (columns.length > 100 || !columns.every((name) => /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(name)) ||
        new Set(columns).size !== columns.length) {
      errors.push('CSV requires 1–100 unique valid column names with no empty columns');
    }
  }

  if (!draft.mappings.length) errors.push('Map at least one extracted field');
  const targets = new Set<string>();
  const normalization: PairProjectContract['normalization'] = { top_fields: [], ns_fields: [], vendor_fields: [] };
  const supportedTypes: FieldType[] = ['string', 'integer', 'timestamp', 'ip', 'port', 'boolean'];
  for (const mapping of draft.mappings) {
    if (!safeUiPath(mapping.source)) errors.push('Invalid source field: ' + mapping.source);
    if (!safeUiPath(mapping.target)) errors.push('Invalid destination field: ' + mapping.target);
    if (targets.has(mapping.target)) errors.push('Duplicate normalized destination: ' + mapping.target);
    else if ([...targets].some((target) => overlappingDestination(target, mapping.target))) {
      errors.push('Normalized destination collision: ' + mapping.target);
    }
    targets.add(mapping.target);
    if (RESERVED_OUTPUT_ROOTS.has(mapping.target.split('.')[0])) {
      errors.push('Reserved destination: ' + mapping.target);
    }
    if (!supportedTypes.includes(mapping.type)) errors.push('Backend subset does not support type ' + mapping.type + ' for ' + mapping.source);
    const group = options.groups[mapping.id] ?? 'vendor_fields';
    const data_type = mapping.type === 'timestamp' ? 'date' : mapping.type;
    if (supportedTypes.includes(mapping.type)) {
      normalization[group].push({
        source: mapping.source.trim(), normalized_name: mapping.target.trim(),
        data_type: data_type as PairProjectContract['normalization']['top_fields'][number]['data_type'],
        ...(mapping.type === 'timestamp' ? { time_format: 'iso8601' as const, timezone: 'UTC' as const } : {}),
      });
    }
  }
  const available = new Map<string, string>();
  const destinations = draft.mappings.map(({ target }) => target);
  for (const mapping of draft.mappings) {
    if ((options.groups[mapping.id] ?? 'vendor_fields') !== 'vendor_fields') {
      available.set(mapping.target, mapping.type);
    }
  }
  const enrich = options.enrichment ?? [];
  if (enrich.length > 64) errors.push('At most 64 ordered enrichment steps are supported');
  for (const [i, rule] of enrich.entries()) {
    if (!['set_const', 'copy', 'lowercase', 'uppercase'].includes(rule.operator)) {
      errors.push('Unsupported enrichment operation at step ' + (i + 1));
      continue;
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(rule.target) ||
        rule.target.split('.').some((part) => ['__proto__', 'constructor', 'prototype'].includes(part)) ||
        ['msg_origin', 'stellar_log_index', 'parser_err_msg'].includes(rule.target.split('.')[0])) {
      errors.push('Unsafe enrichment output at step ' + (i + 1));
    }
    if (destinations.some((value) => value === rule.target ||
        value.startsWith(rule.target + '.') || rule.target.startsWith(value + '.'))) {
      errors.push('Enrichment destination collision at step ' + (i + 1));
    }
    if (rule.operator === 'set_const') {
      if (rule.value.length > 256) errors.push('Enrichment constant exceeds 256 characters');
    } else if (!available.has(rule.source)) {
      errors.push('Enrichment source is not a normalized field at step ' + (i + 1));
    } else if ((rule.operator === 'lowercase' || rule.operator === 'uppercase') &&
               available.get(rule.source) !== 'string') {
      errors.push('Case changes require a text source field at step ' + (i + 1));
    }
    destinations.push(rule.target);
    available.set(rule.target, rule.operator === 'set_const' ? 'string' : (available.get(rule.source) ?? 'unknown'));
  }
  const ruleKeys = new Set<string>();
  for (const rule of options.classification.rules) {
    if (!safeUiPath(rule.sourceField) || !rule.equals.trim()) errors.push('Complete every event classification condition');
    if (ruleKeys.has(rule.sourceField + '\0' + rule.equals)) errors.push('Duplicate event classification condition: ' + rule.sourceField);
    ruleKeys.add(rule.sourceField + '\0' + rule.equals);
  }

  if (errors.length) return { ok: false, errors, diagnostics };
  return {
    ok: true, diagnostics,
    project: {
      schemaRevision: '0.1',
      slug: options.slug,
      vendor: draft.vendor,
      product: draft.name,
      receiver: options.receiver,
      input: { format: draft.format as 'json' | 'kv' | 'csv' | 'syslog_rfc5424' | 'cef' | 'leef' },
      normalization,
      classification: {
        rules: options.classification.rules.map(({ sourceField, equals, index }) => ({ sourceField, equals, index })),
        defaultIndex: options.classification.defaultIndex,
      },
      exportProfile: 'host-customized-pair-draft',
    },
  };
}

export function plannedPairNames(slug: string): { config: string; parser: string } | null {
  if (!/^[a-z][a-z0-9_]{2,47}$/.test(slug)) return null;
  return { config: 'customized_' + slug + '.conf', parser: 'customized_' + slug };
}
