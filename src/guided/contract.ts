import type { FieldType, ParserDraft } from '../model';

export type EventClass = 'Session' | 'Threat' | 'Syslog' | 'Winlogevent';
export type FieldGroup = 'top_fields' | 'ns_fields' | 'vendor_fields';
export type Transport = 'udp' | 'tcp';
export type EventBoundary = 'single-line' | 'blank-line';

export interface GuidedOptions {
  slug: string;
  /** Browser-local event boundary preview, not an assertion of backend loader support. */
  eventBoundary?: EventBoundary;
  groups: Record<string, FieldGroup>;
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
  input: { format: 'json' | 'kv' | 'csv' | 'regex' | 'syslog' };
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

export function defaultGuidedOptions(): GuidedOptions {
  return {
    slug: 'demo_firewall',
    eventBoundary: 'single-line',
    groups: { 'source-ip': 'top_fields', 'target-port': 'ns_fields', action: 'vendor_fields' },
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

  if (!(['json', 'kv'] as string[]).includes(draft.format)) {
    errors.push('This proposed compiler subset requires an explicit JSON or Key / Value format; Auto and other formats are not yet enabled for pairing');
  }

  if (!draft.mappings.length) errors.push('Map at least one extracted field');
  const targets = new Set<string>();
  const normalization: PairProjectContract['normalization'] = { top_fields: [], ns_fields: [], vendor_fields: [] };
  const supportedTypes: FieldType[] = ['string', 'integer', 'timestamp', 'ip', 'port', 'boolean'];
  for (const mapping of draft.mappings) {
    if (!mapping.source.trim() || !/^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(mapping.source)) errors.push('Invalid source field: ' + mapping.source);
    if (!/^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(mapping.target)) errors.push('Invalid destination field: ' + mapping.target);
    if (targets.has(mapping.target)) errors.push('Duplicate normalized destination: ' + mapping.target);
    targets.add(mapping.target);
    if (['msg_origin', 'stellar_log_index'].includes(mapping.target)) errors.push('Reserved destination: ' + mapping.target);
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
  const ruleKeys = new Set<string>();
  for (const rule of options.classification.rules) {
    if (!/^[A-Za-z_][A-Za-z0-9_.]{0,63}$/.test(rule.sourceField) || !rule.equals.trim()) errors.push('Complete every event classification condition');
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
      input: { format: draft.format as 'json' | 'kv' },
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
