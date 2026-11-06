import {validMappingWhen} from '../fieldPaths';
import type { FieldType, ParserDraft } from '../model';
import {validatePreviewRegexPattern} from '../regexSafety';

export type EventClass = 'Session' | 'Threat' | 'Syslog' | 'Winlogevent';
export type FieldGroup = 'top_fields' | 'ns_fields' | 'vendor_fields';
export type Transport = 'udp' | 'tcp';
export type SourceCategory = 'network' | 'endpoint' | 'cloud' | 'application' | 'other';
export type EventBoundary = 'single-line' | 'blank-line';
export type EnrichmentOperator = 'set_const' | 'copy' | 'lowercase' | 'uppercase' | 'split_field' | 'merge_fields';
export interface GuidedEnrichmentRule {
  id: string;
  operator: EnrichmentOperator;
  source: string;
  target: string;
  value: string;
  /** Bounded declarative split/merge only; never Regex or executable syntax. */
  delimiter?: string;
  targets?: string[];
  sources?: string[];
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
    framing: 'newline' | 'blank_line_json' | 'blank_line_java';
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
  productVersion?: string;
  receiver: {
    protocols: Transport[];
    port: number;
    bindPolicy: 'loopback' | 'all';
    messageLimit: number;
    framing: 'newline' | 'blank_line_json' | 'blank_line_java';
  };
  input: { format: 'json' | 'kv' | 'csv' | 'syslog_rfc3164' | 'syslog_rfc5424' | 'cef' | 'leef' | 'mixed' | 'java_stacktrace' | 'generic_structural' | 'regex' | 'syslog' };
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
const SAFE_UI_FIELD_PATH = /^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
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


export const DEFAULT_PARSER_LISTENER_PORT = 6801;

export function defaultGuidedOptions(): GuidedOptions {
  return {
    slug: 'demo_firewall',
    sourceCategory: 'network',
    eventBoundary: 'single-line',
    // Preserve the backend-validated classifier mapping; vendor-only is not routable.
    groups: { 'source-ip': 'top_fields', 'target-port': 'ns_fields', action: 'top_fields' },
    receiver: { protocols: ['udp', 'tcp'], port: DEFAULT_PARSER_LISTENER_PORT, bindPolicy: 'loopback', messageLimit: 8192, framing: 'newline' },
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
    'UI-side contract preview only. The backend DRAFT compiler is connected; native Fluentd execution and actual Stellar target import are not verified.',
    'Stored reference configurations sharing a port do not prove an active target collision.',
  ];

  if (!/^[a-z][a-z0-9_]{2,47}$/.test(options.slug)) errors.push('Parser ID: 3–48 lowercase letters, digits and underscores, starting with a letter');
  if (!draft.vendor.trim() || !draft.name.trim()) errors.push('Set a product name and vendor');
  if (draft.version!==undefined&&(!draft.version.trim()||draft.version.length>64||/[\r\n\u0000-\u001f\u007f]/.test(draft.version))) errors.push('Product version must be 1–64 visible characters');
  if (!options.receiver.protocols.length || new Set(options.receiver.protocols).size !== options.receiver.protocols.length) errors.push('Choose one or more unique UDP/TCP receiver protocols');
  if (!Number.isInteger(options.receiver.port) || options.receiver.port < 1024 || options.receiver.port > 65535) errors.push('Receiving port must be an integer in 1024–65535');
  // One shared sensor ingress / generated CONF <source> port. The backend
  // enforces a narrower minimum for RFC5424 Syslog parser pairs.
  if (['syslog_rfc3164','syslog_rfc5424','generic_structural'].includes(draft.format) &&
      Number.isInteger(options.receiver.port) && options.receiver.port<6800) {
    errors.push('RFC3164/RFC5424/Generic Structural sensor and CONF listener port must be at least 6800');
  }
  if (!Number.isInteger(options.receiver.messageLimit) || options.receiver.messageLimit < 1024 || options.receiver.messageLimit > 65536) errors.push('Message limit must be an integer in 1024–65536 bytes');

  const framedJson=options.receiver.framing==='blank_line_json';
  const framedJava=options.receiver.framing==='blank_line_java';
  if(framedJson&&(
    draft.format!=='json'||options.eventBoundary!=='blank-line'||
    options.receiver.protocols.length!==1||
    options.receiver.protocols[0]!=='tcp')){
    errors.push('TCP blank-line JSON framing requires explicit JSON format, one TCP protocol only, and blank-line event boundaries. Senders must separate complete JSON objects with LF LF.');
  }
  if(framedJava&&(
    draft.format!=='java_stacktrace'||options.eventBoundary!=='blank-line'||
    options.receiver.protocols.length!==1||
    options.receiver.protocols[0]!=='tcp')){
    errors.push('Native Java stack traces require explicitly TCP-only LF LF framing, verified source event separators, and the Java format.');
  }
  if(draft.format==='java_stacktrace'&&!framedJava)
    errors.push('Java Stack Trace can only be generated with explicit TCP LF LF framing.');
  if(options.eventBoundary!=='single-line'&&!framedJson&&!framedJava)
    errors.push('Blank-line grouping is browser-only without a strictly selected TCP JSON or Java LF LF framing.');

  if (!(['json', 'kv', 'csv', 'syslog_rfc3164', 'syslog_rfc5424', 'cef', 'leef', 'mixed','java_stacktrace','generic_structural','regex'] as string[]).includes(draft.format)) {
    errors.push('This compiler subset requires explicit JSON, Key / Value, CSV, RFC3164/RFC5424, standalone CEF/LEEF, Java stack trace, bounded Generic Structural recovery or bounded Regex; Auto and generic Syslog are preview-only');
  }
  const regexSelected=draft.format==='regex'||
    (['syslog_rfc3164','syslog_rfc5424'].includes(draft.format)&&draft.syslogBodyFormat==='regex');
  if(regexSelected){
    const regexIssue=validatePreviewRegexPattern(draft.pattern);
    if(regexIssue)errors.push('Regex parser: '+regexIssue);
  }
  if (['syslog_rfc3164','syslog_rfc5424'].includes(draft.format) &&
      !['raw', 'json', 'kv', 'cef', 'leef', 'regex'].includes(draft.syslogBodyFormat ?? 'raw')) {
    errors.push('Unsupported Syslog body format; use raw, JSON object, strict Key/Value, CEF, LEEF or bounded Regex');
  }
  if(draft.format==='mixed'){
    const list=draft.mixedFormats;
    if(list?.some(f=>f==='rfc5424_cef'||f==='rfc5424_leef'||f==='rfc3164_kv'||f==='rfc5424_json'||f==='rfc5424_kv'||f==='rfc3164_cef'||f==='rfc3164_leef')&&
      options.receiver.port<6800)
      errors.push('Syslog mixed sensor and CONF listener port must be at least 6800');
    if(list?.some(f=>f.startsWith('rfc3164_'))&&draft.mappings.some(m=>
      m.source==='syslog_timestamp'&&m.type==='timestamp'))
      errors.push('Yearless RFC3164 mixed timestamp cannot be cast to a date. Map as text.');
    if(!Array.isArray(list)||list.length<2||list.length>4||
       new Set(list).size!==list.length||
       !list.every(mode=>['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef','csv'].includes(mode)))
      errors.push('Mixed requires 2–4 explicit one-line JSON/KV/CEF/LEEF, RFC5424 JSON/KV/CEF/LEEF or yearless RFC3164 TAG KV/CEF/LEEF families, with CSV only when columns are reviewed');
    if(list?.includes('csv')){
      const columns=draft.csvColumns.split(',').map(name=>name.trim());
      if(columns.length<2||columns.length>100||
         !columns.every(name=>/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(name))||
         new Set(columns).size!==columns.length||
         ![',',';','\t'].includes(draft.csvDelimiter??'INVALID'))
        errors.push('Mixed CSV requires reviewed column names (2–100) and a selected data delimiter.');
    }
  }else if(draft.mixedFormats!==undefined){
    errors.push('Mixed family selections are only valid for Mixed format');
  }
  if (draft.format === 'csv') {
    if (![',', ';', '\t'].includes(draft.csvDelimiter ?? ',')) {
      errors.push('CSV data separator must be comma, semicolon or TAB');
    }
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
    if(mapping.when!==undefined&&!validMappingWhen(mapping.when))
      errors.push('Unsupported or unsafe conditional mapping rule for '+mapping.source);
    if(draft.format==='syslog_rfc3164'&&mapping.source==='syslog_timestamp'&&
      mapping.type==='timestamp')
      errors.push('RFC3164 timestamp has no year or timezone; map it as text.');
    if (!safeUiPath(mapping.source) && mapping.source!=='@timestamp') errors.push('Invalid source field: ' + mapping.source);
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
  const validDelimiter=(value:string|undefined)=>typeof value==='string'&&value.length>=1&&value.length<=8&&
    !/[\u0000-\u001f\u007f]/.test(value);
  const addEnrichmentTarget=(target:string,step:number,type='string')=>{
    if (!safeUiPath(target) || RESERVED_OUTPUT_ROOTS.has(target.split('.')[0]))
      errors.push('Unsafe enrichment output at step ' + step);
    if (destinations.some((value) => value === target ||
        value.startsWith(target + '.') || target.startsWith(value + '.')))
      errors.push('Enrichment destination collision at step ' + step);
    destinations.push(target);available.set(target,type);
  };
  for (const [i, rule] of enrich.entries()) {
    const step=i+1;
    if(rule.operator==='split_field'){
      const targets=rule.targets??[];
      if(!available.has(rule.source)||available.get(rule.source)!=='string')
        errors.push('Split source must be an existing text normalized field at step '+step);
      if(!validDelimiter(rule.delimiter))errors.push('Split delimiter must be 1–8 visible characters at step '+step);
      if(targets.length<2||targets.length>8||new Set(targets).size!==targets.length)
        errors.push('Split requires 2–8 unique output fields at step '+step);
      for(const target of targets)addEnrichmentTarget(target,step);
      continue;
    }
    if(rule.operator==='merge_fields'){
      const sources=rule.sources??[];
      if(sources.length<2||sources.length>8||new Set(sources).size!==sources.length)
        errors.push('Merge requires 2–8 unique source fields at step '+step);
      if(sources.some(source=>!available.has(source)||available.get(source)!=='string'))
        errors.push('Merge sources must be existing text normalized fields at step '+step);
      if(!validDelimiter(rule.delimiter))errors.push('Merge delimiter must be 1–8 visible characters at step '+step);
      addEnrichmentTarget(rule.target,step);
      continue;
    }
    if (!['set_const', 'copy', 'lowercase', 'uppercase'].includes(rule.operator)) {
      errors.push('Unsupported enrichment operation at step ' + step);continue;
    }
    if (rule.operator === 'set_const') {
      if (rule.value.length > 256) errors.push('Enrichment constant exceeds 256 characters');
    } else if (!available.has(rule.source)) {
      errors.push('Enrichment source is not a normalized field at step ' + step);
    } else if ((rule.operator === 'lowercase' || rule.operator === 'uppercase') &&
               available.get(rule.source) !== 'string') {
      errors.push('Case changes require a text source field at step ' + step);
    }
    addEnrichmentTarget(rule.target,step,
      rule.operator === 'set_const' ? 'string' : (available.get(rule.source) ?? 'unknown'));
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
      ...(draft.version?.trim()?{productVersion:draft.version.trim()}:{}),
      receiver: options.receiver,
      input: { format: draft.format as 'json' | 'kv' | 'csv' | 'syslog_rfc3164' | 'syslog_rfc5424' | 'cef' | 'leef' | 'mixed' | 'java_stacktrace' | 'generic_structural' | 'regex' },
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
